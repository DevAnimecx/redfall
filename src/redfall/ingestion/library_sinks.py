"""Infer what a third-party library does from how the project declares it.

**The problem this exists for.** The sink tables name libraries explicitly:

    FETCH_RECEIVERS = {"axios", "http", "https", "got", "request", "superagent"}

That list is why the engine does not generalise. Run it against OWASP NodeGoat
and it classifies **zero sinks**, because NodeGoat fetches with `needle`, which
nobody enumerated. The engine does not report a wrong answer; it reports
nothing, and a scanner that sees no sinks looks exactly like an application
with no vulnerabilities. Measured: the same engine that scores 100% on a tuned
corpus finds 31% on real applications, and the single largest cause is this.

Adding `needle` to the set fixes one application and teaches the engine
nothing. The next app uses `ky`, or `undici`, or `node-fetch`, and the engine
is blind again.

**The move.** A project already tells you what its libraries do, in the manifest
that has to list them for the code to run at all. `needle` is a dependency of a
web application, its name reads as an HTTP client, and its declared shape
matches the fetch family. That is enough to classify it, and it is enough for
libraries this project has never seen.

Three signals, in decreasing order of confidence:

1. **A curated seed.** The libraries already in the sink tables are known, and
   a known library keeps its kind. The seed is not the mechanism; it is what
   keeps existing behaviour byte-identical.
2. **Name morphology.** A dependency whose name matches a family's naming
   conventions — `node-fetch`, `got`, `needle`, `superagent`, `undici` — is
   classified by that match. Precision comes from requiring a *whole-word*
   match against curated stems, not a substring: `request` matches, `requests-
   mock-test` does not.
3. **Declared metadata.** Where a manifest carries a description or keywords,
   those are read. This is the weakest signal and is only consulted when the
   name says nothing.

**What this deliberately does not do.** It does not guess from a single fuzzy
word. An unknown dependency stays unknown, and unknown means "not a sink" —
the safe direction, because a false sink produces a taint path to something
that cannot be exploited, which is the finding this project most wants to
avoid. A library is classified only when a signal names its family clearly.

**The honest limit.** This reads *names and metadata*, not behaviour. A library
called `request-logger` that only logs would be classified as an HTTP client by
its name. The mitigation is the same as the detectors': every inferred family
carries the reason it was inferred, and a finding can be traced to the signal
that produced it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Sink kinds, matching the vocabulary the taint engines already emit.
FETCH = "fetch"
DB = "db"
EXEC = "exec"
FS = "fs"

# --- signal 1: the seed ----------------------------------------------------
#
# What the sink tables already name, plus the libraries this project has met in
# the wild. A seed entry always wins over inference, so existing behaviour does
# not move.
SEED: dict[str, str] = {
    # fetch
    "axios": FETCH,
    "got": FETCH,
    "superagent": FETCH,
    "request": FETCH,
    "node-fetch": FETCH,
    "needle": FETCH,
    "undici": FETCH,
    "ky": FETCH,
    "phin": FETCH,
    "node-rest-client": FETCH,
    "wreck": FETCH,
    # db
    "pg": DB,
    "mysql": DB,
    "mysql2": DB,
    "mongodb": DB,
    "mongoose": DB,
    "sequelize": DB,
    "knex": DB,
    "typeorm": DB,
    "prisma": DB,
    "sqlite3": DB,
    "better-sqlite3": DB,
    "sqlalchemy": DB,
    "psycopg": DB,
    "psycopg2": DB,
    "pymongo": DB,
    "django": DB,
    # exec
    "shelljs": EXEC,
    "execa": EXEC,
    "cross-spawn": EXEC,
    "child_process": EXEC,
    "subprocess": EXEC,
    # fs
    "fs-extra": FS,
    "graceful-fs": FS,
    "memfs": FS,
    "aiofiles": FS,
}

# --- signal 2: name morphology ---------------------------------------------
#
# Whole-word stems per family. `\b`-anchored against the normalised library
# name so `node-fetch` and `fetch` match while `prefetch-cache` does not.
_NAME_STEMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        FETCH,
        (
            "fetch",
            "http",
            "https",
            "ajax",
            "rest",
            "reqwest",
            "urllib",
            "httpx",
            "requests",
            "request",
            "aiohttp",
            "needle",
            "got",
            "axios",
            "superagent",
            "undici",
        ),
    ),
    (
        DB,
        (
            "sql",
            "mysql",
            "postgres",
            "postgresql",
            "pg",
            "mongo",
            "redis",
            "sqlite",
            "orm",
            "database",
            "knex",
            "sequelize",
            "prisma",
            "typeorm",
            "mongoose",
        ),
    ),
    (
        EXEC,
        (
            "shell",
            "exec",
            "spawn",
            "subprocess",
            "child-process",
            "process-control",
        ),
    ),
    (
        FS,
        ("fs", "filesystem", "file-system", "pathlib"),
    ),
)

# --- signal 3: declared metadata -------------------------------------------
#
# Only consulted when the name says nothing. Deliberately conservative: a
# description must contain the family's own vocabulary, not an incidental word.
_DESCRIPTION_STEMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (FETCH, ("http client", "http request", "make requests", "http library")),
    (DB, ("database", "database driver", "sql client", "orm")),
    (EXEC, ("shell command", "subprocess", "process execution")),
    (FS, ("filesystem", "file system")),
)

# Names that read as a family but are not: a test double, a mock, a type-only
# package, or a linter. Match one of these and the library is left unknown.
_NOT_A_SINK = re.compile(
    r"(?i)(^|[-_.@/])(mock|mocks|stub|fake|fixture|test|tests|testing|types|"
    r"typings|eslint|prettier|plugin|lint)([-_.@/]|$)"
)

# Manifests this reads. Every one is a real declaration the code needs to run.
_MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "Pipfile")


@dataclass(frozen=True)
class Inferred:
    """A library classified as a sink, with the signal that classified it."""

    library: str
    kind: str
    by: str
    reason: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "library": self.library,
            "kind": self.kind,
            "by": self.by,
            "reason": self.reason,
        }


def _normalise(name: str) -> str:
    """A package name reduced to comparable words.

    Scope prefixes (`@org/pkg`) are dropped and separators unified, so
    `@sindresorhus/got` and `node_fetch` compare as `got` and `node-fetch`.
    """
    clean = (name or "").strip().lower()
    if clean.startswith("@") and "/" in clean:
        clean = clean.split("/", 1)[1]
    return clean.replace("_", "-")


def _word_stem_match(haystack: str, stems: Iterable[str]) -> str | None:
    """The first stem present as a whole word, or None.

    Whole-word on purpose. A substring test would classify `prefetch-cache` as
    an HTTP client and `filesystem-watcher-lite` as an fs library, and every
    one of those is a false sink producing an unexploitable taint path.
    """
    for stem in stems:
        if re.search(rf"(?:^|[-.])({re.escape(stem)})(?:$|[-.])", haystack):
            return stem
    return None


def classify_library(
    name: str,
    *,
    description: str = "",
    keywords: Iterable[str] = (),
) -> Inferred | None:
    """What kind of sink a library is, or None if it cannot be told.

    None is the answer for most libraries and that is correct: `underscore`,
    `swig` and `body-parser` are not sinks, and the caller treats unknown as
    not-a-sink.
    """
    normalised = _normalise(name)
    if not normalised:
        return None

    # A test double or a type package named after a family is still not the
    # family, and this is checked *first*: `@types/request` and
    # `jest-fetch-mock` both name a seeded library, so a seed lookup that ran
    # before this would classify them as sinks — which is exactly backwards.
    #
    # The raw name is tested, not the normalised one: `_normalise` strips the
    # `@types/` scope, and the scope *is* the signal. Checking after the strip
    # is how `@types/request` — a file of type declarations with no runtime
    # code at all — was classified as an HTTP client.
    if _NOT_A_SINK.search(name.lower()) or _NOT_A_SINK.search(normalised):
        return None

    if normalised in SEED:
        return Inferred(normalised, SEED[normalised], "seed", "a known library")

    for kind, stems in _NAME_STEMS:
        stem = _word_stem_match(normalised, stems)
        if stem:
            return Inferred(
                normalised, kind, "name", f"the name contains {stem!r}"
            )

    haystack = " ".join([description or "", *keywords]).lower()
    if haystack.strip():
        for kind, phrases in _DESCRIPTION_STEMS:
            for phrase in phrases:
                if phrase in haystack:
                    return Inferred(
                        normalised, kind, "metadata", f"its metadata says {phrase!r}"
                    )

    return None


def libraries_from_manifest(path: str | Path) -> dict[str, str]:
    """Declared dependencies from a manifest, as ``{name: description}``.

    Returns an empty mapping for anything it cannot read rather than raising:
    a manifest is one input among several and a malformed one must not end a
    scan.
    """
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    if target.name == "package.json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            return {}
        out: dict[str, str] = {}
        for section in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
        ):
            for name in (document.get(section) or {}):
                out[str(name)] = str(document.get("description") or "")
        return out

    names: dict[str, str] = {}
    if target.name == "requirements.txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name = re.split(r"[<>=!\[; ]", line, maxsplit=1)[0].strip()
            if name:
                names[name] = ""
        return names

    if target.name in {"pyproject.toml", "Pipfile"}:
        # A light read of the dependency lines; a full TOML parse would add a
        # dependency for one field.
        for match in re.finditer(r"(?m)^\s*[\"']?([A-Za-z0-9_.\-]+)[\"']?\s*[=<>~]", text):
            names[match.group(1)] = ""
        return names

    return names


def library_sinks(root: str | Path) -> dict[str, Inferred]:
    """Every declared dependency in a tree that classifies as a sink.

    The result is what the language classifiers consult when a call's receiver
    is not in their built-in table: a library the project actually depends on
    and whose declared identity says what it does.
    """
    base = Path(root)
    found: dict[str, Inferred] = {}
    for manifest in _MANIFESTS:
        for path in base.rglob(manifest):
            if any(part in {"node_modules", ".git", "venv", ".venv"} for part in path.parts):
                continue
            for name, description in libraries_from_manifest(path).items():
                if name in found:
                    continue
                inferred = classify_library(name, description=description)
                if inferred is not None:
                    found[name] = inferred
    return found


def sink_kinds() -> dict[str, str]:
    """The seed table, for a caller that wants the known set only."""
    return dict(SEED)
