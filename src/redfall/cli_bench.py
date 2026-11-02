"""`redfall bench` — drive the arena from the command line.

Three commands:

- `redfall bench recall <corpus>` — run this engine's taint stage over the
  corpus's own targets and score the recall immediately. The one number the
  project most owes.
- `redfall bench report` — build a report bundle from recorded runs, refusing
  to exist without a LIMITATIONS section.
- `redfall bench validate <corpus>` — check a corpus is structurally sound
  before anyone runs against it.

The CLI never computes a number alone: recall comes from the scorer, budget
ceiling enforcement from the corpus loader, and the refusal to write a
limitations-free report lives in the runner. The command layer only wires them.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .store.db import init_engine


def _emit(payload: object, out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
        click.echo(f"wrote {out}")
    else:
        click.echo(text)


@click.group()
def bench() -> None:
    """Measure the engine against a sealed corpus. Show its work."""


@bench.command("validate")
@click.argument("corpus_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def bench_validate(corpus_dir: Path) -> None:
    """Check a corpus is structurally sound.

    Refuses a corpus with no expected findings, a ground truth that disagrees
    with the manifest, or a budget that widens nothing — any of which would
    make a run against it vacuous or dishonest.
    """
    from .bench.corpus import CorpusError, load_corpus

    try:
        corpus = load_corpus(corpus_dir)
    except CorpusError as err:
        raise click.ClickException(f"invalid corpus: {err}") from err
    _emit(
        {
            "valid": True,
            "corpus": corpus.to_wire(),
            "note": "ground truth loaded for the scorer only; it is not part of this output",
        },
        None,
    )


@bench.command("recall")
@click.argument("corpus_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--target", "target_dir", type=click.Path(exists=True, file_okay=False, path_type=Path), default=None, help="The tree to scan. Defaults to the corpus's own source_dir.")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None, help="Write the recall JSON here.")
def bench_recall(corpus_dir: Path, target_dir: Path | None, out_path: Path | None) -> None:
    """Run this engine's taint stage over a corpus and score the recall.

    This is the omission number the repository has never had: of the flows the
    corpus says exist, how many did the engine find — and, per category, how
    many did it miss entirely.
    """
    from .bench.corpus import CorpusError, load_corpus
    from .bench.recall import recall_from_taint
    from .config import load_config

    try:
        corpus = load_corpus(corpus_dir)
    except CorpusError as err:
        raise click.ClickException(f"invalid corpus: {err}") from err

    # The taint stage persists into the store, so the engine must exist. Recall
    # needs no Postgres — a throwaway SQLite file is enough and keeps the
    # measurement runnable on any host.
    config = load_config()
    url = config.database_url if config.database_url.startswith("sqlite") else "sqlite:///redfall-bench.db"
    init_engine(url)

    tree = target_dir or corpus.source_dir
    findings = _all_findings_for(tree, corpus)
    result = recall_from_taint(findings, corpus.expected)

    _emit(
        {
            "corpus": corpus.to_wire(),
            "languages": sorted({e.language for e in corpus.expected}),
            "scanned": str(tree),
            "recall": result.to_wire(),
        },
        out_path,
    )


def _all_findings_for(tree: Path, corpus) -> list[dict[str, object]]:
    """Everything the engine reports about a tree: taint plus detectors.

    Recall is a property of the *engine*, not of one analysis stage. Reporting
    only the taint stage's output measured the wrong thing — it counted nine
    classes as misses that no flow analysis could ever reach, which reads as an
    engine failure when it is a missing detector. Both stages run and their
    findings merge.
    """
    from .detect import detect_file

    rows = _taint_findings_for(tree, corpus)
    seen = {(str(r["category"]), str(r["file"]), int(r["line"])) for r in rows}

    for path in sorted(tree.rglob("*")):
        if not path.is_file() or path.suffix not in {".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".kt", ".go"}:
            continue
        # The corpus anchors are repository-relative to the target root, so the
        # path is taken relative to `tree`, not its parent. Getting this wrong
        # is silent: every detector finding carries a prefix the scorer cannot
        # match, so found flows read as invented ones.
        rel = str(path.relative_to(tree)).replace("\\", "/")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for hit in detect_file(rel, text):
            key = (hit.category, hit.file, hit.line)
            if key in seen:
                continue
            seen.add(key)
            rows.append(hit.to_row())
    return rows


def _taint_findings_for(tree: Path, corpus) -> list[dict[str, object]]:
    """Run this engine's taint stage over a tree and return comparable rows.

    Rows carry ``category``, ``file``, ``line`` and ``symbol`` — the fields the
    scorer matches on. Categories come from the engine's taint kind, mapped
    through the same canonical alias table the range matcher uses, so the two
    measures cannot disagree about what a finding is.

    Two path facts this function has to get right, both of which silently zero
    a recall if wrong:

    * The manifest anchors are repository-relative (``src/pythonbank/...``),
      so the tree scanned must be the target *root*, not its ``src``. Scanning
      ``src`` records ``pythonbank/...`` and every comparison fails.
    * The engine stores ``file_id``, which is the hash of the path, not the
      path. The path lives on the `files` row it references.
    """
    from .ingestion.ingest import ingest
    from .store.db import session_scope
    from .store.models import FileRow, Scan, TaintPath

    scan_id = f"bench-{abs(hash(str(tree))) % 10**10}"
    with session_scope() as session:
        # `ingest` persists files against a scan row; the row must exist first
        # or the foreign key fails. A recall run is a scan like any other.
        if session.get(Scan, scan_id) is None:
            session.add(Scan(id=scan_id, repo=str(tree)))
            session.flush()
        result = ingest(scan_id, tree, session=session)

        path_by_file_id = {
            row.id: row.path for row in session.query(FileRow).filter(FileRow.scan_id == scan_id)
        }
        rows: list[dict[str, object]] = []
        for stored in session.query(TaintPath).filter(TaintPath.scan_id == scan_id):
            rows.append(
                {
                    "category": _category_for_sink(stored.sink),
                    "file": path_by_file_id.get(stored.file_id, ""),
                    "line": int(stored.line or 0),
                    "symbol": stored.symbol or "",
                    "sink": stored.sink,
                }
            )
        return rows


def _category_for_sink(sink: str) -> str:
    """The corpus category a taint sink corresponds to.

    The engine's taint stage reports the *sink call* — ``subprocess.run``,
    ``os.system``, ``cursor.execute`` — not a vulnerability class, so the
    scorer has to map one to the other. Getting this wrong does not just
    mis-report a number: it *under*-credits the engine for bugs it found, and
    an earlier version of this function did exactly that. It tested for the
    substring ``"exec"``, which matches ``cursor.execute`` but not
    ``subprocess.run`` — so a real command-injection finding scored as a miss.

    The table below is matched on the *function name*, not a substring, so
    ``subprocess.run`` cannot fall through the way it did. A sink this does not
    recognise is returned lowercased and will match nothing, which the scorer
    counts against the invented rate rather than silently as a hit.
    """
    from .ingestion.symbols_py import METADATA_HOSTS

    lowered = (sink or "").strip().lower()
    if not lowered:
        return "unknown"
    # Normalise `obj.method` to the method name; the receiver adds no signal
    # the corpus cares about, and keeping it is what hid the bug above.
    name = lowered.rsplit(".", 1)[-1]

    if name in {"run", "call", "check_output", "check_call", "popen"} and "subprocess" in lowered:
        return "cmd_injection"
    if name in {"system", "popen", "spawn", "spawnl", "spawnv", "execl", "execv"}:
        return "cmd_injection"
    if name in {"execute", "executemany", "executescript", "query", "raw", "extra"}:
        return "sqli"
    if name in {"loads", "load", "read", "deserialize"} and any(
        token in lowered for token in ("pickle", "yaml", "marshal", "dill", "shelve")
    ):
        return "unsafe_deserialization"
    if name in {"loads", "deserialize", "fromjson"}:
        return "unsafe_deserialization"
    if name in {"open", "readfile", "readtext", "readbytes", "sendfile", "send_file"}:
        return "path_traversal"
    if name in {"get", "post", "put", "delete", "request", "urlopen", "fetch", "urlretrieve"}:
        # An SSRF whose argument reaches the metadata service is a distinct
        # class in the corpus, so the destination is checked before the generic
        # label is applied.
        if any(host in lowered for host in METADATA_HOSTS):
            return "ssrf_metadata"
        return "ssrf"
    if name in {"redirect", "location", "redirectresponse", "seeother", "found"}:
        return "open_redirect"
    if name in {"eval", "exec"}:
        # `eval` is a sink the corpus has no category for today; naming it
        # `cmd_injection` would over-credit, so it stays unrecognised.
        return "eval"
    return name or "unknown"


@bench.command("report")
@click.argument("runs_json", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--limitations", required=True, help="Why this result cannot claim more than it does. Required.")
@click.option("--baseline", default="", help="What this was compared against, if anything.")
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path), default="bench/reports/latest", show_default=True)
def bench_report_cmd(
    runs_json: Path,
    limitations: str,
    baseline: str,
    out_dir: Path,
) -> None:
    """Build a report bundle from a runs file, with a required LIMITATIONS.

    The runs file is a JSON array of run records. Raw logs, if present in the
    same directory as ``<name>.log``, travel with the bundle.
    """
    from .bench.recall import RecallResult, recall_from_taint
    from .bench.runner import RunRecord, RunReportError, bench_report, write_report

    try:
        runs_raw = json.loads(runs_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise click.ClickException(f"{runs_json} is not valid JSON: {err}") from err
    if not isinstance(runs_raw, list):
        raise click.ClickException("the runs file must be a JSON array of run records")

    pairs: list[tuple[RunRecord, RecallResult]] = []
    for index, raw in enumerate(runs_raw):
        if not isinstance(raw, dict):
            raise click.ClickException(f"runs[{index}] is not an object")
        try:
            record = RunRecord(
                corpus_name=raw["corpus_name"],
                corpus_version=raw.get("corpus_version", ""),
                corpus_fingerprint=raw.get("corpus_fingerprint", ""),
                tool=raw.get("tool", "unknown"),
                findings=raw.get("findings") or [],
                log=raw.get("log") or "",
                duration_s=raw.get("duration_s"),
                tokens_used=raw.get("tokens_used"),
                sandbox_minutes=raw.get("sandbox_minutes"),
                cost_usd=raw.get("cost_usd"),
                tool_notes=raw.get("tool_notes") or "",
            )
        except KeyError as err:
            raise click.ClickException(f"runs[{index}] is missing {err}") from err
        pairs.append((record, recall_from_taint(record.findings, _expected_for(record))))

    try:
        report = bench_report(pairs, limitations=limitations, baseline=baseline)
        bundle = write_report(report, out_dir)
    except RunReportError as err:
        raise click.ClickException(str(err)) from err
    click.echo(f"bundle written to {bundle}")


def _expected_for(record: RunRecord):
    """The expected flows for a recorded run's corpus.

    A runs file names its corpus; the scorer reads the expected list from that
    corpus, never from the runs file — the same seal as a live run.
    """
    from .bench.corpus import CorpusError, load_corpus

    if not record.corpus_name:
        return []
    candidates = [
        Path("bench/corpora") / record.corpus_name,
        Path(record.corpus_name),
    ]
    for candidate in candidates:
        if candidate.is_dir():
            try:
                return load_corpus(candidate).expected
            except CorpusError:
                continue
    raise click.ClickException(
        f"cannot resolve corpus {record.corpus_name!r} for a recorded run; "
        "pass from the repository root or name the corpus by path"
    )
