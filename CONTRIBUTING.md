# Contributing to Redfall

Thanks for wanting to make it better. Redfall has one unusual rule, and it
shapes everything else, so it comes first.

## The one rule: nothing is claimed without a proof

Every number in the docs, every finding, every metric and every test fixture
must come from something that actually ran.

- `scripts/check_no_mock.py` scans the package for dry-run modes, fabricated
  defaults and fallback paths. If your change adds one, CI fails — by design.
- Tests run against real artefacts: a real Postgres, real target apps over real
  HTTP, real built wheels. Database-backed tests take the URL from
  `REDFALL_TEST_DATABASE_URL`.
- If something cannot run on your machine (no container runtime, no provider
  key), say so in the PR and leave it visibly blocked in [`BLOCKED.md`](BLOCKED.md)
  instead of faking a result. "Built but blocked, here is the exact unblock" is
  a valid contribution. A fabricated result is not.

The analyser has a second rule that follows from the first: **static analysis
produces candidates, never findings.** Only proofs that executed inside the
sandbox become findings. Keep that line where it is.

## Getting set up

- Python 3.12+ (3.13 supported), Node 20+ for TS/JS targets, Postgres 17 and
  Redis for the data layer.
- `make install` installs `redfall` and `range_runner` editable with dev deps.
- `make doctor` prints exactly which prerequisites your host satisfies.
- `make check` runs all four contract checkers plus the full test suite
  (`make check-no-mock`, `make check-version`, `make check-orphans`,
  `make check-clean-tree`, `make test` individually).

```bash
export REDFALL_TEST_DATABASE_URL=postgresql+psycopg://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/redfall_test
make check
```

## Where things are

- `src/redfall/ingestion/` — tree-sitter parsing, symbols, taint (intra +
  depth-one inter with return flow and a call graph), dependency and git facts.
- `src/redfall/branching/` — the recursive tree and its seven adaptive
  detectors.
- `src/redfall/chain/` — attack graph, compound CVSS, narrative.
- `src/redfall/validation/harness.mjs` — the exploit runner that executes
  inside the sandbox; the harness' payloads are the only things that turn a
  candidate into a finding.
- `range/` — the ground-truth targets. `vulnbank`, `vulnbank-adaptive`,
  `chainbank`, `pythonbank`; each ships a generated manifest and a PoC replay.
- `web/` — the Next.js dashboard.

## Working on the analyser

- Sources live in `SOURCE_PROPS` / `SOURCE_PREFIXES`; sinks in
  `DANGEROUS_SINK_CALLS` and `symbols_py.classify_call`. Adding one needs a
  test that proves the flow on a real fixture and a lookalike that must **not**
  match (see `tests/test_framework_routes.py` for the pattern).
- The interprocedural passes resolve a callee or drop the edge — never guess.
  If a specifier could match two files, or a symbol cannot be proved to be a
  function, the edge does not exist. Ambiguity is a false-positive machine.
- Interpass summaries are depth one and unseeded in the direction they are not
  proving. Concretely: parameter summaries are seeded, return summaries are
  unseeded, and neither may use call-site context. `tests/test_return_flow.py`
  pins the depth limit on purpose — a second hop is *not* claimed.

## Working on the range targets

- Manifests are generated, never hand-edited:
  `python scripts/write_manifest.py` (pythonbank also supports `--check`, which
  its test suite asserts).
- Never weaken a PoC, an anchor or an expected count to make a gate pass. If a
  target's number changed, say which real behaviour changed and re-measure.

## Commits and pull requests

- Small, scoped commits with real messages: what moved, what was measured.
  Do not split one change into dozens of commits, and do not bundle unrelated
  changes to inflate counts.
- Run `make check` (or at least the checkers plus the affected tests) before
  pushing. CI runs the same plus the packaging matrix on Linux, macOS and
  Windows.
- Update the docs when a claim changes — README and `BLOCKED.md` carry counts
  that must match reality, because that is the entire point of this project.

The PR template has the checklist; the short version is: what changed, how you
proved it, what you could not run.

## Reporting a security issue

Redfall is a security tool; treat its own vulnerabilities accordingly. Please
report privately via [`SECURITY.md`](SECURITY.md) — not in a public issue.
