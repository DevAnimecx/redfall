# Baseline recall — the first measured number

**This is the first time this repository has measured what it fails to find.**
Every previous number in the changelog counted what the engine produced; none
could see what it did not, because there was nothing there to count.

Measured 2026-11-01 on the build host, by
`redfall bench recall bench/corpora/pythonbank --target range/pythonbank`.

## The number

| Metric | Value |
| --- | --- |
| Expected flows (seeded) | 17 |
| **Found** | **5** |
| **Recall** | **0.294** |
| Missed | 12 |
| Invented (reported, matched nothing) | 8 |
| Invented rate | 0.615 |

**Recall is 29.4%.** Of the 17 flows the corpus says exist, the engine's taint
stage finds five.

## What that means, honestly

The five found are exactly the categories a taint-path engine can see — a
request value reaching a dangerous call:

| Category | Recall | In corpus |
| --- | --- | --- |
| SQL injection | 1.0 | 2 |
| Path traversal | 1.0 | 1 |
| SSRF | 1.0 | 1 |
| Unsafe deserialization | 1.0 | 1 |
| Command injection | 1.0 | 1 |

`cmd_injection` is in this table as of the 2026-11-02 correction: the engine
found it and the scorer did not credit it. The single most useful thing this
baseline did was get its own arithmetic wrong in a way that was visible.

The eleven missed split into two groups, and the split matters more than the
total:

**Expected misses — these are not taint flows and no amount of taint depth
would find them.** They need different detectors the engine does not have:

- `hardcoded_secret`, `secret_exposure` — a literal in the source, not a path
- `weak_password_hash_md5` — an algorithm choice at one call site
- `missing_rate_limit` — an *absence*; nothing to trace
- `verbose_error` — a response shape, not a data flow
- `user_enumeration` — a timing/response difference between two paths
- `csv_injection`, `unrestricted_file_type` — an output-encoding and an input
  check, each a local property rather than a flow
- `idor` — an authorisation *absence* on a reachable route

**Taint-shaped, and diagnosis separated the two:**

- **`open_redirect`** — a **genuine engine gap**. `classify_call` in
  `symbols_py.py` has no rule for the Flask response-construction family
  (`redirect`, `abort`, `url_for`), so `redirect.py` yields **0 sinks and 0
  taint paths**. One table entry fixes it.
- **`ssrf_metadata`** — **found but mislabelled**. The engine reports
  `requests.get` at `proxy.py:18`; it cannot distinguish an SSRF against the
  link-local range from a general one. Half real gap (nothing inspects the
  argument for a metadata-range literal), half corpus modelling.

> `cmd_injection` appeared in this list until 2026-11-02 and should not have.
> The engine had always found it — `tools.py:24` — and the **scorer** dropped
> it because its category map tested for the substring `"exec"`, which matches
> `cursor.execute` but not `subprocess.run`. The bug was in the instrument, not
> the engine, and it cost the baseline 5.9 points. See
> [`docs/roadmap/0.7.0.md`](../docs/roadmap/0.7.0.md) §1.1.

One flow of a shape the engine claims to handle was not found. That is a
defect, not a scope boundary, and it is a number someone can improve against.

The invented rate (0.615) is a separate finding: of the 13 taint paths the
engine reported, 8 matched no seeded flow. Some are legitimate flows the
manifest does not seed (the corpus is not exhaustive); some are the precision
cost of recording sanitisers rather than modelling them. Both are visible now.

## What this baseline is not

- **Not a complete recall figure.** The corpus seeds 17 flows; a real
  application has more, and those are not counted here. This is recall against
  a *known* set, which is a floor, not a ceiling.
- **Not a multi-language measure.** pythonbank is Python only. TypeScript,
  Java, Kotlin and Go have no baseline yet.
- **Not a claim about the whole engine.** This measures the taint stage alone.
  A flow missed here might still be surfaced by a framework pack or the branch
  engine; those are not wired into the recall command yet.
- **Not reproducible elsewhere without the corpus.** The fingerprint is
  `sha256:eb4e25…`; a run whose manifest hash differs measured something else.

## The commitment this creates

1. Recall is reported per language and per category on every release.
2. A regression in it fails CI the way a test failure does.
3. The three real misses above are the first concrete work items — they are
   named, not aggregated into "improve recall".

This file is the baseline that commitment is measured against. It will be
replaced by a lower-bound number that rises, and the misses it names will be
struck through as each is fixed.
