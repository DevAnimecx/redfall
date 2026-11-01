---
title: The evidence model
description: How a candidate becomes a finding in RedFall, what the E0–E4 grades mean, and why the ledger refuses a reportable record that lacks a reproduction.
---

# The evidence model

Every claim RedFall makes about a target is a record in a hash-chained ledger,
carrying a grade. The grade is not decoration — it decides whether the claim may
appear in a report at all.

## The grades

| Grade | Name | What it asserts | Reportable |
| --- | --- | --- | --- |
| **E0** | Opinion | A model suggested something might be wrong | No |
| **E1** | Static observation | A source→sink path exists in the source | No |
| **E2** | Dynamic observation | Something happened at runtime | No |
| **E3** | Reproduced | An exploit ran and an observable changed as predicted | **Yes** |
| **E4** | Reproduced with impact | As E3, plus a demonstrated consequence | **Yes** |

The line between E2 and E3 is the important one. E2 says *the target did
something*. E3 says *the target did the specific thing the claim predicted*. A
500 response to a malformed request is an E2. A 200 response carrying another
user's record is an E3.

The line between E3 and E4 is impact. E3 proves the bug is reachable. E4 proves
what reaching it costs — a cross-tenant read, an authenticated bypass, code
execution.

## What the ledger refuses

`EvidenceLedger.append` validates at write time. An E3 or E4 record that lacks
any of these is rejected, and the rejection is an exception rather than a
downgrade:

| Required for E3/E4 | Why |
| --- | --- |
| `payload.execution_id` | The execution it came from, so it can be re-run |
| `payload.observable` or `expected_observable` | What was predicted, so success is not judged after the fact |
| `reproduce_command` | The exact command that reproduces it |
| `environment_digest` | What the target and sandbox were, so "works on my machine" is falsifiable |
| `payload.impact` *(E4 only)* | What the consequence was |

Lower grades have their own minimums: E1 needs a path, file, source, symbol or
query; E2 needs a non-empty observation.

**Why at write time.** If the validation ran when a report was generated, a
record could exist in a valid database in a state that no report could use — and
the failure would surface at the least convenient moment, in front of a
customer. Rejecting at write time means the database only ever contains records
that something could report.

## The chain

Each record's `content_hash` is a SHA-256 digest over the record's canonical
JSON, which includes the previous record's `content_hash`. The first record
commits to a genesis hash of 64 zeros.

```
  record 1 ──hash──┐
                   ▼
  record 2 ──hash──┐   each commits to its predecessor's digest
                   ▼
  record 3 ──hash──┐
                   ▼
```

Editing any record invalidates every record after it, so tampering is
detectable rather than merely detectable-in-principle. `verify()` walks the
chain and returns the first record that fails, with the reason.

**What this does and does not give you.** It proves internal consistency: the
records are what they were when written. It does not prove the *contents* are
truthful — a fabricated record appended honestly has a valid hash. The defence
against that is not cryptography; it is that a fabricated E3/E4 must still carry
a reproduce command that runs.

## How a candidate becomes a finding

```
  candidate (E1)          a source→sink flow from static analysis
      │
      │  author a PoC
      ▼
  execute                 boot the target in a sandbox, run the PoC, evaluate
      │                   the predicate against the real response
      │
  ┌───┴────┐
  │        │
reproduced  not
  │        │
  ▼        ▼
 E3/E4    recorded as unreproduced, with the failure
  │
  │  (E4 if impact was also demonstrated)
  ▼
 reportable
```

The candidate's grade never rises because a model was confident about it. Only
execution changes a grade. That is the property that lets static analysis be
approximate without compromising the output: its errors are absorbed at the
gate.

## Reporting gate

The report generator requests reportable records and refuses to render a
finding whose evidence is missing, unverified or fails schema validation. There
is no flag that lowers this, because a flag is how a gate becomes a suggestion.

SARIF output carries `properties.redfall.verified` on every result, so a
consumer downstream can tell a reproduced finding from an unreproduced
candidate — and unreproduced candidates are still emitted, marked, rather than
silently dropped. Dropping them would hide the generator's error rate.

## The range targets

The evidence model is exercised against real targets under `range/`:

| Target | Shape | What it proves |
| --- | --- | --- |
| `vulnbank` | A Node service with seeded vulnerabilities | The full pipeline: route → taint → PoC → reproduction → fix |
| `vulnbank-adaptive` | vulnbank plus seven adaptive surfaces | That the branch triggers fire on real source |
| `pythonbank` | Flask and FastAPI services | That the Python engine reaches the same standard |
| `chainbank` | Packages with real advisories | That a two-step exploit chain reproduces end to end |

These are the only place in the repository where a finding is proven rather than
argued, and they are the reason a claim in the changelog can carry a number.

## Reading a finding

```json
{
  "evidence_id": "ev_01J...",
  "campaign_id": "cmp_01J...",
  "grade": "E4",
  "finding_id": "fnd_01J...",
  "claim": "IDOR lets principal A read principal B's invoice",
  "source": {"kind": "execution", "execution_id": "exe_01J..."},
  "environment_digest": "sha256:...",
  "expected_observable": {"status": 200, "body_contains": "invoice-b"},
  "reproduce_command": "redfall reproduce fnd_01J...",
  "artifacts": ["logs.txt", "trace.json", "response.http"],
  "previous_hash": "sha256:...",
  "content_hash": "sha256:..."
}
```

Everything needed to re-run the claim is in the record. If it is not there, the
record would not have been accepted.
