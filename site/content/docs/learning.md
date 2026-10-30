---
title: The learning loop
seoTitle: "Self-Improving Vulnerability Scanner, Gated on Proof | RedFall"
description: "How RedFall learns only from reproduced outcomes: a lesson cites E3/E4 evidence or is not created, runs in shadow, and is promoted only on the worst holdout."
path: docs/learning/
group: Trust and evidence
kind: cluster
pillar: security
order: 23
updated: 2026-10-30
keywords: self-improving security scanner, vulnerability scanner learning loop, evidence gated ML, shadow deployment security
sources: https://github.com/DevAnimecx/redfall/blob/main/src/redfall/learning/registry.py, https://github.com/DevAnimecx/redfall/blob/main/src/redfall/learning/promotion.py
related: security, verified-findings, evidence
---

**RedFall 0.5.0 adds a learning loop, and its whole design is one rule: nothing
is learned that was not first reproduced.**

A lesson cites an E3/E4 evidence record. Not a model's opinion, not a
plausible-sounding suggestion, not a hypothesis. `propose` reads the evidence
row itself and checks its grade.

> **What this page does not claim.** No holdout set exists on the build host, so
> **no lesson has been promoted on real data and no learning gain is claimed**.
> What is tested is the machinery and its refusals. Whether any particular
> lesson improves anything is unmeasured here.

## The provenance rule, and how it is enforced

```python
row, created = propose(
    session,
    kind="route_shape",
    evidence_id="ev_01J...",     # an E3/E4 record, checked here
    summary="Spring joins the class prefix onto the method path",
    payload={"framework": "spring", "shape": "class+method"},
)
```

`propose` **takes no grade argument**. That is not an oversight — it is the
strongest available form of the guarantee. A test asserts the parameter is
absent from the signature, because a caller who believes their own claim is
solid cannot say so; the ledger says so or nobody does. Only E3 and E4 qualify.
E0/E1/E2 are hypotheses, and learning from them is how a guess hardens into
durable policy.

An evidence id that does not resolve is refused. So a lesson in the table always
has a real, reportable record behind it.

## The five steps, and why each exists

| Step | What happens | Why it is not skipped |
| --- | --- | --- |
| `propose` | Stored as a candidate with its evidence | Provenance is captured while it is known |
| `shadow` | Runs beside current behaviour, disagreement recorded, output unchanged | A lesson that disagrees constantly is either a correction or noise, and this filters cheaply |
| `evaluate` | Compared against the incumbent on a holdout | A number, recorded separately per holdout |
| `promote` | Put in force | The gate is **re-checked here**, not trusted from an earlier call |
| `rollback` | Taken out of force, reason kept | "We tried this and precision dropped" is the most useful thing the loop remembers |

`promote` re-runs the gate rather than accepting the caller's earlier
`evaluate` result, because an evaluation can be replaced in between and a
promotion acting on a stale decision is one nobody approved.

## The gate

Three constants, each stated rather than tuned:

| Constant | Value | Meaning |
| --- | --- | --- |
| `MIN_AGREEMENT` | `0.8` | A shadow disagreeing more often than this is not worth evaluation budget |
| `MIN_DELTA` | `0.02` | Zero would promote noise; a margin makes promotion a decision |
| `MIN_HOLDOUT_N` | `10` | A two-case holdout that improves by 0.5 is one flipped finding, not evidence |

**The worst holdout decides, not the best.** A lesson that helped on one holdout
and hurt on another is not ready, and averaging those two into one favourable
number is precisely how a regression ships. If any evaluation's delta is below
the bar, promotion is refused and the refusal names the worst one.

## Confidence is computed, not declared

`occurrences` rises when the same lesson is derived from a second campaign, and
`confidence` follows from it: `min(1.0, occurrences / 5)`. A ratio rather than a
curve with free parameters — one observation is 0.2, five saturate at 1.0, and
more evidence never reads as less certainty.

Deduplication is by a content fingerprint over the lesson's *meaning*. Two
campaigns observing the same route shape land on one row rather than two, so
`occurrences` is honest evidence for how often a pattern was really seen.
Bookkeeping keys such as the list of campaigns that sighted a lesson are
excluded from the fingerprint — folding them in would fork every reinforced
lesson into a second row the moment a new campaign saw it.

## Rejection and rollback

Both require a reason, and neither deletes anything.

```bash
redfall learn reject <id> --reason "the holdout leaked into training"
redfall learn rollback <id> --reason "precision dropped in production"
```

The row keeps its payload, its state trail and the reason. A rejected lesson's
reason surfaces when someone later tries to promote it, because an operator
asking to promote a rejected lesson is asking *why not*, and the answer is the
reason it was rejected.

Every state change is appended to a `learning_events` trail, so the history
reads as `candidate → shadow → promoted → rolled_back` rather than leaving the
route invisible.

## Driving it

```bash
redfall learn kinds                                    # the kinds and the gate constants
redfall learn propose --kind sink --evidence ev_... --summary "..."
redfall learn evaluate <id> --holdout arena-v1 --baseline 0.80 --candidate 0.90 \
    --baseline-n 25 --candidate-n 25
redfall learn shadow <id> --agreement 0.95
redfall learn promote <id>                             # exits nonzero if the gate refuses
redfall learn show <id>                                # trail, evaluations, gate verdict
redfall learn active                                   # what is currently in force
```

`promote` exits nonzero with the reason when the gate refuses, so a scripted
promotion fails loudly instead of appearing to succeed.

## What is not here

- **No automatic promotion.** A human or an explicit command promotes. The loop
  never puts a lesson in force on its own.
- **No training on customer code.** A lesson is a stored observation and its
  payload, not a model update.
- **No measured gain.** Stated once more because it matters: the gates and their
  refusals are tested; no claim is made that any lesson improves results.
