# The sandbox: RedFall against real applications

`redfall bench` measures against corpora this project wrote. That is the right
instrument for regression and the wrong one for capability — a corpus authored
by the same person who wrote the detectors shares their blind spots, and
agreement looks like accuracy.

This directory scores RedFall against **applications nobody here wrote**,
seeded by people who had no interest in what RedFall finds. It is the only
measurement in the project that can falsify the tuned numbers.

## Run it

```bash
sh sandbox/fetch_challenges.sh              # clone the pinned apps
python -m redfall.cli bench sandbox         # score the engine against them
python -m redfall.cli bench sandbox --target dvna
```

## What is fetched

| App | What it is | Commit |
| --- | --- | --- |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | A deliberately vulnerable Node/Express app, taught as the OWASP Top 10 | `c5cb68a7` |
| [dvna](https://github.com/appsecco/dvna) | Damn Vulnerable Node Application | `9ba473ad` |

Both are pinned to a **commit**, not a branch. A challenge that moves under the
runner makes yesterday's result unreproducible, and an unreproducible score is
the thing this repository exists to argue against. The trees are large and are
ignored by git; `fetch_challenges.sh` plus `ground_truth.json` is what
reproduces a run.

## The measured result

**Mean recall: 38.1% — 5 of 13 documented vulnerabilities.**

| App | Found | Recall | Findings reported |
| --- | --- | --- | --- |
| dvna | 2 / 6 | 33% | 20 |
| NodeGoat | 2 / 7 | 29% | 10 |

Read against the other two numbers this project publishes:

| Corpus | Recall | What it measures |
| --- | --- | --- |
| `pythonbank` (tuned) | 100% | Agreement with detectors written against it |
| `vulnbank` (holdout) | 21.9% | A different codebase, same author |
| **Real apps** | **38.1%** | Code nobody here touched |

**The tuned 100% is not the claim.** The two numbers that mean anything are the
holdout and this one, and both say the same thing: the engine finds roughly a
third of what is there.

## How scoring works, and its limit

**By file and category, not by line.** A third-party app's ground truth comes
from its documentation and its own code comments, which name *where* a class of
bug lives, rarely the line its authors would have chosen. Scoring on lines would
measure whether this project guessed another team's formatting.

The trade-off is real and stated: file+category is a weaker match, so a detector
that fires on the wrong line of the right file still scores.

## Two bugs this harness found, and what they cost

Both were in the *measurement*, not the engine — and both are the same shape.

1. **The runner scored only the detector stage.** A SQL injection is a flow, not
   a shape, so the detector suite cannot see one. Every injection in both apps
   scored as a miss while the taint stage had already found them.
2. **The sink→category map dropped `exec`.** The taint engine emits the sink
   *kind* (`exec`) and the corpus names the *class* (`cmd_injection`); the map
   sent the bare kind through a fallback that returned the string `"eval"`,
   which matched nothing. One line, **15 points** — on both this harness and the
   holdout corpus, which also contains a command injection.

The second is the third instance of the same defect class in this project's
history, after `subprocess.run` and the taint-only recall gate. A scorer that
silently drops findings looks exactly like an engine that never found them, and
the only defence is feeding it output someone has checked by hand.

## The generalisation fix: infer sinks from what a project declares

The single largest cause of the gap was a **fixed receiver table**. The engine
recognised `axios`, `got`, `http`, `superagent` and a handful more, and was
blind to every client nobody enumerated. NodeGoat fetches with `needle`; run it
before this change and the engine classifies **zero sinks** and reports nothing
— which is indistinguishable from a clean application, and is the most
dangerous way for a measurement to fail.

Adding `needle` to the set fixes one app and teaches nothing. The next app uses
`ky`, or `undici`, or `node-fetch`, and the engine is blind again.

**A project already says what its libraries do.** It has to, in a manifest that
names every dependency for the code to run at all. `src/redfall/ingestion/
library_sinks.py` reads those manifests and classifies each library by its
declared identity: a curated seed first, then whole-word name morphology, then
declared metadata. Unknown stays unknown, and unknown means not-a-sink — a
false sink produces a taint path to something that cannot be exploited, which
is the finding this project most wants to avoid.

The effect on NodeGoat's SSRF, end to end:

```
before:  sinks classified: []
after:   needle.get  ->  fetch
         taint path:  req.query -> url (line 15) -> needle.get (line 16)
```

**A second bug surfaced while wiring it.** `symbols.py` and `taint.py` had each
grown their own sink classifier, and only one of them learned about declared
libraries — so the first reported `needle.get` as a sink while the second,
which actually decides whether a taint path exists, still returned nothing.
Two tables that disagree produce a scanner that reports no sinks. Both now
consult one registry, and a test asserts they agree.

## What the misses say

NodeGoat and dvna are not adversarial cases. They are the two best-known
vulnerable Node applications in existence, documented class by class, and
RedFall finds two of seven and two of six.

The misses are consistent across both:

- **XSS.** No detector looks at output encoding on a template render.
- **SQL injection in a layered app.** The flow exists but crosses a DAO boundary
  the interprocedural pass does not follow.
- **Verbose errors.** Error handlers that return `err.stack` are not recognised
  outside the shapes the detector was written against.
- **Uploads.** Express uses `multer` and a middleware chain rather than the
  copy-then-save shape the detector knows.

None of that is a surprise. It is the generalisation gap the holdout corpus
predicted, confirmed on code with no connection to this project — which is
exactly what this harness was built to establish.
