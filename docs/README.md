# RedFall — documentation map

This is the index for everything under `docs/` and the root-level documents it
organises. If you arrived from the repository root and do not know which of the
eight top-level Markdown files to open, start here.

**Reading order for a new reader:** [What it is](what-is-redfall.md) →
[Positioning](analysis/positioning.md) → [The case against it](analysis/cons.md)
→ [What comes next](roadmap/deeper.md).

---

## Orientation

| Document | Answers | Read it when |
| --- | --- | --- |
| [What RedFall is](what-is-redfall.md) | The whole system in one document | First. Nothing else is needed to understand the idea. |
| [How it is structured](architecture.md) | Module map, data flow, the seams | Before touching code |
| [Glossary](glossary.md) | Every term this project uses precisely | When a word seems to mean something specific |

## Where it stands

| Document | Answers |
| --- | --- |
| [Positioning](analysis/positioning.md) | Which category it is in, what it does better, what it does worse |
| [The case against RedFall](analysis/cons.md) | Every serious objection, ordered by damage, with its fix |
| [Roadmap](roadmap/deeper.md) | The next phases, each one closing a named objection |

## Trust and evidence

| Document | Answers |
| --- | --- |
| [Evidence model](evidence-model.md) | How a candidate becomes a finding, and what E0–E4 mean |
| [The bench](bench.md) | How the engine's own recall is measured, and the first number |
| [`SECURITY.md`](../SECURITY.md) | Reporting a vulnerability; the supply-chain story; the range-target warning |
| [`BLOCKED.md`](../BLOCKED.md) | What cannot run on the build host, with the smallest real unblock for each |
| [`CHANGELOG.md`](../CHANGELOG.md) | What shipped, with the numbers that were measured |

## Working on it

| Document | Answers |
| --- | --- |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | The no-mock rule, stage ownership, the PR contract |
| [`RELEASE.md`](../RELEASE.md) | The release checklist and versioning policy |
| [Architecture](architecture.md) | Where a change belongs |

## Historical

Kept because a decision is easier to judge with its reasoning attached.

| Document | What it was |
| --- | --- |
| [`PLAN-0.2-to-0.5.md`](history/PLAN-0.2-to-0.5.md) | The plan that produced 0.2.0 through 0.5.0. **Spent** — every phase shipped. |
| [`ROADMAP.md`](../ROADMAP.md) | The twelve-month destination and the 1.0 definition of done |

---

## Where a given question is answered

| Question | Document |
| --- | --- |
| "Does it actually find anything?" | [Positioning §5](analysis/positioning.md) — and the honest answer is that this is unmeasured |
| "What is it bad at?" | [The case against RedFall](analysis/cons.md) |
| "Why is this test skipped?" | [`BLOCKED.md`](../BLOCKED.md) |
| "What does `E3` mean?" | [Evidence model](evidence-model.md) |
| "Can I run it without Docker?" | No. [`BLOCKED.md`](../BLOCKED.md), and the engine refuses rather than degrading |
| "How do I add a language?" | [Architecture § language registry](architecture.md#adding-a-language) |
| "How do I add an agent?" | [`CONTRIBUTING.md`](../CONTRIBUTING.md), then the driver contract |
| "Is it safe to point at my code?" | [`SECURITY.md`](../SECURITY.md) |
| "What is the licensing?" | [`README.md`](../README.md) — and there is no declared license |

---

## The documents at the root, and why they are there

Only files that a reader of the repository *front page must see* stay at the
root. Everything explanatory lives in `docs/`.

| Root file | Why not in `docs/` |
| --- | --- |
| `README.md` | The front door. GitHub renders it by default. |
| `CONTRIBUTING.md` | GitHub links it from the issue and PR templates. |
| `SECURITY.md` | GitHub links it from the security tab. |
| `CHANGELOG.md` | Convention; GitHub's releases UI links it. |
| `BLOCKED.md` | Named in the README's status table and in `SECURITY.md`; a reader must be able to find it from the root. |
| `ROADMAP.md` | Named in the README and the site's navigation. |
| `RELEASE.md` | Referenced by the release workflow. |
| `llms.txt` | Must be at the root for a crawler to find it by convention. |
