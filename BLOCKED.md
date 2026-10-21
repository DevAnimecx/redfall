# BLOCKED

Two prerequisites for a full Redfall scan are not available on this host. Both
are infrastructure, not design: the code paths are written and complete, and each
one fails loudly at the point where it would otherwise have to pretend.

Per §1 rule 9 this document exists rather than a fallback. There is no demo mode,
no synthetic fixture path, and no host-execution escape hatch.

---

## Blocker 1 — no container runtime, so no gVisor sandbox

### What is blocked

`redfall scan` cannot execute a PoC. §1 rule 5 requires every finding to be
reproduced inside a real Docker container on `runsc`. Nothing is reported without
that.

### What was tried

```
$ which docker runsc crun runc
(no output — none of them exist)

$ ls -la /var/run/docker.sock
ls: cannot access '/var/run/docker.sock': No such file or directory

$ for b in docker podman nerdctl ctr crictl runsc runc crun singularity apptainer proot bwrap firejail; do command -v $b; done
(no output)

$ docker info --format '{{json .Runtimes}}'
/bin/bash: line 1: docker: command not found
```

Also checked: `/proc/sys/kernel/unprivileged_userns_clone` does not exist, and
`sudo` works — so the missing piece is the runtime itself, not permissions. There
is no daemon to talk to and nothing to install a runtime into.

Redfall's own check agrees:

```
$ python3 -c "import sys; sys.path.insert(0,'src'); \
  from redfall.sandbox.docker_gvisor import describe; print(describe())"
{'runtime': 'runsc', 'ready': False,
 'reasons_unavailable': ['the `docker` CLI is not on PATH'], 'docker_cli': False}
```

### Smallest real unblock

A host with Docker plus gVisor installed and registered:

```jsonc
// /etc/docker/daemon.json
{ "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } } }
```

`redfall doctor` turns green the moment `runsc` appears in `docker info`. Nothing
in `src/redfall/sandbox/` needs to change.

### What is real in the meantime

- `src/redfall/sandbox/docker_gvisor.py` builds the full `docker run` vector:
  `--runtime=runsc`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  `--pids-limit=256`, memory and CPU caps, per-run labels, workspace mount, and
  guaranteed cleanup. `check_runtime()` enumerates the actual reasons it cannot
  run rather than returning a boolean.
- `src/redfall/validation/harness.mjs` — the in-container exploit runner — is
  complete for both target runtimes: it starts a real PostgreSQL, installs and
  boots the target (Node through `npm start`; Python through a venv plus the
  target's `redfall.target.json` — or a root `app.py`), waits for `/health`,
  replays raw HTTP requests over a real socket, and evaluates the PoC predicate
  against the real response. An unknown tree is a reported `target-missing`
  failure, never a guessed entrypoint.
- The Python boot contract was **verified end to end on this host**: the real
  `range/pythonbank/redfall.target.json` resolves to
  `python -m pythonbank.app` (cwd `src`, `PYTHONBANK_PORT=$PORT`), and that
  command line really boots pythonbank and answers `200` on `/health`
  (`node tests/harness/verify_python_target.mjs`, also run by the pytest
  suite). The host Python stands in for the sandbox's virtualenv Python; the
  argv/cwd/env semantics under test are identical.
- The harness's request parsing, chunked-transfer decoding, CSV parsing and
  predicate evaluation were **verified against live HTTP traffic on this host**,
  including the real VULN-001 predicate from the manifest. Two genuine bugs were
  found that way (see below). They would otherwise have silently turned every
  successful exploit into a false negative.
- `tests/test_sandbox.py` asserts the refusal, and asserts there is no host
  execution path in the module: no `os.system`, no `shell=True`, and every
  `subprocess.run` command vector starts with the docker CLI.

---

## Blocker 2 — no LLM provider credential

### What is blocked

The planner, analyser, PoC generator and fixer cannot run. §1 rule 4 requires
every LLM call to be live to a real provider, or a cached *real* response with
its raw request and response stored. There is no third option, so nothing is
synthesised.

### What was tried

```
$ env | grep -E 'OPENAI|ANTHROPIC'
(no output)

$ redfall doctor
│ LLM provider │ MISSING │ set OPENAI_API_KEY or ANTHROPIC_API_KEY │
```

Calling through the real client confirms it fails rather than inventing:

```
LLMError: gpt-4o-mini call failed at stage 'probe': InternalServerError:
litellm.InternalServerError: InternalServerError: OpenAIException -
Missing credentials. Please p...
```

### Smallest real unblock

```bash
export OPENAI_API_KEY=sk-...      # or ANTHROPIC_API_KEY
```

Tier routing honours `REDFALL_MODEL_FAST` / `_MID` / `_DEEP` if you want specific
models instead of the defaults.

### What is real in the meantime

- `src/redfall/llm.py` makes live LiteLLM calls, enforces the §5 token and cost
  ceilings *before* the call, and persists the verbatim request and response for
  every call in `llm_responses`. Repeating an identical prompt reuses the stored
  real transcript (recorded with `cached=true`) instead of re-billing — it never
  substitutes a fabricated one.
- JSON extraction handles fenced, prose-wrapped and trailing-garbage output, and
  raises `JSONParseError` when there is genuinely nothing to parse. Malformed
  output triggers a real repair call; it never falls back to a default.
- `src/redfall/agent/prompts/` contains the five real stage prompts (planner,
  analyzer, poc generator, fixer, chain analyst) plus the shared `_common.md`.
- `src/redfall/agent/categories.py` is the 25-of-32 coverage decision, with the
  measured reason recorded for each of the 4 exclusions.

---

## What is verified and running

Everything that does not need those two prerequisites is built and was exercised
against the real target:

| Command | Result |
| --- | --- |
| `python scripts/check_no_mock.py` | `NO-MOCK CONTRACT: PASS` (80 files) |
| `python scripts/check_version.py` | `VERSION CONTRACT: PASS` (11 declarations, 5 lockfile roots) |
| `python scripts/check_orphans.py` | `ORPHAN CHECK: PASS` (78 modules) |
| `python scripts/check_clean_tree.py` | `CLEAN TREE: PASS` |
| `python -m pytest tests/ -q` on this host | `337 passed, 30 skipped` in 196.67s (25 PostgreSQL, 5 gVisor) |
| `python -m pytest tests/ -q` in CI (latest pre-release run 39313598416) | `357 passed, 5 skipped` in 63.08s, PostgreSQL 17 / Python 3.12 |
| `python -m pip wheel . --no-deps -w dist` + `scripts/verify_wheel.py` in a fresh venv, run from outside the checkout | `WHEEL VERIFY: PASS` — the installed wheel ships the harness and finds the interprocedural taint |
| `python scripts/build_release.py` | builds `redfall-0.1.1-py3-none-any.whl` + `redfall-0.1.1.tar.gz`, writes `SHA256SUMS`, and proves the harness, every prompt and the Dockerfile are inside both archives |
| `powershell -File scripts/install.ps1 -NoPath` with a throwaway `REDFALL_HOME` | `Redfall 0.1.1 installed.` and the host's real doctor report — executed end to end on Windows; `bash -n scripts/install.sh` parses clean with a real POSIX shell here, and CI executes both installers on Ubuntu, Windows and macOS |
| GitHub CI on `main` (`check` + 6-job package matrix) | green on the latest pre-release run 39313598416; the 0.1.1 release-commit run is recorded after publication |
| `gh attestation verify redfall-0.1.1-py3-none-any.whl --repo DevAnimecx/redfall` on the downloaded release | pending publication; the 0.1.0 artifact was verified against `release.yml@refs/tags/v0.1.0` |
| `node tests/harness/verify_harness.mjs --poc <poc>` | `ALL HARNESS CHECKS PASSED` |
| `node tests/harness/verify_python_target.mjs` | `ALL PYTHON TARGET CHECKS PASSED` |
| `node tests/harness/verify_chain_steps.mjs` | `ALL CHAIN HARNESS CHECKS PASSED` |
| `python scripts/replay_poc.py --all` (pythonbank) | `reproduced: 17 / 17` over real HTTP |
| `python -m pytest tests/ -q` (pythonbank) | `18 passed` |
| `cd range/vulnbank && ./scripts/verify_patches.sh` | `verified: 32 / 32` |
| `npm test` (vulnbank) | `76 passed` |
| `npm test` (vulnbank-adaptive) | `91 passed` |
| `npx ts-node scripts/replay_poc.ts --all` (vulnbank-adaptive) | `7/7 PoC(s) reproduced` |
| `npm test` (chainbank) | `8 passed` |
| `npx ts-node scripts/replay_chain_poc.ts` (chainbank) | `6/6 chain(s) reproduced end to end` |
| `redfall scan range/vulnbank` | refuses with both blockers named |
| `cd site && npm ci && npm run build` | prerenders the landing page into `dist/index.html` (full rendered markup plus JSON-LD), generates 23 static docs/trust pages, a 24-URL sitemap, `robots.txt`, `llms.txt`, a real 404 and 24 OG cards; the `pages` workflow re-asserts the content and runs `npm run check:seo` before upload |
| Pages deploy (last was 0.1.0, [run 39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525), 2026-10-19) | **build + deploy both succeeded** for 0.1.0. The build ran `check:seo` (`PASS`, 24 HTML routes / 23 sitemap URLs / 0 errors). The deploy job verified the live key, POSTed 23 URLs to IndexNow and received **HTTP 202 Accepted**, then the live SEO monitor passed all 23 pages. A missing live path returned **HTTP 404**, not a soft 200. The 0.1.1 deployment is recorded after publication |
| Live site `https://devanimecx.github.io/redfall/` after that deploy | landing and docs `200`; canonical/hreflang/title/OG present; `sitemap.xml`, `robots.txt`, `llms.txt`, IndexNow key and OG card all `200` |
| Lighthouse, live deployed landing, desktop preset | **100 / 100 / 100 / 100**; LCP 0.6 s, TBT 0 ms, CLS 0 |
| Lighthouse, live deployed landing, mobile preset (0.1.0) | **98 performance**, with **100 / 100 / 100** accessibility, best-practices and SEO; LCP 1.7 s, TBT 60 ms, CLS 0. Above the 95 gate |
| Lighthouse, live deployed docs page | **100 / 100 / 100 / 100** desktop; **99 performance**, 100 accessibility/best-practices/SEO mobile; zero client JavaScript |
| Lighthouse, local 0.1.1 production build, landing mobile preset | **100 / 100 / 100 / 100**; LCP 1.5 s, TBT 0 ms, CLS 0 under simulated Slow-4G. Every category stays above the 95 gate |
| Lighthouse, local production build, redesigned landing desktop preset | **100 / 100 / 100 / 100**; LCP 0.4 s, CLS 0 |
| Lighthouse, local production build, docs page mobile | **99–100 performance**, with **100 / 100 / 100** accessibility, best-practices and SEO; the docs ship zero client JavaScript, so `robots-txt` only passes once `connect-src 'self'` is allowed (it was `'none'`, which blocked Lighthouse's own `robots.txt` probe) |
| `node site/scripts/a11y_check.mjs` (axe-core in real Chrome) at 390, 768 and 1280 px | `PASS` — **0 violations** at every width on the landing page. This caught a real bug: the horizontally scrollable install code blocks were not keyboard-reachable; they are now labelled, focusable regions |
| `node site/scripts/docs_check.mjs` (axe-core + layout + zero-JS on every docs route) | `PASS` — 23 routes × 390/1280 px, **0 axe violations**, **0 px horizontal overflow**, exactly one H1, no client scripts, and the H1 is readable with JavaScript disabled. This found and fixed two real bugs: duplicate `role="region"` landmark names in Markdown tables/code, and a long inline `pipx install git+https://…` token that widened the mobile document by 9 px until `overflow-wrap: anywhere` was applied |
| `node site/scripts/seo_check.mjs` | `SEO GATE: PASS` — 25 HTML routes, 24 sitemap URLs, 0 errors; canonical/H1/schema/internal-link/OG/robots/llms/IndexNow checks included |
| `node site/scripts/indexnow.mjs --dry-run` | prints the 24 sitemap URLs and the public key location, sends nothing. The 0.1.1 production submission runs in the Pages deploy workflow after publication; the last recorded submission was 23 URLs (0.1.0) with **HTTP 202 Accepted** |
| `python -m pytest tests/test_brand_assets.py -q` | `4 passed` — the SVG shield geometry is pinned to the raster generator's point list; the committed social card is 1200×630 and every icon matches the size its link advertises |
| `python scripts/check_no_mock.py` / `check_version.py` / `check_orphans.py` / `check_clean_tree.py` | `PASS` (80 files scanned, 11 version declarations, 78/78 modules reachable, no stray files) |

The ingestion engine, run against the real `vulnbank` tree:

```
files=21 taints=20 routes=27 deps=24 errors=[]
mount prefixes resolved: 14
   src/routes/auth.ts   -> /api/auth
   src/routes/admin.ts  -> /api/admin
   ...
-- taint path -> owning route
   src/routes/auth.ts:41   pool.query  <- req.body    | POST /api/auth/login
   src/routes/admin.ts:25  exec        <- req.body    | POST /api/admin/exec
   ...
-- persisted rows
   files 21 | symbols 238 | taint_paths 20 | deps 24
```

That `auth.ts:41` line is VULN-001. The manifest anchors it at line 38, which is
inside the matcher's ±5 tolerance, and the symbol `loginHandler` matches exactly.

The interprocedural pass, run against the real `pythonbank` tree, where VULN-017's
SQL is built in `core/reports.py` while the route only forwards a parameter:

```
$ python -c "... ingest('probe', 'range/pythonbank/src') ..."
parse_errors: []
edges: 26
reports edges: [('summary', 'department_summary', ['department'])]
inter taints:
  pythonbank/core/reports.py conn.execute 15 department_summary request.args.get()
  via: ['request.args.get() -> summary (pythonbank/routes/reports.py:21)',
        'pythonbank.core.reports.department_summary -> department_summary via argument 2 (pythonbank/core/reports.py)',
        'param department -> conn.execute']
```

The manifest anchors VULN-017 at `core/reports.py:13`; the emitted taint lands on
line 15, inside tolerance, with the symbol fetched through the import bindings
(`from ..core import reports`) rather than a name match.

The TypeScript side of the same pass, run against the real `vulnbank` tree —
cross-file calls resolved through ESM import bindings, `require` bindings,
aliases and namespaces, with tainted arguments recorded on the edge:

```
$ python -c "... ingest('probe-ts', 'range/vulnbank') ..."
errors: []
edges: 11
selected edges (caller -> callee, tainted params):
  src/routes/auth.ts   loginHandler -> src/auth/hash.ts       verifyPassword [plain]
  src/routes/auth.ts   loginHandler -> src/routes/auth.ts     asString       [value]
  src/middleware/jwt.ts requireAuth -> src/middleware/jwt.ts  verifyToken    [token]
  src/db/seed.ts       seed         -> src/db/schema.ts       ensureSchema
  src/server.ts        main         -> src/app.ts             createApp
inter taints: []
```

`loginHandler -> verifyPassword [plain]` is the login handler's password
argument: the argument really is tainted (`req.body`), and the edge records that
fact — but `verifyPassword`'s body contains no classified sink, so **no taint is
claimed**. Zero interprocedural taints on vulnbank: the scored pipeline gains a
real call graph and no new claims, which is exactly the intended direction of
error. Every interprocedural taint that is emitted must be reachable from a
route through the graph (`routes_for_line` follows the edges), enforced by
`tests/test_inter_ts.py::test_vulnbank_call_graph_is_real` and the existing
reachability test in `tests/test_ingestion.py`.

---

## Bugs found by testing rather than by reading

Both were in the component that decides whether an exploit worked. Neither would
have been visible until the first real scan, and both would have suppressed every
true positive.

1. **`static` is a strict-mode reserved word.** The harness evaluated predicates
   inside `new Function(..., '"use strict"; return (…)')` and bound a parameter
   named `static`. Every predicate threw `SyntaxError: Unexpected strict mode
   reserved word` before it could run.
2. **Chunked responses were not decoded.** Node's HTTP server chunks any response
   whose length is not known up front, so response bodies arrived as
   `57\r\n{"token":…}\r\n0\r\n\r\n`. `JSON.parse` failed on the chunk-size prefix,
   leaving `json === null`, so every predicate that inspected the parsed body
   evaluated to false.

Both are now covered by `tests/harness/verify_harness.mjs`, which runs the real
predicate from `manifest.yaml` against a live Node HTTP server.

Three more were found the same way while building the adaptive and chain
components. Each was invisible in a unit test and would have suppressed real
results:

3. **A multipart body cannot survive CRLF normalisation.** `parseRawRequest`
   rewrites every CRLF to LF, which is right for JSON and wrong for RFC 7578:
   the rewritten body no longer matches the `Content-Length` describing it, so
   the server waited for bytes that never arrived. `chainbank`'s upload chain
   hung for the full request timeout instead of failing.
4. **Two `Content-Length` headers are a hard rejection.** The harness emitted the
   manifest's declared length and then its own. Express treats that as a possible
   smuggling attempt and answers 400 with an empty body, which reads like a
   missing route rather than a malformed request.
5. **A scope fingerprint keyed on files alone drops whole trigger types.** Three
   distinct surfaces in one module — a feature flag, an environment conditional
   and a plugin loader — hashed to the same scope, so the cycle guard refused two
   of the three. Only 4 of the 7 adaptive triggers ever reached the tree. The
   fingerprint now includes the triggering surface.

---

## Blocker 3 — no KVM, so no Firecracker microVMs

### What is blocked

The scale-out target of 50 concurrent microVMs, and the p95 < 100 ms claim about
branch startup, cannot be measured here.

### What was tried

```
$ ls -l /dev/kvm
ls: cannot access '/dev/kvm': No such file or directory

$ grep -E 'vmx|svm' /proc/cpuinfo
(no output — the CPU flags are not exposed to this sandbox)

$ apt-cache policy qemu-kvm
qemu-kvm: Installed: (none)

$ which firecracker jailer
(no output)

$ free -m
              total        used        free
Mem:           1982         ...
```

GitHub's release endpoint for Firecracker is reachable (HTTP 200), so the
binaries could be downloaded. They cannot be booted: there is no `/dev/kvm` and
no nested virtualisation.

The memory ceiling is the harder limit. 50 VMs at 512 MiB each is 25,600 MB
against 1,982 MB available. Even with KVM this host could not hold the
concurrency the claim describes.

### Smallest real unblock

A KVM-capable host. The user has one available; the Firecracker configuration
and the measurement harness should be written here and measured there, with the
result recorded in `range/firecracker_metrics.json` per §2 rule 15. No number
from the PRD may be cited in its place.

---

## Blocker 4 — no provider key, so no token-economics benchmark

### What is blocked

The ≥90% median token reduction claim. §2 rule 14 requires the comparison to run
against a genuine tool-calling baseline on the same branch, model, sandbox and
target, over at least 20 branches and 3 apps.

### What was tried

No credential is available, and `src/redfall/llm.py` refuses to run without one
rather than degrading. There is no cached-response path that could substitute:
the cache records real transcripts from real calls, and there have been none.

### Smallest real unblock

A provider key. Without one, the honest position is that the claim is
unmeasured — not that it is approximately some number.

---

## Blocker 5 — Rust orchestrator parity cannot be demonstrated

### What is blocked

§2 rule 16 requires the Rust orchestrator's output to diff empty against the
Python one on `vulnbank` and `chainbank`. Parity is a statement about two real
scans, and neither scan can run (blockers 1 and 2).

`rustc 1.85.1` is available via apt and `rustup` is reachable, so the
orchestrator itself can be written and compiled here. What cannot be produced
here is the pair of scan outputs to compare.

### Smallest real unblock

Blockers 1 and 2 first. Writing the Rust orchestrator before the Python scan
path works would mean comparing two things that both fail.

---

## Blocker 6 — actions that require a human account or a human decision

### What is blocked

| Item | Why it cannot be done from this repository | Smallest real unblock |
| --- | --- | --- |
| Google Search Console verification | Google issues a per-account verification file/token; committing a fabricated one would be a false claim | The owner adds a URL-prefix property for `https://devanimecx.github.io/redfall/`, verifies with the real HTML file, and submits `sitemap.xml` |
| Bing Webmaster Tools | Same account-bound verification | The owner verifies the property and confirms the IndexNow submissions in the dashboard |
| GitHub social preview upload | GitHub exposes this through the web UI, not the API used here | Upload `site/public/og.png` (1200×630) in repository settings |
| Backlinks, organic rankings, AI citations | Depend on external sites, search engines and assistants; they cannot be manufactured or guaranteed | Earn them by publishing and submitting real work; record only observed referrals/citations with a date and source |
| Full `python -m pytest tests/ -q` on this host | The database-backed tests require an explicit `REDFALL_TEST_DATABASE_URL`; this host has no PostgreSQL service or binaries, so 25 database tests skip. The five gVisor tests also skip. The complete local run was 337 passed / 30 skipped on 2026-10-21 | Provision PostgreSQL and set `REDFALL_TEST_DATABASE_URL`, then re-run the full suite |
| License choice | Choosing a licence is a legal decision for the project owner, not an SEO or engineering default | The owner adds the chosen `LICENSE` file; until then the repository is source-available, and no licence is claimed |
| Dependabot pull requests | Need human review before merge; merging unreviewed dependency bumps would weaken the supply-chain claim | Review and merge or close them, one at a time, with CI evidence |

None of these blocks the technical SEO gates: those run on every push without
external accounts. The site does not pretend a verification happened before the
account confirms it, and it does not display a ranking, a backlink count or an
AI-citation count that was not observed.

---

## Update 2026-10-11 — the sandbox blocker is cleared; one remains

Blocker 1 (no container runtime) is **resolved on this host**, and clearing it
exposed a latent bug in the exploit-execution path.

### What was done

Docker 26.1.5 and `runsc` 0.0~20240729.0 were installed via apt and runsc was
registered in `/etc/docker/daemon.json`. Verified by executing inside the
container, not by reading `docker info`:

```
$ docker run --rm --runtime=runsc alpine:3 sh -c 'head -c 40 /proc/version'
Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016
```

`4.4.0` is gVisor's Sentry kernel, not the host kernel, so the sandbox is real.

### Bug found and fixed: the ENTRYPOINT swallowed argv

`src/redfall/sandbox/images/redfall-sandbox/Dockerfile` declared
`ENTRYPOINT ["/bin/bash", "-lc"]`. A caller-supplied vector is appended to an
entrypoint, so `command=["node", "harness.mjs"]` became
`bash -lc node harness.mjs`, which execs `node` with `$0="harness.mjs"` and no
arguments. Measured before the fix:

```
$ docker run --rm --runtime=runsc -v $WD:/work --workdir=/work \
    redfall-sandbox:latest node harness.mjs
(no output)
exit=0
```

The harness never ran, yet the run reported success with empty stdout. This is
the worst possible failure mode for a validator: `validator.py` and `fixer.py`
both pass their vector as `command=`, so **every reproduction and every fix
verification would have reported a silent pass**. It was invisible until now
only because the sandbox could never execute anything.

Fix: `ENTRYPOINT []`. Callers that want shell semantics pass `bash -lc`
themselves, which `fixer.py` already does. After the fix the same vector gives:

```
HARNESS_RAN argv= []
```

Five tests were added to `tests/test_sandbox.py` covering the positive path —
output capture, the `/work` mount, non-root uid, argv delivery, and Sentry
kernel confirmation. The ENTRYPOINT mutation was injected and all five fail;
reverting restores 8 passed.

### A second finding the fix uncovered

The container runs as uid 10001 and bind-mounts the host workdir. A workdir
created `0700` — which is what `tempfile.mkdtemp` and therefore pytest's
`tmp_path` produce — is not traversable by it, and the failure surfaces as
`cat: /work/marker.txt: Permission denied` rather than as a configuration
error. A checked-out repo is `0755` and works. This is recorded because any
caller that stages a workspace with restrictive permissions will hit it.

### Environment restore

The sandbox recycles between sessions and none of this survives. `scripts/restore_env.sh`
now restores Postgres (with the roles, databases, schema ownership and grants
the tests require), Redis, the Python dependencies, `range/*/node_modules`, and
Docker with runsc registered, in one idempotent command. Run it before trusting
any green result.

### What is still blocked

```
$ python3 -c "... check_prerequisites(config) ..."
PREREQUISITES: UNMET
unmet prerequisites:
  - no LLM provider credential found; set OPENAI_API_KEY or ANTHROPIC_API_KEY.
```

One prerequisite now fails instead of two. Redfall makes live provider calls
only (§2, no-mock contract), so a real `redfall scan` still cannot run on this
host. Nothing has been stubbed to get past it.

### Measured state after this work

`pytest tests/ --continue-on-collection-errors -q` → **139 passed, 3 skipped**.
The 3 skips are the gVisor-absence tests in `test_sandbox.py`, which now skip
because gVisor genuinely is available — their reason string says so.

---

## Update 2026-10-18 — this host has no container runtime; chain and fix plumbing hardened

That 2026-10-11 update describes a Linux sandbox session, not this host. Measured
here, right now:

```
$ docker --version
docker: command not found

$ python -c "... describe() ..."
{'runtime': 'runsc', 'ready': False,
 'reasons_unavailable': ['the `docker` CLI is not on PATH'], 'docker_cli': False}
```

Blocker 1 is active again on this host, and the five gVisor tests in
`tests/test_sandbox.py` skip with `gVisor unavailable on this host: nothing to
execute`. Blocker 2 is unchanged. `redfall scan range/vulnbank` refuses naming
both prerequisites; that is the only implemented behaviour.

### What was added and verified since (all through real execution)

- **The chain stage is complete.** Reproduced findings go to a chain analyst
  prompt; `chain/plan.py` reviews each proposal structurally (step counts,
  finding references, extract grammar); the accepted chain is replayed as one
  composite PoC by the same sandbox validator; only hops whose predicates held
  become `EdgeRow`s, and the report's chains/edges are read back from the
  database and rebuilt with `build_graph`. A proposal review refuses is
  persisted and reported as refused with its reasons, and a review refusal can
  never contribute an edge. `tests/test_chain_pipeline.py` drives all of this
  against a real Postgres (plan rules, PoC composition, hop admission at
  k=3/2/0, persistence, graph rebuild, refusal rows).
- **The multi-step runner is verified over live HTTP.**
  `runStepChain` (substitution, extraction, per-step predicates) lives in
  `validation/harness_internals.mjs`; `tests/harness/verify_chain_steps.mjs`
  executes it against servers it starts itself — 38 checks, including a real
  JWT forgery and every failure kind (`unbound`, `predicate`, `extract`,
  `setup`).
- **The range scorer translates id vocabularies.** The scanner reports its own
  finding ids; the manifest speaks in its own. `range_runner` now rewrites the
  report through the matcher's finding→vuln map before scoring. A join through
  a step outside ground truth breaks the sequence instead of being bridged, so
  no join is credited that the report did not state.
- **`redfall fix --out fixes.json`** appends or replaces one record per finding
  (`finding_id`, `verified`, `status`, test and PoC outcomes) — the file
  `range_runner --fixes` scores.
- **Two real bugs in `fix/applier.py`**, found by new tests against a scratch
  git repository: `git apply --check -` was never handed the patch on stdin, so
  every patch was rejected; and on Windows, text-mode pipes rewrote the patch's
  line endings, so hunks could not match. `tests/test_fix_applier.py` covers
  acceptance, rejection, branch rebuild on a stale branch, and revert.
- **The checker scripts are clean on Windows.** `check_version.py` no longer
  false-positives on path separators; `check_orphans.py` credits a package
  `__init__` that a reachable submodule executes. `make check` runs all four
  checkers plus the suite, and `.github/workflows/ci.yml` runs the same on
  every push.

### Measured state after this work

`python -m pytest tests/ -q` → **254 passed, 5 skipped** (the 5 gVisor skips),
with `REDFALL_TEST_DATABASE_URL` pointed at a real Postgres. The four contract
checkers all pass; see the table at the top of this document.

The package is installable on any platform Python 3.12 runs on: the wheel is
`py3-none-any`, carries the sandbox harness, the prompts and the Dockerfile as
package data, and is verified from outside the checkout by
`scripts/verify_wheel.py` in a fresh virtualenv (`WHEEL VERIFY: PASS`). CI runs
a `package` matrix (Ubuntu, Windows, macOS × Python 3.12, 3.13) that builds the
wheel, installs it, and drives the console script from a directory outside the
repository.

---

## Update 2026-10-19 — redesign, documentation and SEO surface deployed

The redesigned landing page and 22 static docs/trust pages are live at
<https://devanimecx.github.io/redfall/>. Pages run
[39253506525](https://github.com/DevAnimecx/redfall/actions/runs/39253506525)
completed both jobs: the build ran the SEO gate (24 HTML routes, 23 sitemap URLs,
0 errors), the deploy job verified the live IndexNow key, submitted 23 URLs and
received **HTTP 202 Accepted**, and the live SEO monitor passed all 23 pages. A
missing live path returned **HTTP 404** with the custom page. Live Lighthouse:
landing 100/100/100/100 desktop and 98 performance with 100 accessibility,
best-practices and SEO mobile; docs 100/100/100/100 desktop and 99 performance
with 100 elsewhere mobile.

What remains outside this repository is still outside it: Google Search Console
and Bing Webmaster verification need the account owner, the GitHub social
preview is a web-UI upload, and rankings, backlinks and AI citations are
outcomes that are observed (or not) rather than manufactured. The full checklist
is in [`site/SEO.md`](site/SEO.md).
