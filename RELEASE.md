# Release plan and checklist

This is the operating plan for RedFall releases. It is deliberately concrete:
every step names the command, the expected evidence, or the limitation that must
be stated instead of hidden. A release is not "done" because the tag exists; it
is done when the published artifacts and the documented evidence agree.

## Versioning policy

- `src/redfall/version.py` is the single source of truth for the version.
- `VERSION`, `pyproject.toml`, `range/pyproject.toml`, the package manifests,
  the npm lockfile roots, the site release module and `llms.txt` are checked
  against it by `scripts/check_version.py`.
- A release never moves or reuses a tag. If a published artifact is wrong, yank
  it and ship the next patch version.
- Until 1.0, backward-incompatible changes are allowed in a minor release. This
  project uses patch releases for consolidations only when explicitly planned;
  `0.1.1` is such a consolidation.

## 0.1.1 scope

`0.1.1` consolidates everything landed after the `v0.1.0` tag:

- Phase 1: campaign kernel, durable tasks/leases/budgets, evidence ledger, MCP
  stdio campaign tools and the campaign CLI.
- Phase 2: persisted provenance-aware graph v1, resumable runner, real
  graph/scan/reproduce/report handlers, 44 MCP tools, scope hardening and the
  executable MCP adapter contract.
- Phase 3: HTTP/OpenAPI and A2A v1.0 gateway over the same `ToolRegistry`,
  agent tokens/scopes/quotas, audit, signed artifacts, webhooks, SSE and the
  HTTP/A2A contract checkers.
- Post-0.1.0 site, documentation, SEO, accessibility, brand and evidence work.
- Test-harness hardening: PostgreSQL tests require an explicit test database and
  skip honestly when it is absent.
- Release hardening: dynamic version contract across source, package metadata,
  lockfiles and site metadata; release-contract tests.

## Pre-release plan

1. **Establish the baseline.** Confirm `main` is clean, the latest CI run is
   green, and `v0.1.1` does not already exist.
2. **Declare the version once.** Update `src/redfall/version.py`, then make the
   checker and every declaration agree. Run `python scripts/check_version.py`.
3. **Write the release record.** Move the post-0.1.0 changelog entries under
   `[0.1.1]`, add the comparison link, update README/ROADMAP/BLOCKED/SECURITY,
   and update the generated site and `llms.txt`.
4. **Make the public docs true.** The CLI reference must list the actual
   commands; the architecture and interoperability pages must describe the
   shipped transports and their limits. No unexecuted transport is called
   "certified".
5. **Run the local gates.**
   - `python scripts/check_no_mock.py`
   - `python scripts/check_version.py`
   - `python scripts/check_orphans.py`
   - `python scripts/check_clean_tree.py`
   - `python -m pytest tests/ -q` (expect the PostgreSQL and gVisor subsets to
     skip when their prerequisites are absent; never count a skip as a pass)
   - `cd site && npm ci && npm run build && npm run check:seo`
   - Chrome-backed `check:layout`, `check:a11y`, `check:docs`, and Lighthouse
     where a Chrome binary exists.
6. **Prove the package.** `python scripts/build_release.py`, then
   `scripts/verify_wheel.py` in a fresh virtualenv from outside the checkout;
   run both installers into throwaway homes.
7. **Commit and push.** Keep the release commit focused. Wait for every CI job,
   including the Postgres-backed `check` job and the six package/installer jobs.
8. **Tag and release.** Create `v0.1.1` at the verified commit and push the tag.
   The release workflow builds, checksums, attests and publishes the artifacts.
9. **Verify the published result.** Download the release assets, check
   `SHA256SUMS`, run `gh attestation verify` for both the wheel and the sdist,
   install the wheel outside the checkout, and record the release URL and
   attestation identity in `BLOCKED.md` and the site evidence page.
10. **Publish the final evidence.** Push the measured release evidence. Do not
    rewrite a claim to match a failed run; report the failure and fix it.

## Release gates

| Gate | Pass condition | What it does not prove |
| --- | --- | --- |
| Version contract | Every declaration equals the source of truth | That the package was published |
| No-mock contract | No synthetic fallback in product code | That every runtime path was exercised |
| Unit/contract suite | All collected tests pass or skip with a named prerequisite | That a full scan works on a host without gVisor/LLM/Postgres |
| Site build + SEO | Real static pages, canonical/schema/sitemap/llms checks | Search rankings, backlinks or AI citations |
| Release build | Wheel and sdist contain the harness, prompts and Dockerfile | That the target application is safe |
| Sigstore attestation | Artifact came from the tagged release workflow | That the software has no vulnerabilities |
| Installer matrix | The wheel installs on the CI OS/Python matrix | That the host has a sandbox or provider key |

## Rollback

- Never retag `v0.1.1` or replace its assets silently.
- If the release is unusable, mark the GitHub release as a pre-release or delete
  the release (keeping the tag history visible), publish the reason, fix on
  `main`, and ship `0.1.2`.
- If only documentation is wrong, ship a docs-only commit and update the release
  notes; do not rebuild the same version with different bytes.

## Execution record

Fill this table only with commands that actually ran. A blank cell is a pending
check, not a pass.

| Date | Check | Observed result |
| --- | --- | --- |
| 2026-10-21 | Baseline `main` | `9000b9e`, clean tree; CI run `39313598416` green |
| 2026-10-21 | Version contract | `VERSION CONTRACT: PASS` — 11 declarations, 5 lockfile roots |
| 2026-10-21 | No-mock contract | `NO-MOCK CONTRACT: PASS` — 80 files |
| 2026-10-21 | Orphan check | `ORPHAN CHECK: PASS` — 78 reachable modules |
| 2026-10-21 | Clean-tree check | `CLEAN TREE: PASS` — no stray files |
| 2026-10-21 | Full local suite | **337 passed, 30 skipped** in 221.23s (25 PostgreSQL, 5 gVisor); 367 collected |
| 2026-10-21 | Site build + SEO | 25 HTML routes, 24 sitemap URLs, 0 errors; axe 0 violations on 23 docs routes; layout clean at 390/768/1280; Lighthouse 100/100/100/100 desktop and mobile (mobile LCP 1.5 s) |
| 2026-10-21 | Release build + wheel verification | wheel/sdist built with `SHA256SUMS`; `WHEEL VERIFY: PASS` outside the checkout; installed distribution reports 0.1.1 |
| 2026-10-21 | Windows installer | throwaway `REDFALL_HOME` installed 0.1.1; `install.sh` parsed with Git Bash |
| 2026-10-21 | `redfall doctor` on release host | Postgres and Redis MISSING after bounded probes; `runsc` and LLM provider MISSING; Node/npm OK; exits 1 |
| 2026-10-21 | CI on release code (`7e1695f`) | run [39612206950](https://github.com/DevAnimecx/redfall/actions/runs/39612206950): **362 passed, 5 skipped in 73.96s**; all six package jobs' steps completed successfully |
| 2026-10-21 | CI on tag commit | pending |
| 2026-10-21 | Pages deployment | run [39612206947](https://github.com/DevAnimecx/redfall/actions/runs/39612206947): 25 HTML routes / 24 sitemap URLs; live monitor 24 pages; IndexNow 24 URLs, HTTP 200; missing path 404 |
| 2026-10-21 | Live Lighthouse (two runs) | desktop 97–98; mobile 93–99; 100 accessibility/best-practices/SEO; one mobile run below the 95 performance gate |
| 2026-10-21 | `v0.1.1` publication | pending |
| 2026-10-21 | Downloaded artifact + attestation verification | pending |
