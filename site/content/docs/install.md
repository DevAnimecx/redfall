---
title: Install RedFall
seoTitle: "Install RedFall on Windows, Linux or macOS"
description: "Install RedFall with pipx or a private virtualenv, verify the release attestation, run redfall doctor, and know exactly which prerequisites a full scan needs."
path: docs/install/
group: Start here
kind: pillar
pillar: install
order: 2
updated: 2026-10-21
keywords: install RedFall, vulnerability scanner install, pipx security tool, gVisor scanner setup
sources: https://github.com/DevAnimecx/redfall, https://github.com/DevAnimecx/redfall/releases/tag/v0.1.1, https://gvisor.dev/docs/user_guide/install/
related: cli, release-verification, blocked
---

**RedFall installs as a pure-Python wheel with no compiled extensions and no post-install hooks.** The installers use `pipx` when it is available and a private virtualenv otherwise, never system-wide and never elevated. A full scan additionally needs Docker with a gVisor runtime and one LLM provider key; `redfall doctor` is the authority on what the host can actually run.

This page covers the supported install paths, how to verify a release before running it, and the difference between installing the scanner and being able to execute a scan.

## What are the prerequisites?

The install itself is small. The full scan is not.

| Requirement | Needed for | Notes |
| --- | --- | --- |
| Python 3.12+ (3.13 supported) | The package | Pure-Python wheel, `py3-none-any` |
| Node 20+ | TypeScript/JavaScript targets | Targets start through `npm start` |
| Docker | Full scan | The sandbox requires a container runtime |
| gVisor `runsc` | Full scan | Execution must run on the gVisor runtime |
| LLM provider key | Analysis and chaining | Bring your own key through LiteLLM |
| PostgreSQL 17 + Redis | Persisted scans | SQLAlchemy store and runtime state |
| A target boot contract | Execution | Node or Python target contract |

The scanner will install without Docker, gVisor or a provider key. It will not fabricate a scan result without them. The [blocked page](/docs/blocked/) records the current development host, which has no container runtime and no provider key, and the [evidence page](/evidence/) separates what ran from what did not.

## How do you install with the repository installers?

The installers clone path is the most transparent option because the scripts are in the repository and can be read before they run.

**Windows (PowerShell):**

```powershell
git clone https://github.com/DevAnimecx/redfall.git; cd redfall
.\scripts\install.ps1
```

**Linux and macOS:**

```bash
git clone https://github.com/DevAnimecx/redfall.git && cd redfall
./scripts/install.sh
```

Both scripts use `pipx` when present, otherwise a private virtualenv. They do not request elevation and they do not install into the system Python. They finish by running `redfall doctor`, which prints the host's real capability report.

## How do you install with pipx, uv or a wheel?

If you already use an isolated Python installer, use it directly:

```bash
pipx install git+https://github.com/DevAnimecx/redfall
# or, inside a uv virtualenv:
uv pip install git+https://github.com/DevAnimecx/redfall
# or install a verified release wheel:
pip install redfall-0.5.0-py3-none-any.whl
```

The release wheel is built by CI from the tagged source. It carries the sandbox harness (`redfall.validation`), the agent prompts and the sandbox Dockerfile, so the runtime does not depend on files that happen to be in your checkout. `scripts/verify_wheel.py` installs the wheel into a fresh virtualenv, runs it from a directory outside the checkout, and requires it to parse, taint and find the interprocedural flow.

## How do you verify a release before running it?

A download should be verifiable, not trusted. The v0.1.1 release publishes `SHA256SUMS` and a Sigstore attestation:

```bash
gh attestation verify redfall-0.5.0-py3-none-any.whl --repo DevAnimecx/redfall
```

The attestation proves the wheel came from the repository's release workflow and the tagged commit. The checksum proves the file you downloaded is the file that was published. The [release verification page](/docs/release-verification/) explains what each check does and what it cannot prove. There is no claim here that the software is "virus free"; the claim is that the artifact and its build provenance can be checked.

## What does `redfall doctor` tell you?

`redfall doctor` reports exactly which prerequisites the host satisfies and which it does not. `redfall environment` prints the same capability report as JSON, which is useful in CI and in bug reports. The checks are deliberately concrete: a binary exists, a socket is reachable, a credential is present, a target contract is readable.

The important distinction is between *installed* and *runnable*. A host can have the CLI installed and still be unable to execute a scan. The doctor report is how you know which situation you are in before you spend time on a target.

## What does a first scan look like?

On a host with a container runtime, gVisor and a provider key:

```bash
export OPENAI_API_KEY=sk-...
redfall scan range/chainbank --out scan.json
redfall fix <finding-id> --target range/chainbank --out fixes.json
python -m range_runner.run --target range/chainbank \
  --scan scan.json --fixes fixes.json --out range/report.json
```

`redfall fix --out` appends one record per finding: `finding_id`, `verified`, `status`, and the test and PoC outcomes. Re-running it for the same finding replaces that record instead of duplicating it. The [CLI reference](/docs/cli/) covers every command and the common options; `redfall <command> --help` is authoritative for the installed build.

## What can you run without Docker?

The development host used for 0.1.1 has no container runtime, so the repository separates what can be exercised from what cannot.

| Workload | Docker needed? | Database needed? | What it demonstrates |
| --- | --- | --- | --- |
| Python unit and contract tests | No | No | Parsing, taint, route extraction, SARIF, packaging |
| `pythonbank` range replay | No | No | 17/17 PoCs over real HTTP |
| `vulnbank-adaptive` replay | No | Yes | 7/7 adaptive surfaces; 91/91 target tests |
| `chainbank` replay | No | Yes | 6/6 chains reproduce end to end |
| Full `redfall scan` | Yes, gVisor | Yes | The complete execution-gated pipeline |

The ranges boot real applications and real databases. They are not fixtures that return canned JSON. The [range targets page](/docs/ranges/) records the commands and the measured counts.

## How do you set up a development checkout?

The development setup is `make install`, which installs the package and the range runner in editable mode with dev dependencies:

```bash
make install
make check-no-mock
make test
make doctor
```

The database-backed tests need a reachable PostgreSQL. Point them at a throwaway database with `REDFALL_TEST_DATABASE_URL`; without it the tests fall back to the local defaults declared in the tests:

```bash
export REDFALL_TEST_DATABASE_URL=postgresql+psycopg://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/redfall_test
```

The full 0.1.1 suite collects **367 tests**. On the release host, without PostgreSQL or a container runtime, it reported **337 passed, 30 skipped**; the 30 skips are 25 PostgreSQL tests and five gVisor tests. The CI run on the tag commit ([39616295334](https://github.com/DevAnimecx/redfall/actions/runs/39616295334)) reported **362 passed, 5 skipped in 45.49s** against PostgreSQL 17. Skips are reported as skips, not passes. See [the evidence page](/evidence/) for the date and exact command.

## What should you do when the scan cannot start?

Read the error before changing the target. The common failures are prerequisite failures, not vulnerabilities:

- **No container runtime.** Install Docker, then a gVisor runtime, and confirm the runtime is registered.
- **No provider key.** Set the provider credential the model tier expects. The CLI fails rather than returning a synthetic result.
- **No database.** Start PostgreSQL and set `DATABASE_URL`. The scan store needs it to persist the run.
- **Target will not boot.** Check the target's `redfall.target.json` boot contract and its test suite. The sandbox boots the real app, so a broken app is a broken scan.
- **No `runsc`.** A Docker runtime alone is not enough. The isolation boundary is the gVisor runtime, not the container alone.

The [blocked page](/docs/blocked/) documents the smallest real unblock for each prerequisite on the current host.

## Frequently asked questions

### Does the installer need administrator rights?

No. It uses `pipx` or a private virtualenv in the user's home directory. Nothing is installed system-wide and the script does not request elevation.

### Can I install RedFall without Docker?

Yes. The CLI installs and the non-execution stages run. You cannot produce an execution-verified finding without a container runtime and gVisor, and RedFall will not pretend otherwise.

### Where do I report an install problem?

Open an issue in the [RedFall repository](https://github.com/DevAnimecx/redfall/issues) with the operating system, Python version, the install command, and the output of `redfall environment`. Do not paste provider keys or target credentials.
