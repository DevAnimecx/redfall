# Security policy

## The `range/` targets are deliberately vulnerable

`range/vulnbank`, `range/vulnbank-adaptive`, `range/chainbank` and
`range/pythonbank` are applications built to contain known vulnerabilities so
the analyser and the PoC replays have ground truth. They exist to be exploited
by the test suite.

- Never deploy a range target anywhere reachable. The local scripts bind
  loopback only; keep it that way.
- Never point Redfall at systems you do not own or have written permission to
  test. Redfall generates and executes exploits by design.

## Reporting a vulnerability in Redfall itself

Please use GitHub's private vulnerability reporting: the **Security** tab →
**Report a vulnerability**. Do not open a public issue for anything
exploitable.

Include what you have: affected version (or commit), a minimal reproduction,
the impact you believe it has, and whether a range target is needed to trigger
it. Reports about the *unintended* execution of target code outside the
sandbox, or about the harness escaping its container, are especially welcome.

What to expect: acknowledgement within a few days, an honest triage (including
"not a vulnerability" with reasoning when that is the answer), credit in the
release notes when you want it.

## Supported versions

0.1.x receives security fixes. There is no back-porting policy before 1.0;
fixes land on `main` and ship in the next release.

## Supply chain

What is true about the artifacts, and how to check it:

- The `redfall` package is pure Python: the wheel is `py3-none-any` and ships
  no compiled binaries, no post-install hooks and no vendored code.
- Runtime dependencies are declared in `pyproject.toml` with lower bounds and
  audited weekly by `pip-audit` (`.github/workflows/security.yml`).
- Release artifacts (wheel, sdist) are built by GitHub Actions from the tagged
  source and carry Sigstore build attestations. Verify a download with:

  ```bash
  gh attestation verify redfall-0.4.0-py3-none-any.whl --repo DevAnimecx/redfall
  ```

- Every release publishes `SHA256SUMS` next to the artifacts. If a hash does
  not match, do not install the file.
- You can always rebuild from source instead of trusting a download:
  `python -m build` in a checkout produces the same wheel layout, and
  `scripts/verify_wheel.py` proves an installed wheel behaves.

## What "secure" means here

Redfall executes target code inside a sandbox (Docker + gVisor) on purpose.
The threat Redfall manages is *the target's*, not the analyst's: run scans only
against code you are allowed to execute, on a host you control. The package
itself is small, readable, and every line that runs is Python source you can
audit — `scripts/check_no_mock.py`, `scripts/check_clean_tree.py` and the
release attestations exist to keep that claim checkable rather than aspirational.
