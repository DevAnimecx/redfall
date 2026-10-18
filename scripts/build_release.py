"""Build the release artifacts (wheel + sdist) and prove what is inside them.

    python scripts/build_release.py [--out release]

Artifacts land in release/ (gitignored), together with SHA256SUMS. The script
then inspects both archives the way the installed package will be used: the
sandbox harness, the agent prompts and the sandbox Dockerfile must all be in
the wheel and in the sdist. The release workflow (`.github/workflows/release.yml`)
builds and attests the same layout on the tag.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RUNTIME_FILES = [
    "redfall/validation/harness.mjs",
    "redfall/validation/harness_internals.mjs",
    "redfall/agent/prompts/_common.md",
    "redfall/agent/prompts/planner.md",
    "redfall/agent/prompts/analyzer.md",
    "redfall/agent/prompts/poc_generator.md",
    "redfall/agent/prompts/fixer.md",
    "redfall/agent/prompts/chain_analyst.md",
    "redfall/sandbox/images/redfall-sandbox/Dockerfile",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="release", help="output directory (default: release)")
    args = parser.parse_args()

    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    for old in list(out.glob("redfall-*")) + [out / "SHA256SUMS"]:
        old.unlink()

    built = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(out), "--no-isolation"],
        cwd=ROOT,
    )
    if built.returncode != 0:
        print("error: `python -m build` failed", file=sys.stderr)
        return 1

    artifacts = sorted(p for p in out.iterdir() if p.name.startswith("redfall-"))
    wheel = next((p for p in artifacts if p.suffix == ".whl"), None)
    sdist = next((p for p in artifacts if p.name.endswith(".tar.gz")), None)
    if wheel is None or sdist is None:
        print(f"error: expected a wheel and an sdist in {out}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()

    missing = [name for name in RUNTIME_FILES if name not in wheel_names]
    missing += [name for name in RUNTIME_FILES if not any(member.endswith(name) for member in sdist_names)]
    if missing:
        print("error: runtime files missing from the artifacts:", file=sys.stderr)
        for name in sorted(set(missing)):
            print(f"  {name}", file=sys.stderr)
        return 1

    lines = []
    for artifact in artifacts:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        lines.append(f"{digest}  {artifact.name}")
        print(f"built {artifact.name} ({artifact.stat().st_size:,} bytes)")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"checksums written to {out / 'SHA256SUMS'}")
    print("both archives carry the sandbox harness, the prompts and the Dockerfile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
