"""The installers are contracts too: they must parse on a real shell, stay
unprivileged, and end with the host's real capability report.

The POSIX script is syntax-checked with a real shell when one is available
(Git for Windows' bash counts; the Windows WSL stub without a distribution is
detected and skipped, honestly). The PowerShell script is parsed with the real
PowerShell parser. What cannot be proven on this host — executing the POSIX
script end to end — is left to the CI package matrix, which runs it on Linux
and macOS and runs the PowerShell one on Windows.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
BUILD_RELEASE = ROOT / "scripts" / "build_release.py"

GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")


def _posix_shell() -> str | None:
    """A shell that can actually parse sh, not the WSL stub."""
    candidates = [shutil.which("bash"), str(GIT_BASH) if GIT_BASH.is_file() else None]
    for candidate in candidates:
        if not candidate:
            continue
        probe = subprocess.run(
            [candidate, "-c", "echo ok"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if probe.returncode == 0 and "ok" in probe.stdout:
            return candidate
    return None


def test_install_sh_parses_with_a_real_posix_shell():
    shell = _posix_shell()
    if shell is None:
        pytest.skip("no working POSIX shell on this host")
    proc = subprocess.run([shell, "-n", str(INSTALL_SH)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_install_ps1_parses_with_the_powershell_parser():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell on this host")
    command = (
        "$errors = $null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{INSTALL_PS1}', [ref]$null, [ref]$errors) | Out-Null; "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
    )
    proc = subprocess.run([shell, "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_installer_scripts_stay_ascii_only():
    # Windows PowerShell 5.1 reads .ps1 files as ANSI: a stray em dash breaks
    # string literals (this actually happened once). ASCII-only is the fix.
    for script in (INSTALL_SH, INSTALL_PS1):
        text = script.read_text(encoding="utf-8")
        offenders = [line for line in text.splitlines() if any(ord(char) > 127 for char in line)]
        assert not offenders, f"{script.name} must stay ASCII-only: {offenders!r}"


def test_installers_stay_unprivileged_and_reach_for_real_python():
    sh_text = INSTALL_SH.read_text(encoding="utf-8")
    ps1_text = INSTALL_PS1.read_text(encoding="utf-8")
    assert "sudo" not in sh_text, "install.sh must never ask for privileges"
    assert "RunAs" not in ps1_text, "install.ps1 must never ask for elevation"
    for text in (sh_text, ps1_text):
        assert "3, 12" in text, "both installers must gate on Python 3.12+"
        assert "github.com/DevAnimecx/redfall" in text, "network installs must point at the canonical repository"
        assert "doctor" in text, "the installer must end with the real capability report"


def test_installer_doctor_can_be_skipped_for_headless_use():
    assert "REDFALL_NO_DOCTOR" in INSTALL_SH.read_text(encoding="utf-8")
    assert "REDFALL_NO_DOCTOR" in INSTALL_PS1.read_text(encoding="utf-8")


def test_build_release_script_has_a_working_cli():
    proc = subprocess.run(
        [sys.executable, str(BUILD_RELEASE), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SHA256SUMS" in proc.stdout or "release" in proc.stdout
