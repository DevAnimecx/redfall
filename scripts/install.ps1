# Redfall installer for Windows (Windows PowerShell 5.1+ and PowerShell 7+).
#
#   .\scripts\install.ps1
#
# What it does:
#   * finds a Python >= 3.12 (the `py` launcher when present, else python)
#   * installs Redfall into a private virtualenv at %LOCALAPPDATA%\Redfall\venv
#   * adds that venv's Scripts directory to your user PATH (unless -NoPath)
#   * runs `redfall doctor` so the host's real capability report is the last
#     thing you see (unless -NoDoctor)
#
# Never system-wide, never elevated.
#
# Environment:
#   REDFALL_SOURCE     package source to install (default: this checkout when
#                      run from one, else git+https://github.com/DevAnimecx/redfall)
#   REDFALL_HOME       install location for the virtualenv (default %LOCALAPPDATA%\Redfall)
#   REDFALL_PYTHON     interpreter to use (default: the best python found)
#   REDFALL_NO_DOCTOR  set to 1 to skip the final doctor report
#   REDFALL_NO_PATH    set to 1 to leave PATH untouched

[CmdletBinding()]
param(
    [string]$Source = "",
    [switch]$NoDoctor,
    [switch]$NoPath
)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/DevAnimecx/redfall"

# Windows PowerShell 5.1 turns native stderr output into a terminating error
# under $ErrorActionPreference = "Stop". Several calls below (the `py` launcher
# probing for an absent version, pip printing a warning) write to stderr while
# being completely fine, so native calls run relaxed and their exit code is the
# verdict.
function Invoke-Relaxed {
    param([scriptblock]$Action)
    $previousEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Action } finally { $ErrorActionPreference = $previousEAP }
}

if (-not $Source) { $Source = $env:REDFALL_SOURCE }
if (-not $Source) {
    $checkout = Join-Path $PSScriptRoot ".."
    $pyproject = Join-Path $checkout "pyproject.toml"
    if ((Test-Path $pyproject) -and (Select-String -Path $pyproject -Pattern '^name = "redfall"' -Quiet)) {
        $Source = (Resolve-Path $checkout).Path
    } else {
        $Source = "git+$RepoUrl"
    }
}

$PyExe = $null
$PyArgs = @()
foreach ($candidate in @(
        @("py", "-3.13"), @("py", "-3.12"), @("py", "-3"), @("python3"), @("python"))) {
    if (-not (Get-Command $candidate[0] -ErrorAction SilentlyContinue)) { continue }
    $argsList = @()
    if ($candidate.Length -gt 1) { $argsList = @($candidate[1..($candidate.Length - 1)]) }
    Invoke-Relaxed { & $candidate[0] @argsList -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" 2>$null }
    if ($LASTEXITCODE -eq 0) {
        $PyExe = $candidate[0]
        $PyArgs = $argsList
        break
    }
}
if (-not $PyExe) {
    throw "Redfall needs Python 3.12+; install it from https://python.org and run this script again."
}

$RedfallHome = if ($env:REDFALL_HOME) { $env:REDFALL_HOME } else { Join-Path $env:LOCALAPPDATA "Redfall" }
$Venv = Join-Path $RedfallHome "venv"
Write-Host "installing Redfall into a private virtualenv at: $Venv"

Invoke-Relaxed { & $PyExe @PyArgs -m venv $Venv }
if ($LASTEXITCODE -ne 0) { throw "creating the virtualenv failed with exit code $LASTEXITCODE" }

$VenvPy = Join-Path $Venv "Scripts\python.exe"
Invoke-Relaxed { & $VenvPy -m pip install --quiet --upgrade pip }
if ($LASTEXITCODE -ne 0) { throw "upgrading pip failed with exit code $LASTEXITCODE" }

Invoke-Relaxed { & $VenvPy -m pip install --quiet $Source }
if ($LASTEXITCODE -ne 0) { throw "installing Redfall failed with exit code $LASTEXITCODE" }

$version = Invoke-Relaxed { & $VenvPy -c "import importlib.metadata; print(importlib.metadata.version('redfall'))" 2>$null }

$Scripts = Join-Path $Venv "Scripts"
if ($env:REDFALL_NO_PATH -eq "1") { $NoPath = $true }
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $Scripts) {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $Scripts), "User")
        Write-Host "added $Scripts to your user PATH (restart the shell to pick it up)"
    }
}
$env:Path = "$env:Path;$Scripts"

Write-Host ""
Write-Host "Redfall $version installed."
if (-not $NoDoctor -and $env:REDFALL_NO_DOCTOR -ne "1") {
    $RedfallExe = Join-Path $Scripts "redfall.exe"
    Write-Host "running: $RedfallExe doctor"
    Invoke-Relaxed { & $RedfallExe doctor }
    # A missing prerequisite is the host's answer, not an installer failure.
    if ($LASTEXITCODE -ne 0) {
        Write-Host "note: doctor reported missing prerequisites - that report is the point; see BLOCKED.md."
    }
}
