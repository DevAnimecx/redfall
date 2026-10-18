"""pythonbank: the Python ground truth, held to three contracts.

1. The ingestion engine sees the taint-visible vulnerabilities at the lines the
   manifest claims (and the manifest's anchors really point at live source).
2. Every PoC in the manifest reproduces over real HTTP against a booted target.
3. The engine's own findings survive `range_runner`'s matcher against the
   manifest — the same bridge a real scan is scored through.

The replay boots the target on 127.0.0.1:4003, so this module needs that port
free; the bank's own suite covers the same weaknesses in-process and runs in
CI without a socket.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

from redfall.ingestion.ingest import ingest
from range_runner.ground_truth import load_manifest
from range_runner.match import match

BANK_ROOT = Path(__file__).resolve().parents[1] / "range" / "pythonbank"
MANIFEST_PATH = BANK_ROOT / "manifest.yaml"

# vuln id -> (sink kind, path relative to range/pythonbank/src)
TAINT_VISIBLE = {
    "VULN-001": ("db", "pythonbank/routes/auth.py"),
    "VULN-007": ("exec", "pythonbank/routes/tools.py"),
    "VULN-008": ("exec", "pythonbank/routes/serialize.py"),
    "VULN-009": ("fs", "pythonbank/routes/files.py"),
    "VULN-011": ("fetch", "pythonbank/routes/proxy.py"),
    "VULN-012": ("fetch", "pythonbank/routes/proxy.py"),
    # The sink is in core.reports; only the interprocedural pass links it to
    # the request parameter the route passes (VULN-017).
    "VULN-017": ("db", "pythonbank/core/reports.py"),
}

# Sink labels the engine emits for pythonbank, mapped to the category the seeded
# entry declares. Assigning categories at scan time is the agent's job; this
# mapping exists only so the engine's real output can reach the real matcher.
SINK_LABEL_CATEGORY = {
    "conn.execute": "sqli",
    "subprocess.run": "cmd_injection",
    "pickle.loads": "unsafe_deserialization",
    "os.path.join": "path_traversal",
    "open": "path_traversal",
    "requests.get": "ssrf",
}

SYMBOLS_THAT_ARE_NOT_FUNCTIONS = {"TOKEN_SECRET"}


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def _build_manifest_module():
    spec = importlib.util.spec_from_file_location(
        "pythonbank_build_manifest", BANK_ROOT / "scripts" / "build_manifest.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_is_derived_and_current():
    result = subprocess.run(
        [sys.executable, "scripts/write_manifest.py", "--check"],
        cwd=BANK_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is current" in result.stdout


def test_manifest_lines_point_at_live_source():
    build_manifest = _build_manifest_module()
    manifest = _manifest()
    assert len(manifest["vulns"]) == len(build_manifest.ANCHORS)
    for entry in manifest["vulns"]:
        rel_path, pattern, symbol = build_manifest.ANCHORS[entry["id"]]
        location = entry["location"]
        assert location["file"] == rel_path
        assert location["symbol"] == symbol
        assert location["lines"] == [build_manifest.anchor_line(rel_path, pattern)]


def test_engine_sees_the_manifest_symbols_and_the_taint():
    result = ingest("test-pythonbank-parity", BANK_ROOT / "src")
    assert result.parse_errors == []

    by_path = {file.path: file for file in result.files}
    manifest = _manifest()
    for entry in manifest["vulns"]:
        rel = entry["location"]["file"].removeprefix("src/")
        assert rel in by_path, f"{entry['id']}: {rel} was not ingested"
        if entry["location"]["symbol"] not in SYMBOLS_THAT_ARE_NOT_FUNCTIONS:
            functions = {fn.name for fn in by_path[rel].symbols.functions}
            assert entry["location"]["symbol"] in functions, (
                f"{entry['id']}: {entry['location']['symbol']} not found in {rel}"
            )

    taints_by_path: dict[str, list] = {}
    for rel, taint in result.taint_paths:
        taints_by_path.setdefault(rel, []).append(taint)
    locations = {entry["id"]: entry["location"] for entry in manifest["vulns"]}
    for vuln_id, (kind, rel) in TAINT_VISIBLE.items():
        anchor = locations[vuln_id]["lines"][0]
        hits = [
            taint
            for taint in taints_by_path.get(rel, [])
            if taint.sink_kind == kind and abs(taint.line - anchor) <= 5
        ]
        assert hits, f"{vuln_id}: no {kind} taint within +-5 of {rel}:{anchor}"


def test_engine_findings_survive_the_gate_matcher():
    """The engine's real taint output, shaped like scanner findings and fed
    through range_runner's matcher, lands exactly on the manifest entries."""
    result = ingest("test-pythonbank-matcher", BANK_ROOT / "src")
    assert result.parse_errors == []

    findings = []
    for rel, taint in result.taint_paths:
        category = SINK_LABEL_CATEGORY.get(taint.sink)
        if category is None:
            # A sink label without an unambiguous category is the agent's call
            # at scan time, not something this test should guess.
            continue
        findings.append(
            {
                "id": f"engine-{rel}:{taint.line}:{taint.sink}",
                "category": category,
                "location": {
                    "file": f"src/{rel}",
                    "line": taint.line,
                    "symbol": taint.symbol,
                },
            }
        )
    assert findings, "the engine produced no mappable taint on pythonbank"

    manifest = load_manifest(MANIFEST_PATH)
    matched = match(findings, manifest).matched_vuln_ids
    assert matched == {"VULN-001", "VULN-007", "VULN-008", "VULN-009", "VULN-011", "VULN-017"}


def test_target_own_suite_passes():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"],
        cwd=BANK_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert " failed" not in result.stdout


def test_replay_reproduces_every_poc():
    result = subprocess.run(
        [sys.executable, "scripts/replay_poc.py", "--all"],
        cwd=BANK_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    total = len(_manifest()["vulns"])
    assert f"reproduced: {total} / {total}" in result.stdout
