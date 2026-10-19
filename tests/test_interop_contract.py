"""Executable HTTP and A2A contracts run against a real gateway subprocess.

These are the certification tests: a passing result is the measured basis for
`redfall interop certify --protocol http|a2a`. Nothing here is simulated; the
gateway binds a socket, the contracts speak HTTP/SSE to it, and it executes real
tool calls against a temporary database and a temporary repository.
"""

from __future__ import annotations

from redfall.interop.contract import run_a2a_contract, run_http_contract


def test_http_contract_certifies_a_real_gateway():
    report = run_http_contract(timeout=60)
    failures = [check.to_wire() for check in report.checks if not check.passed]
    assert report.certified, {"error": report.error, "failed": failures}
    assert report.protocol == "openapi"
    assert report.transport == "http"
    assert report.tool_count >= 44
    assert report.error == ""
    names = {check.name for check in report.checks}
    assert {
        "health",
        "openapi",
        "unauthenticated-denial",
        "tools-list",
        "tool-call",
        "graph-index",
        "scope-denial",
        "unknown-tool",
        "quota",
        "audit",
    } <= names


def test_a2a_contract_certifies_a_real_gateway():
    report = run_a2a_contract(timeout=60)
    failures = [check.to_wire() for check in report.checks if not check.passed]
    assert report.certified, {"error": report.error, "failed": failures}
    assert report.protocol == "a2a"
    assert report.transport == "http"
    assert report.protocol_version == "1.0"
    assert report.tool_count >= 44
    assert report.error == ""
    names = {check.name for check in report.checks}
    assert {
        "agent-card",
        "unauthenticated-denial",
        "send-message",
        "get-task",
        "list-tasks",
        "artifact-url",
        "cancel-terminal",
        "unknown-method",
        "push-unsupported",
        "scope-denial",
        "streaming",
    } <= names
