"""A real agent-shaped program that answers RedFall's own prompts.

This stands in for Claude Code in the self-test (`test_agent_driven_scan.py`).
It is a real process: RedFall really spawns it, really reads its stdout, and the
engine really parses what it prints. It is not a mock of RedFall and it is not a
`patch` of the model layer — it is the other side of the real subprocess
boundary.

It detects which stage it is being asked for from the prompt the engine sends
and returns the JSON that stage's schema requires. The findings it names are the
ones actually present in `range/vulnbank`; whether they count as real still
depends on the sandbox reproducing them, which this program cannot influence.
"""

from __future__ import annotations

import json
import sys


def _plan() -> dict:
    return {
        "branches": [
            {
                "name": "auth-and-users",
                "type": "http_surface",
                "scope_files": ["src/routes/auth.ts", "src/routes/users.ts"],
                "scope_routes": ["POST /api/login", "GET /api/users/:id"],
                "priority": 1,
                "model_tier": "mid",
                "rationale": "Login and object reads carry the request surface.",
            }
        ]
    }


def _findings() -> dict:
    return {
        "findings": [
            {
                "category": "idor",
                "severity": "high",
                "title": "Missing owner check on user read",
                "description": "The user route reads by id without an owner predicate.",
                "location": {"file": "src/routes/users.ts", "line": 24, "symbol": "getUser"},
                "poc": {
                    "kind": "http",
                    "method": "GET",
                    "path": "/api/users/2",
                    "headers": {"authorization": "Bearer {{user_1_token}}"},
                    "expect": "another user's record is returned",
                },
                "evidence": "route reads req.params.id and queries by id only",
                "remediation": "add an owner predicate to the query",
            }
        ]
    }


def _poc() -> dict:
    return {
        "poc": {
            "kind": "http",
            "method": "GET",
            "path": "/api/users/2",
            "headers": {"authorization": "Bearer {{user_1_token}}"},
            "expect": "another user's record is returned",
        }
    }


def _chains() -> dict:
    return {"chains": []}


def _fix() -> dict:
    return {
        "patch": {
            "file": "src/routes/users.ts",
            "find": "WHERE id = ?",
            "replace": "WHERE id = ? AND owner_id = ?",
        },
        "rationale": "Restore the owner predicate.",
    }


def respond(prompt: str) -> dict:
    lowered = prompt.lower()
    if "planner" in lowered or '"branches"' in lowered and "taint_paths" in lowered:
        return _plan()
    if "analyser" in lowered or "analyzer" in lowered or "categories_in_scope" in lowered:
        return _findings()
    if "proof of concept" in lowered or '"poc"' in lowered:
        return _poc()
    if "chain" in lowered:
        return _chains()
    if "fix" in lowered or "patch" in lowered:
        return _fix()
    # Unknown stage: return the plan shape, which is the most permissive.
    return _plan()


def main(argv: list[str]) -> int:
    prompt = argv[0] if argv else sys.stdin.read()
    if "--version" in argv:
        print("self-agent 0.2.0")
        return 0
    print(json.dumps(respond(prompt)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
