"""A real, tiny agent CLI used to test the driver machinery.

This is not a mock of an agent — it is a real program that behaves like one:
it reads a prompt and writes a reply, and a test points a `CustomAgentDriver`
at it. The driver really spawns it, really captures stdout, and really parses
it. That keeps the agent tests honest under the same no-mock spirit as the rest
of the suite, where a fake agent that was never executed would prove nothing.

Usage:  python fake_agent.py --prompt "<text>"       # or read the prompt on stdin
Reply is chosen from the prompt so a test can ask for text or for JSON.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    prompt = ""
    if "--prompt" in argv:
        prompt = argv[argv.index("--prompt") + 1]
    else:
        prompt = sys.stdin.read()

    if "--version" in argv:
        print("fake-agent 1.0.0")
        return 0

    lowered = prompt.lower()
    if "json" in lowered:
        print(json.dumps({"ok": True, "value": 42}))
        return 0
    print("ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
