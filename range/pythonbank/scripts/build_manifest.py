#!/usr/bin/env python3
"""Anchor lines for pythonbank, read from the real source.

This table is the single place that decides which line carries each defect.
`write_manifest.py` reads it to build `manifest.yaml`; `tests/test_api.py` and
the repo-level pythonbank test rely on the manifest staying in sync with it.
"""

from __future__ import annotations

import re
from pathlib import Path

BANK_ROOT = Path(__file__).resolve().parents[1]

# (rel_path, regex for the anchor line, symbol)
ANCHORS: dict[str, tuple[str, str, str]] = {
    "VULN-001": ("src/pythonbank/routes/auth.py", r"WHERE username = '", "login"),
    "VULN-002": ("src/pythonbank/routes/auth.py", r'@bp\.post\("/login"\)', "login"),
    "VULN-003": ("src/pythonbank/routes/auth.py", r'"no such user"', "login"),
    "VULN-004": ("src/pythonbank/routes/auth.py", r"password_hash = db\.md5_hex\(password\)", "register"),
    "VULN-005": ("src/pythonbank/tokens.py", r"TOKEN_SECRET = ", "TOKEN_SECRET"),
    "VULN-006": ("src/pythonbank/routes/config.py", r'"token_secret": TOKEN_SECRET', "get_config"),
    "VULN-007": ("src/pythonbank/routes/tools.py", r"subprocess\.run\(cmd, shell=True", "admin_exec"),
    "VULN-008": ("src/pythonbank/routes/serialize.py", r"pickle\.loads\(raw\)", "import_object"),
    "VULN-009": ("src/pythonbank/routes/files.py", r"path = os\.path\.join\(PUBLIC_DIR, name\)", "download"),
    "VULN-010": ("src/pythonbank/routes/files.py", r"file\.save\(target\)", "upload"),
    "VULN-011": ("src/pythonbank/routes/proxy.py", r"response = requests\.get\(url", "proxy_fetch"),
    "VULN-012": ("src/pythonbank/routes/proxy.py", r"response = requests\.get\(url", "proxy_fetch"),
    "VULN-013": ("src/pythonbank/routes/redirect.py", r"return redirect\(target, code=302\)", "open_redirect"),
    "VULN-014": ("src/pythonbank/routes/export.py", r'lines\.append\(f"', "export_csv"),
    "VULN-015": ("src/pythonbank/routes/diagnostics.py", r"traceback\.format_exc\(\)", "debug_echo"),
    "VULN-016": ("src/pythonbank/routes/users.py", r'@bp\.get\("/<int:user_id>"\)', "get_user"),
    "VULN-017": ("src/pythonbank/core/reports.py", r"WHERE department = '", "department_summary"),
}


def anchor_line(rel_path: str, pattern: str) -> int:
    path = BANK_ROOT / rel_path
    with open(path, encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            if re.search(pattern, line):
                return index
    raise SystemExit(f"anchor not found: {rel_path} :: {pattern}")


def main() -> None:
    for vuln_id, (rel_path, pattern, _symbol) in sorted(ANCHORS.items()):
        line = anchor_line(rel_path, pattern)
        print(f"{vuln_id}\t{rel_path}:{line}")


if __name__ == "__main__":
    main()
