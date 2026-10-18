"""Filesystem locations the target uses, resolved from this file's position."""

from __future__ import annotations

from pathlib import Path

BANK_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DIR = BANK_ROOT / "public"
PRIVATE_DIR = BANK_ROOT / "private"
