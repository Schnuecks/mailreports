# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Check translations: lists texts that are missing or unused in mailreports/locales/*.json.

    python tools/i18n_extract.py            # report, exit code 1 if something is missing
    python tools/i18n_extract.py --keys     # print all keys as JSON (to start a new language)
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from jinja2 import Environment

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "mailreports"
FUNCS = {"_", "gettext", "ngettext", "N_"}


def from_python(path: Path) -> set[str]:
    keys = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in FUNCS:
                count = 2 if name == "ngettext" else 1
                for arg in node.args[:count]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        keys.add(arg.value)
    return keys


def from_templates() -> set[str]:
    env = Environment(extensions=["jinja2.ext.i18n"])
    keys = set()
    for path in (PKG / "templates").glob("*.html"):
        for _lineno, _func, message in env.extract_translations(path.read_text(encoding="utf-8"),
                                                               gettext_functions=FUNCS):
            for msg in (message if isinstance(message, tuple) else (message,)):
                if isinstance(msg, str):
                    keys.add(msg)
    return keys


def all_keys() -> set[str]:
    keys = from_templates()
    for path in PKG.glob("*.py"):
        keys |= from_python(path)
    return keys


def main() -> int:
    keys = all_keys()
    if "--keys" in sys.argv:
        print(json.dumps({k: "" for k in sorted(keys)}, ensure_ascii=False, indent=1))
        return 0
    failed = False
    for path in sorted((PKG / "locales").glob("*.json")):
        catalog = json.loads(path.read_text(encoding="utf-8"))
        missing = sorted(k for k in keys if not catalog.get(k))
        unused = sorted(k for k in catalog if k not in keys)
        print(f"{path.name}: {len(missing)} missing, {len(unused)} unused")
        for k in missing:
            print(f"  missing: {k}")
        for k in unused:
            print(f"  unused:  {k}")
        failed |= bool(missing)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
