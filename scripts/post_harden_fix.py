#!/usr/bin/env python3
"""Normalize generated source after regex-based hardening transforms.

The hardener intentionally uses regex replacements for large upstream functions.
Python's regex replacement engine interprets backslash escapes, so literal `\n`
inside generated Python string literals can become a physical newline. This step
repairs those two known generated literals and validates the result structurally.
"""
from pathlib import Path

p = Path("core/bruteforce_worker.py")
text = p.read_text(encoding="utf-8")

text = text.replace('uf.write("\n".join(users))', 'uf.write("\\n".join(users))')
text = text.replace('pf.write("\n".join(passwords))', 'pf.write("\\n".join(passwords))')

if 'uf.write("\\n".join(users))' not in text:
    raise SystemExit("post-hardening fix failed: users temp-file newline literal not normalized")
if 'pf.write("\\n".join(passwords))' not in text:
    raise SystemExit("post-hardening fix failed: password temp-file newline literal not normalized")

p.write_text(text, encoding="utf-8")
print("post-hardening normalization: PASS")
