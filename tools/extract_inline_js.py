#!/usr/bin/env python3
"""Pull the inline <script> bodies out of an HTML file, for syntax checking.

The dashboard is served as static files with no build step, so a syntax error in
its inline script reaches a client's browser unmodified. `node --check` can only
read a .js file, hence this.

Scripts with a src attribute are skipped (nothing to check locally) and so are
non-JavaScript script types, which are data rather than code.
"""

from __future__ import annotations

import re
import sys

SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
SRC = re.compile(r"\bsrc\s*=", re.IGNORECASE)
TYPE = re.compile(r'\btype\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

JS_TYPES = {"", "text/javascript", "application/javascript", "module"}


def extract(html: str) -> str:
    blocks = []
    for attrs, body in SCRIPT.findall(html):
        if SRC.search(attrs):
            continue
        declared = TYPE.search(attrs)
        if declared and declared.group(1).lower() not in JS_TYPES:
            continue
        blocks.append(body)
    return "\n;\n".join(blocks)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <file.html>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8", errors="replace") as handle:
        sys.stdout.write(extract(handle.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
