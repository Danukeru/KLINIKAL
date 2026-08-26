#!/usr/bin/env python3
"""Reject project paths that collide on a case-insensitive filesystem."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path


EXCLUDED_TOP_LEVEL = {".git", "build", "build-windows-clang22"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()
    collisions: dict[str, list[str]] = defaultdict(list)

    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
            continue
        collisions[str(relative).casefold()].append(str(relative))

    duplicates = [paths for paths in collisions.values() if len(paths) > 1]
    if duplicates:
        for paths in duplicates:
            print("case-colliding paths: " + ", ".join(sorted(paths)))
        return 1
    print("case audit passed: project paths are unique under Unicode casefold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
