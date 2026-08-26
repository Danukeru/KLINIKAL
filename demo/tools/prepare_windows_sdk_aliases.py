#!/usr/bin/env python3
"""Create case-compatible hard-link aliases inside an imported Windows SDK."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


INCLUDE = re.compile(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]', re.MULTILINE)


def make_link(source: Path, alias: Path) -> bool:
    if alias == source or alias.exists() or alias.is_symlink():
        return False
    os.link(source, alias)
    return True


def add_lowercase_aliases(root: Path) -> tuple[int, int]:
    created = skipped = 0
    for path in [item for item in root.rglob("*") if item.is_file()]:
        if make_link(path, path.with_name(path.name.lower())):
            created += 1
        else:
            skipped += 1
    return created, skipped


def add_requested_header_aliases(roots: list[Path]) -> int:
    files = [path for root in roots for path in root.rglob("*") if path.is_file()]
    by_directory: dict[Path, dict[str, Path]] = {}
    for path in files:
        by_directory.setdefault(path.parent, {})[path.name.casefold()] = path

    created = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for requested in INCLUDE.findall(text):
            if "/" in requested or "\\" in requested:
                continue
            source = by_directory.get(path.parent, {}).get(requested.casefold())
            if source is not None and make_link(source, path.parent / requested):
                created += 1
            for root in roots:
                source = by_directory.get(root, {}).get(requested.casefold())
                if source is not None and make_link(source, root / requested):
                    created += 1
    return created


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--aliases-only", action="store_true")
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args()
    missing = [str(root) for root in args.roots if not root.is_dir()]
    if missing:
        raise SystemExit("missing Windows SDK root(s): " + ", ".join(missing))

    lowercase = existing = 0
    for root in args.roots:
        created, skipped = add_lowercase_aliases(root)
        lowercase += created
        existing += skipped
    requested = 0 if args.aliases_only else add_requested_header_aliases(args.roots)
    print("Windows SDK aliases: "
          f"lowercase={lowercase} requested={requested} existing={existing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
