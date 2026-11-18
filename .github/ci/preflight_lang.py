#!/usr/bin/env python3
"""Check plural forms and prefixes supported by codegen_lang subsets."""

import argparse
import re
from pathlib import Path


KEY_VALUE = re.compile(
    r'^\s*"(?P<key>[^"\\]*(?:\\.[^"\\]*)*)"\s*=\s*'
    r'"(?P<value>[^"\\]*(?:\\.[^"\\]*)*)"'
)
PLURAL_TAGS = {"zero", "one", "two", "few", "many", "other"}
SUBSET_PREFIXES = ("lng_", "ayu_")


def subset_key_errors(lines):
    errors = []
    for number, line in enumerate(lines, 1):
        match = KEY_VALUE.match(line)
        if match and not match["key"].startswith(SUBSET_PREFIXES):
            errors.append((number, match["key"], "use lng_ or ayu_ for generated language subsets"))
    return errors


def plural_key_errors(lines):
    groups = {}
    errors = []
    for number, line in enumerate(lines, 1):
        match = KEY_VALUE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value")
        if "#" not in key:
            if "{count}" in value:
                errors.append((
                    number,
                    key,
                    "untagged {count} placeholder requires plural forms",
                ))
            continue
        base, tag = key.rsplit("#", 1)
        if tag not in PLURAL_TAGS:
            continue
        variants = groups.setdefault(base, {"tags": set(), "line": number})
        variants["tags"].add(tag)
    for base, value in groups.items():
        if "other" not in value["tags"]:
            errors.append((
                value["line"],
                base,
                f"plural variants #{', #'.join(sorted(value['tags']))} "
                "are missing #other",
            ))
    return errors


def check_file(path):
    path = Path(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        print(f"::error file={path}::{error}")
        return 2
    failures = plural_key_errors(lines)
    for number, key, reason in failures:
        print(
            f"::error file={path},line={number}::plural key '{key}': "
            f"{reason} (codegen_lang error 806)"
        )
    subset_failures = subset_key_errors(lines)
    for number, key, reason in subset_failures:
        print(f"::error file={path},line={number}::language key '{key}': {reason}")
    if failures or subset_failures:
        return 1
    print(f"Language key preflight passed: {path}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("strings_file", type=Path)
    args = parser.parse_args()
    return check_file(args.strings_file)


if __name__ == "__main__":
    raise SystemExit(main())
