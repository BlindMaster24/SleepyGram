#!/usr/bin/env python3
"""Forward build output and annotate diagnostics observed before a build stops."""

import os
import re
import subprocess
import sys
from pathlib import Path


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
COMPILER_ERROR = re.compile(
    r"(?:^|:\s*)(?:fatal error|error)(?:\s+[A-Z]*\d+)?:\s*\S"
    r"|(?:^|:\s*)syntax error(?:,\s*|\s+)\S",
    re.IGNORECASE,
)
BUILD_ERROR = re.compile(
    r"^CMake Error\b|^ld(?:\.lld)?:\s*error:"
    r"|^Undefined symbols for architecture\b",
    re.IGNORECASE,
)
SUMMARY_ERROR = re.compile(
    r"^ninja: error:|No space left on device",
    re.IGNORECASE,
)
DIAGNOSTIC = re.compile(
    rf"(?:{COMPILER_ERROR.pattern})|(?:{BUILD_ERROR.pattern})|(?:{SUMMARY_ERROR.pattern})",
    re.IGNORECASE,
)


def diagnostic_priority(line):
    if not DIAGNOSTIC.search(line):
        return None
    if SUMMARY_ERROR.search(line):
        return 1
    if COMPILER_ERROR.search(line) or BUILD_ERROR.search(line):
        return 0
    return None


def prioritized_diagnostics(candidates, limit=8):
    unique = {}
    for priority, order, line in candidates:
        unique.setdefault(line, (priority, order, line))
    selected = sorted(unique.values())[:limit]
    return [line for _, _, line in selected]


def annotate(message):
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error::{escaped}", flush=True)


def main():
    args = sys.argv[1:]
    log_file = None
    if args[:1] == ["--log-file"]:
        if len(args) < 4:
            sys.exit("Usage: build_diagnostics.py [--log-file PATH] -- COMMAND [ARGS...]")
        log_file = Path(args[1])
        args = args[2:]
    if len(args) < 2 or args[0] != "--":
        sys.exit("Usage: build_diagnostics.py [--log-file PATH] -- COMMAND [ARGS...]")
    sensitive = sorted({
        value for key, value in os.environ.items()
        if len(value) >= 4 and any(part in key.upper() for part in (
            "TOKEN", "SECRET", "PASSWORD", "API_ID", "API_HASH", "API_KEY", "CREDENTIAL",
        ))
    }, key=len, reverse=True)
    candidates = []
    line_number = 0
    context_owner = None
    contexts = {}
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
    log = log_file.open("w", encoding="utf-8") if log_file else None
    try:
        with subprocess.Popen(
            args[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace",
        ) as process:
            for raw in process.stdout:
                line_number += 1
                line = ANSI.sub("", raw.rstrip("\r\n"))
                for value in sensitive:
                    line = line.replace(value, "***")
                if log:
                    log.write(line + "\n")
                    log.flush()
                # Prevent child output from being interpreted as a workflow command.
                if line.lstrip().startswith(("::", "##[")):
                    print(f"[build] {line}", flush=True)
                else:
                    print(line, flush=True)
                priority = diagnostic_priority(line)
                if priority is not None:
                    candidates.append((priority, line_number, line))
                if line.startswith(("CMake Error", "Undefined symbols")):
                    context_owner = line
                    contexts.setdefault(line, [])
                elif context_owner and len(contexts[context_owner]) < 2 and line.strip():
                    # CMake and Clang sometimes put the explanation on the next line.
                    if line[:1].isspace():
                        contexts[context_owner].append(line.strip())
                    else:
                        context_owner = None
            code = process.wait()
    finally:
        if log:
            log.close()
    errors = prioritized_diagnostics(candidates)
    if code:
        for index, error in enumerate(errors):
            context = contexts.get(error, []) if index == 0 else []
            detail = " ".join((error, *context))
            annotate(detail[:1200])
        if not errors:
            annotate(f"Build command exited with code {code} without a recognized compiler diagnostic.")
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
