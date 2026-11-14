#!/usr/bin/env python3
"""Forward build output and annotate the first compiler diagnostics on failure."""

from collections import deque
import os
import re
import subprocess
import sys


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DIAGNOSTIC = re.compile(
    r"(?:^|:\s*)(?:fatal error|error)(?:\s+[A-Z]+\d+)?:\s*\S"
    r"|^CMake Error\b|^ninja: error:|^ld(?:\.lld)?:\s*error:"
    r"|^Undefined symbols for architecture\b|No space left on device",
    re.IGNORECASE,
)


def annotate(message):
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error::{escaped}", flush=True)


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        sys.exit("Usage: build_diagnostics.py -- COMMAND [ARGS...]")
    sensitive = sorted({
        value for key, value in os.environ.items()
        if len(value) >= 6 and any(part in key.upper() for part in (
            "TOKEN", "SECRET", "PASSWORD", "API_HASH", "API_KEY", "CREDENTIAL",
        ))
    }, key=len, reverse=True)
    errors = []
    context = deque(maxlen=2)
    with subprocess.Popen(
        sys.argv[2:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace",
    ) as process:
        for raw in process.stdout:
            line = ANSI.sub("", raw.rstrip("\r\n"))
            for value in sensitive:
                line = line.replace(value, "***")
            # Prevent child output from being interpreted as a workflow command.
            if line.lstrip().startswith(("::", "##[")):
                print(f"[build] {line}", flush=True)
            else:
                print(line, flush=True)
            if line.startswith("CMake Error") or DIAGNOSTIC.search(line):
                if line not in errors and len(errors) < 8:
                    errors.append(line)
            elif errors and len(errors) == 1 and len(context) < 2 and line.strip():
                # CMake and Clang sometimes put the explanation on the next line.
                if errors[0].startswith(("CMake Error", "Undefined symbols")) and line[:1].isspace():
                    context.append(line.strip())
        code = process.wait()
    if code:
        for index, error in enumerate(errors):
            detail = " ".join((error, *context)) if index == 0 else error
            annotate(detail[:1200])
        if not errors:
            annotate(f"Build command exited with code {code} without a recognized compiler diagnostic.")
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
