#!/usr/bin/env python3
"""Sync forked AyuGram submodules with exact upstream desktop-app commits for tdesktop v7.4.3."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

TARGETS = [
    (
        ROOT / "Telegram" / "lib_ui",
        "https://github.com/desktop-app/lib_ui.git",
        "caaa3f1eb20bab7ef838c6aea35db2397e8f3f07",
    ),
    (
        ROOT / "Telegram" / "codegen",
        "https://github.com/desktop-app/codegen.git",
        "dbd1d53137cd581cfdbeebe93bcaf54abf55ec74",
    ),
]


def run(cwd: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    for path, upstream_url, commit in TARGETS:
        if not (path / ".git").exists():
            print(f"[skip] {path} is not initialized", flush=True)
            continue
        already = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=str(path),
        )
        if already.returncode == 0:
            print(f"[ok] {path.name} already contains {commit[:10]}", flush=True)
            continue
        has_commit = subprocess.run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=str(path),
        )
        if has_commit.returncode != 0:
            print(f"[fetch] {path.name} <- {upstream_url} ({commit[:10]})", flush=True)
            run(path, "fetch", "--no-tags", upstream_url, commit)
        print(f"[merge] {path.name} + {commit[:10]}", flush=True)
        run(
            path,
            "-c",
            "user.name=SleepyGram Builder",
            "-c",
            "user.email=builder@sleepygram.local",
            "merge",
            "--no-edit",
            commit,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
