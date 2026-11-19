#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from build_artifact import MACOS_INSTALLER, PLATFORMS
from update_package import ED25519_PUBLIC_PREFIX, MAX_DOWNLOAD, TAG, asset_name, digest_stream, stable_version


def stable_key_id(keys: Path, pem: Path) -> str:
    manifest = json.loads((keys / "manifest.min.json").read_bytes())
    groups = manifest["channels"]["stable"]
    if len(groups) != 1 or not groups[0]:
        raise ValueError("The SleepyGram signing job requires one stable key group.")
    result = subprocess.run([
        "openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER", "-passin", "pass:",
    ], capture_output=True, check=True)
    public = result.stdout
    prefix = ED25519_PUBLIC_PREFIX
    if len(public) != len(prefix) + 32 or not public.startswith(prefix):
        raise ValueError("Expected a private Ed25519 update signing key.")
    x = base64.urlsafe_b64encode(public[len(prefix):]).rstrip(b"=").decode("ascii")
    for key in manifest["keys"]:
        key_id = key["id"]
        expires = key.get("expires", 0)
        if (key_id in groups[0] and key_id not in manifest.get("revoked", [])
                and (not expires or expires > time.time()) and key["alg"] == "Ed25519"
                and key["x"].rstrip("=") == x and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id)):
            return key_id
    raise ValueError("The signing key is missing, expired or revoked in the stable manifest.")


def sign(args: argparse.Namespace) -> None:
    secret = os.environ.pop("SLEEPYGRAM_UPDATE_STABLE_KEY_PEM", "")
    if not secret.strip():
        raise ValueError("SLEEPYGRAM_UPDATE_STABLE_KEY_PEM is missing from the release environment.")
    with tempfile.TemporaryDirectory() as temp_dir:
        pem = Path(temp_dir) / "stable-key.pem"
        descriptor = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as file:
            file.write(secret.strip() + "\n")
        key_id = stable_key_id(args.keys, pem)
        for platform in PLATFORMS:
            directory = args.directory / f"package-{platform}"
            signed = directory / asset_name(platform)
            if signed.exists():
                raise ValueError(f"Refusing to overwrite {signed.name}.")
            subprocess.run([
                args.packer.resolve(strict=True), "-channel", "stable", "-keys-loc", str(args.keys),
                "-unsigned", str(signed) + ".unsigned", "-local-key", str(pem), "-local-key-id", key_id,
            ], check=True)
            if not 0 < signed.stat().st_size <= MAX_DOWNLOAD:
                raise ValueError(f"{signed.name} exceeds the updater's download limit.")


def gh_api(repo: str, endpoint: str, *options: str):
    command = ["gh", "api", f"repos/{repo}/{endpoint}", *options]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else None


def list_release_items(repo: str, endpoint: str) -> list[dict]:
    pages = gh_api(repo, endpoint, "--paginate", "--slurp")
    return [item for page in pages for item in page]


def existing_tag(repo: str, tag: str) -> str | None:
    refs = gh_api(repo, f"git/matching-refs/tags/{tag}")
    for ref in refs:
        if ref["ref"] != f"refs/tags/{tag}":
            continue
        target = ref["object"]
        for _ in range(16):
            if target["type"] == "commit":
                return target["sha"]
            if target["type"] != "tag":
                break
            target = gh_api(repo, f"git/tags/{target['sha']}")["object"]
        raise ValueError(f"Could not resolve {tag} to a Git commit.")
    return None


def check_release_version(releases: list[dict], tag: str) -> None:
    current = tuple(map(int, TAG.fullmatch(tag).groups()))
    for release in releases:
        existing = release["tag_name"]
        if existing == tag:
            raise ValueError(f"Release {tag} already exists.")
        match = TAG.fullmatch(existing)
        if (match and not release["draft"] and not release["prerelease"]
                and tuple(map(int, match.groups())) >= current):
            raise ValueError(f"The new stable tag must be newer than {existing}.")


def release_assets(directory: Path) -> dict[str, Path]:
    assets = {}
    for platform, (archive, _) in PLATFORMS.items():
        names = [archive, asset_name(platform)]
        if platform == "macos-arm64":
            names.append(MACOS_INSTALLER)
        for name in names:
            path = directory / f"package-{platform}" / name
            if not path.is_file() or not path.stat().st_size:
                raise ValueError(f"Missing release asset: {name}")
            assets[name] = path
    return assets


def check_uploaded_assets(uploaded: list[dict], assets: dict[str, Path]) -> None:
    if len(uploaded) != len(assets) or {item["name"] for item in uploaded} != set(assets):
        raise ValueError("Draft release has a different set of assets.")
    for item in uploaded:
        asset = assets[item["name"]]
        size = asset.stat().st_size
        with asset.open("rb") as stream:
            digest = "sha256:" + digest_stream(stream, size).hex()
        if item["state"] != "uploaded" or item["size"] != size or item.get("digest") != digest:
            raise ValueError(f"GitHub did not confirm the exact uploaded asset: {asset.name}")


def publish(args: argparse.Namespace) -> None:
    tag, _ = stable_version(args.repo_root)
    sha = os.environ["GITHUB_SHA"]
    repo = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[a-f0-9]{40}", sha) or repo != "slpkbt/SleepyGram":
        raise ValueError("Unexpected repository or release source SHA.")
    assets = release_assets(args.directory)
    check_release_version(list_release_items(repo, "releases"), tag)
    commit = existing_tag(repo, tag)
    if commit is not None and commit != sha:
        raise ValueError(f"Tag {tag} points at a different commit.")
    notes = args.repo_root / "docs" / "releases" / f"{tag}.md"
    body = notes.read_text(encoding="utf-8").strip() if notes.is_file() else ""
    run_id = os.environ["GITHUB_RUN_ID"]
    if not run_id.isdecimal():
        raise ValueError("Invalid release workflow run ID.")
    build = f"[`{sha[:10]}` · GitHub Actions](https://github.com/{repo}/actions/runs/{run_id})"
    body = f"{body}\n\n{build}" if body else build
    api_id = gh_api(repo, "releases", "--method", "POST", "-f", f"tag_name={tag}",
                    "-f", f"target_commitish={sha}", "-F", "draft=true", "-F", "prerelease=false",
                    "-f", f"name=SleepyGram {tag}", "-f", f"body={body}")["id"]
    print(f"Created draft release {tag} (ID {api_id}).", flush=True)
    subprocess.run(["gh", "release", "upload", tag, "--repo", repo, *assets.values()], check=True)
    check_uploaded_assets(list_release_items(repo, f"releases/{api_id}/assets"), assets)
    check_release_version([item for item in list_release_items(repo, "releases") if item["id"] != api_id], tag)
    commit = existing_tag(repo, tag)
    if commit is None:
        gh_api(repo, "git/refs", "--method", "POST", "-f", f"ref=refs/tags/{tag}", "-f", f"sha={sha}")
    if existing_tag(repo, tag) != sha:
        raise ValueError(f"Tag {tag} changed before publishing.")
    draft = gh_api(repo, f"releases/{api_id}")
    if not draft["draft"] or draft["prerelease"] or draft["tag_name"] != tag:
        raise ValueError(f"Draft {tag} changed before publishing.")
    published = gh_api(repo, f"releases/{api_id}", "--method", "PATCH", "-F", "draft=false",
                       "-F", "prerelease=false", "-f", "make_latest=true")
    if published["draft"] or published["prerelease"] or published["tag_name"] != tag or existing_tag(repo, tag) != sha:
        raise ValueError("Published release did not match the staged release.")
    for _ in range(5):
        if gh_api(repo, "releases/latest")["id"] == api_id:
            print(f"Published {tag} as Latest with all three verified stable update assets.")
            return
        time.sleep(2)
    raise ValueError(f"Release {tag} is public but GitHub Latest has not selected it.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign or publish a stable SleepyGram build.")
    sub = parser.add_subparsers(required=True, dest="command")
    signing = sub.add_parser("sign")
    signing.add_argument("--keys", type=Path, required=True)
    signing.add_argument("--packer", type=Path, required=True)
    release = sub.add_parser("publish")
    release.add_argument("--repo-root", type=Path, default=Path.cwd())
    for command in (signing, release):
        command.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        (sign if args.command == "sign" else publish)(args)
    except subprocess.CalledProcessError as error:
        if args.command == "publish" and error.stderr:
            print(error.stderr.strip(), file=sys.stderr)
        sys.exit(f"{args.command.capitalize()} failed with exit code {error.returncode}.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
