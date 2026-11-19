#!/usr/bin/env python3
import argparse
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_artifact import MACOS_INSTALLER, PLATFORMS
from update_package import TARGETS, TEST_TRUST_DIR, TRUST_FILES, asset_name, pack, stable_version, trust_bundle, verify_candidate
from update_release import check_release_version, check_uploaded_assets, publish, sign, stable_key_id


REPO = Path(__file__).resolve().parents[2]
KEYS = REPO / TEST_TRUST_DIR
TEST_KEY = REPO / "tools/tests/fixtures/sleepygram-update-leaf.pem"
PACKER = None


def make_archive(directory, platform, name, content):
    archive = directory / PLATFORMS[platform][0]
    if platform == "linux-x64":
        with tarfile.open(archive, "w:xz") as package:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            member.size = len(content)
            package.addfile(member, io.BytesIO(content))
    else:
        with zipfile.ZipFile(archive, "w") as package:
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = 0o100755 << 16
            package.writestr(member, content)
    return archive


def make_candidate(directory, platform, version, content, override_os=None):
    os_id, arch_id, _, _, updater = TARGETS[platform]
    name = asset_name(platform)
    filename = updater.encode("utf-16-be")
    inner = struct.pack(">III", version, 1, len(filename)) + filename
    inner += struct.pack(">II", len(content), len(content)) + content
    if platform == "windows-x64":
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 4096, "lc": 4, "lp": 0, "pb": 2}]
        payload = struct.pack("<BII", 94, 4096, len(inner)) + lzma.compress(inner, format=lzma.FORMAT_RAW, filters=filters)
    else:
        inner += b"\x01"
        payload = struct.pack("<I", len(inner)) + lzma.compress(inner)
    manifest = (KEYS / "manifest.min.json").read_bytes()
    signature = (KEYS / "manifest.sig").read_bytes()
    fields = (b"TDUP", 2, 0, os_id if override_os is None else override_os, arch_id, version << 32, 1, len(manifest))
    header = struct.pack("<4sIBBBQQI", *fields) + manifest
    unsigned = header + struct.pack("<I", len(signature)) + signature + struct.pack("<II", 0, len(payload)) + payload
    (directory / f"{name}.unsigned").write_bytes(unsigned)
    (directory / f"{name}.signing-input").write_bytes(header + hashlib.sha256(payload).digest())


class SignedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def test_trust_fixture_cannot_publish(self):
        with patch.dict(os.environ, {"SLEEPYGRAM_UPDATE_PUBLIC_BUNDLE": ""}):
            trust_bundle(REPO, self.output, False)
            self.assertEqual((self.output / "root-public.pem").read_bytes(), (KEYS / "root-public.pem").read_bytes())
            with self.assertRaisesRegex(ValueError, "repository variable"):
                trust_bundle(REPO, self.output, True)
        values = {name: base64.b64encode((KEYS / name).read_bytes()).decode() for name in TRUST_FILES}
        with patch.dict(os.environ, {"SLEEPYGRAM_UPDATE_PUBLIC_BUNDLE": json.dumps(values)}):
            with self.assertRaisesRegex(ValueError, "reuses public test keys"):
                trust_bundle(REPO, self.output, True)
        self.assertEqual(stable_key_id(KEYS, TEST_KEY), "sleepygram-ci-fixture")

    def test_same_platform_and_inventory(self):
        _, version = stable_version(REPO)
        for platform, (os_id, _, _, _, updater) in TARGETS.items():
            with self.subTest(platform=platform):
                content = (b"file contents" * (2 ** 18)) + b"!"
                archive = make_archive(self.output, platform, updater, content)
                make_candidate(self.output, platform, version, content)
                verify_candidate(self.output, platform, version, KEYS, archive)
                make_candidate(self.output, platform, version, content, override_os=(os_id + 1) % 3)
                with self.assertRaisesRegex(ValueError, "Wrong TDUP header"):
                    verify_candidate(self.output, platform, version, KEYS, archive)
                make_candidate(self.output, platform, version, content[:-1] + b"?")
                with self.assertRaisesRegex(ValueError, "differs from the manual archive"):
                    verify_candidate(self.output, platform, version, KEYS, archive)
                signing = self.output / f"{asset_name(platform)}.signing-input"
                signing.write_bytes(signing.read_bytes()[:-1] + b"?")
                with self.assertRaisesRegex(ValueError, "Incorrect TDUP signing input"):
                    verify_candidate(self.output, platform, version, KEYS, archive)

    def test_release_version_and_upload(self):
        old = {"tag_name": "v7.9.0", "draft": False, "prerelease": False}
        check_release_version([old], "v7.10.0")
        with self.assertRaisesRegex(ValueError, "already exists"):
            check_release_version([old], "v7.9.0")
        with self.assertRaisesRegex(ValueError, "newer"):
            check_release_version([old], "v7.8.0")
        asset = self.output / "setup.zip"
        asset.write_bytes(b"zip")
        uploaded = {"name": asset.name, "size": 3, "state": "uploaded",
                    "digest": "sha256:" + hashlib.sha256(b"zip").hexdigest()}
        check_uploaded_assets([uploaded], {asset.name: asset})
        with self.assertRaisesRegex(ValueError, "different set"):
            check_uploaded_assets([], {asset.name: asset})
        with self.assertRaisesRegex(ValueError, "exact uploaded asset"):
            check_uploaded_assets([{**uploaded, "digest": "sha256:wrong"}], {asset.name: asset})

    def test_release_only_publishes_verified_draft(self):
        tag, _ = stable_version(REPO)
        sha = "a" * 40
        upload = []
        for platform, (archive, _) in PLATFORMS.items():
            directory = self.output / f"package-{platform}"
            directory.mkdir()
            names = [archive, asset_name(platform)]
            if platform == "macos-arm64":
                names.append(MACOS_INSTALLER)
            for name in names:
                content = name.encode()
                (directory / name).write_bytes(content)
                upload.append({"name": name, "size": len(content), "state": "uploaded",
                               "digest": "sha256:" + hashlib.sha256(content).hexdigest()})
        args = argparse.Namespace(directory=self.output, repo_root=REPO)
        draft = {"id": 1, "draft": True, "prerelease": False, "tag_name": tag}
        public = {**draft, "draft": False}
        environment = {"GITHUB_SHA": sha, "GITHUB_REPOSITORY": "slpkbt/SleepyGram"}
        for good_upload in (False, True):
            with self.subTest(good_upload=good_upload):
                with patch.dict(os.environ, environment), redirect_stdout(io.StringIO()), \
                        patch("update_release.existing_tag", return_value=sha), \
                        patch("update_release.subprocess.run"), \
                        patch("update_release.list_release_items", side_effect=[[], upload if good_upload else [], [draft]]), \
                        patch("update_release.gh_api", side_effect=[draft, draft, public, public]) as api:
                    if not good_upload:
                        with self.assertRaisesRegex(ValueError, "different set"):
                            publish(args)
                        self.assertEqual(api.call_count, 1)
                    else:
                        publish(args)
                        self.assertEqual(api.call_args_list[-1].args[-1], "releases/latest")
                        self.assertIn("make_latest=true", api.call_args_list[-2].args)

    def test_native_packer_signs_with_fixture_key(self):
        if PACKER is None:
            self.skipTest("Pass --packer to exercise native unsigned packing and signing.")
        _, version = stable_version(REPO)
        for platform, (_, _, _, _, updater) in TARGETS.items():
            directory = self.output / f"package-{platform}"
            directory.mkdir()
            content = b"fixture updater"
            archive = make_archive(directory, platform, updater, content)
            if (sys.platform == "darwin" and platform == "macos-arm64"
                    or sys.platform.startswith("linux") and platform == "linux-x64"):
                stage = self.output / "staged"
                staged_updater = stage / updater
                staged_updater.parent.mkdir(parents=True)
                staged_updater.write_bytes(content)
                staged_updater.chmod(0o755)
                stage = stage / "SleepyGram.app" if platform == "macos-arm64" else stage
                pack(argparse.Namespace(repo_root=REPO, platform=platform, keys=KEYS, packer=PACKER,
                                        stage=stage, output=directory, archive=archive))
            else:
                make_candidate(directory, platform, version, content)
        args = argparse.Namespace(directory=self.output, keys=KEYS, packer=PACKER)
        with patch.dict(os.environ, {"SLEEPYGRAM_UPDATE_STABLE_KEY_PEM": TEST_KEY.read_text()}):
            sign(args)
        for platform in TARGETS:
            asset = self.output / f"package-{platform}" / asset_name(platform)
            self.assertTrue(asset.read_bytes().startswith(b"TDUP"))
            self.assertGreater(asset.stat().st_size, asset.with_suffix(".tdup.unsigned").stat().st_size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--packer", type=Path)
    options, unittest_args = parser.parse_known_args()
    PACKER = options.packer
    unittest.main(argv=[sys.argv[0], *unittest_args])
