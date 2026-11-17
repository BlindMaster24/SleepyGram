import subprocess
import tempfile
import unittest
from pathlib import Path

from build_artifact import _parse_gitlinks, submodule_revisions


class SubmoduleRevisionTests(unittest.TestCase):
    def test_parses_paths_with_spaces_and_parentheses_from_nul_records(self):
        sha = b"1" * 40
        output = b"160000 " + sha + b" 0\tlibraries/source (mirror)\0"

        self.assertEqual(_parse_gitlinks(output), [(b"libraries/source (mirror)", sha)])

    def test_rejects_malformed_trailing_git_index_record(self):
        sha = b"a" * 40
        output = b"160000 " + sha + b" 0\tvalid/path\0trailing garbage"

        with self.assertRaisesRegex(RuntimeError, "Could not safely parse tracked submodule paths"):
            _parse_gitlinks(output)

    def test_rejects_conflicted_gitlink_stages(self):
        sha = b"a" * 40
        other = b"b" * 40
        output = (
            b"160000 " + sha + b" 1\tmodule\0"
            b"160000 " + other + b" 2\tmodule\0"
        )

        with self.assertRaisesRegex(RuntimeError, "unresolved merge"):
            _parse_gitlinks(output)

    def test_reads_recursive_gitlinks_and_effective_dirty_revision(self):
        with tempfile.TemporaryDirectory(prefix="artifact-submodules-") as temporary:
            root = Path(temporary) / "root"
            outer_source = Path(temporary) / "outer-source"
            inner_source = Path(temporary) / "inner-source"
            _init_repo(inner_source, "inner")
            _init_repo(outer_source, "outer")
            _git(outer_source, "-c", "protocol.file.allow=always", "submodule",
                "add", "-q", str(inner_source), "nested (helper)")
            _git(outer_source, "add", ".gitmodules", "nested (helper)")
            _git(outer_source, "commit", "-qm", "add nested submodule")

            _init_repo(root, "root")
            _git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                str(outer_source), "modules/outer (source)")
            _git(root, "add", ".gitmodules", "modules/outer (source)")
            _git(root, "commit", "-qm", "add outer submodule")
            _git(root, "-c", "protocol.file.allow=always", "submodule", "update",
                "--init", "--recursive")

            clean = submodule_revisions(root)
            self.assertEqual(
                {entry["path"] for entry in clean},
                {
                    "modules/outer (source)",
                    "modules/outer (source)/nested (helper)",
                },
            )
            self.assertTrue(all(entry["gitlink_match"] for entry in clean))

            checked_out_outer = root / "modules/outer (source)"
            (checked_out_outer / "change.txt").write_text("advanced\n")
            _git(checked_out_outer, "add", "change.txt")
            _git(checked_out_outer, "commit", "-qm", "advance checked-out submodule")

            dirty = submodule_revisions(root)
            dirty_outer = next(
                entry for entry in dirty
                if entry["path"] == "modules/outer (source)")
            clean_outer = next(
                entry for entry in clean
                if entry["path"] == "modules/outer (source)")
            self.assertFalse(dirty_outer["gitlink_match"])
            self.assertNotEqual(dirty_outer["actual_sha"], clean_outer["actual_sha"])

    def test_rejects_uninitialized_path_that_resolves_to_parent_repo(self):
        with tempfile.TemporaryDirectory(prefix="artifact-submodule-missing-") as temporary:
            root = Path(temporary) / "root"
            child_source = Path(temporary) / "child-source"
            _init_repo(child_source, "child")
            _init_repo(root, "root")
            _git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                str(child_source), "modules/child")
            _git(root, "add", ".gitmodules", "modules/child")
            _git(root, "commit", "-qm", "add submodule")
            uninitialized = Path(temporary) / "uninitialized"
            subprocess.run(
                ["git", "clone", "-q", "--no-recurse-submodules", str(root), str(uninitialized)],
                check=True,
                stderr=subprocess.PIPE,
            )
            (uninitialized / "modules/child").mkdir(parents=True, exist_ok=True)

            with self.assertRaisesRegex(RuntimeError, "Submodule is not initialized"):
                submodule_revisions(uninitialized)


def _git(directory: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(directory), *arguments],
        text=True,
        stderr=subprocess.PIPE,
    )


def _init_repo(directory: Path, name: str) -> None:
    directory.mkdir(parents=True)
    _git(directory, "init", "-q")
    _git(directory, "config", "user.name", "CI Test")
    _git(directory, "config", "user.email", "ci-test@example.invalid")
    (directory / "README").write_text(name + "\n")
    _git(directory, "add", "README")
    _git(directory, "commit", "-qm", "initial")


if __name__ == "__main__":
    unittest.main()
