import shutil
import tempfile
import unittest
from pathlib import Path

from prune_macos_qt_sources import prune


class MacOSQtSourcePruneTests(unittest.TestCase):
    def make_fixture(
        self,
        root: Path,
        tool_directory: str = "libexec",
    ) -> tuple[Path, Path, Path]:
        libraries = root / "Libraries"
        stage = libraries / "qt_6.11.2"
        marker = libraries / "cache_keys" / "qt_6.11.2"
        installed = libraries / "local" / "Qt-6.11.2"
        (stage / "qtbase" / ".git" / "objects").mkdir(parents=True)
        (stage / "qtbase" / ".git" / "objects" / "pack").write_text("source build")
        marker.parent.mkdir(parents=True)
        marker.write_text("a" * 40)
        for path in (
            installed / "include" / "QtCore" / "qglobal.h",
            installed / "lib" / "cmake" / "Qt6" / "Qt6Config.cmake",
            installed / "lib" / "libQt6Core.a",
            installed / "lib" / "libQt6Gui.a",
            installed / "lib" / "libQt6Widgets.a",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("installed output")
        for name in ("moc", "rcc", "uic"):
            tool = installed / tool_directory / name
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("tool")
            tool.chmod(0o755)
        return libraries, stage, marker

    def test_prunes_only_stage_contents_and_preserves_cache_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            libraries, stage, marker = self.make_fixture(root)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("keep")
            (stage / "qtbase" / "external-link").symlink_to(
                outside,
                target_is_directory=True)

            self.assertTrue(prune(libraries, "6.11.2"))

            self.assertTrue(stage.is_dir())
            self.assertEqual(list(stage.iterdir()), [])
            self.assertEqual(marker.read_text(), "a" * 40)
            installed_core = (
                libraries / "local" / "Qt-6.11.2" / "lib" / "libQt6Core.a")
            self.assertTrue(installed_core.is_file())
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertTrue(prune(libraries, "6.11.2"))

    def test_does_not_prune_when_installed_output_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            libraries, stage, _ = self.make_fixture(Path(directory))
            (libraries / "local" / "Qt-6.11.2" / "lib" / "libQt6Widgets.a").unlink()

            self.assertFalse(prune(libraries, "6.11.2"))

            self.assertTrue((stage / "qtbase" / ".git" / "objects" / "pack").is_file())

    def test_accepts_tools_installed_in_bin(self):
        with tempfile.TemporaryDirectory() as directory:
            libraries, stage, _ = self.make_fixture(
                Path(directory),
                tool_directory="bin")

            self.assertTrue(prune(libraries, "6.11.2"))
            self.assertTrue(stage.is_dir())

    def test_does_not_accept_an_installed_header_linked_into_the_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            libraries, stage, _ = self.make_fixture(Path(directory))
            installed_header = (
                libraries / "local" / "Qt-6.11.2" / "include" / "QtCore" / "qglobal.h")
            staged_header = stage / "qtbase" / "qglobal.h"
            staged_header.write_text("staged header")
            installed_header.unlink()
            installed_header.symlink_to(staged_header)

            self.assertFalse(prune(libraries, "6.11.2"))
            self.assertTrue(staged_header.is_file())

    def test_does_not_follow_a_stage_symlink_outside_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            libraries, stage, marker = self.make_fixture(root)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("keep")
            for child in stage.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            stage.rmdir()
            stage.symlink_to(outside, target_is_directory=True)

            self.assertFalse(prune(libraries, "6.11.2"))

            self.assertEqual(sentinel.read_text(), "keep")
            self.assertEqual(marker.read_text(), "a" * 40)


if __name__ == "__main__":
    unittest.main()
