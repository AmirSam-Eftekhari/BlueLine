import sys
import unittest
from pathlib import Path
from unittest import mock

from app.core import paths


class TestPathResolution(unittest.TestCase):
    def test_not_frozen_when_running_from_source(self):
        self.assertFalse(paths.is_frozen())

    def test_source_bundle_root_is_project_root(self):
        root = paths.bundle_root()
        # Project root should contain the top-level app/ and ui/ directories.
        self.assertTrue((root / "app").is_dir())
        self.assertTrue((root / "ui").is_dir())

    def test_frozen_onefile_uses_meipass(self):
        # Simulate exactly what PyInstaller sets at runtime for a onefile
        # build, without needing an actual PyInstaller build available.
        fake_meipass = "/tmp/_MEI123456"
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "_MEIPASS", fake_meipass, create=True):
            self.assertTrue(paths.is_frozen())
            self.assertEqual(paths.bundle_root(), Path(fake_meipass))
            self.assertEqual(paths.ui_dir(), Path(fake_meipass) / "ui")

    def test_frozen_onedir_falls_back_to_executable_directory(self):
        # onedir builds don't set _MEIPASS the same way in every
        # PyInstaller version; the fallback must still resolve sensibly.
        with mock.patch.object(sys, "frozen", True, create=True):
            if hasattr(sys, "_MEIPASS"):
                delattr(sys, "_MEIPASS")
            with mock.patch.object(sys, "executable", "/opt/BlueLine/BlueLine"):
                self.assertEqual(paths.bundle_root(), Path("/opt/BlueLine"))

    def test_user_data_dir_is_not_the_current_working_directory(self):
        data_dir = paths.user_data_dir()
        self.assertNotEqual(str(data_dir), os_getcwd())
        self.assertTrue(data_dir.is_dir())  # created if it didn't exist

    def test_user_data_dir_is_stable_across_calls(self):
        self.assertEqual(paths.user_data_dir(), paths.user_data_dir())

    def test_default_db_path_lives_under_user_data_dir(self):
        db_path = paths.default_db_path()
        self.assertTrue(db_path.startswith(str(paths.user_data_dir())))
        self.assertTrue(db_path.endswith("blueline_data.sqlite3"))


def os_getcwd():
    import os
    return os.getcwd()


if __name__ == "__main__":
    unittest.main()
