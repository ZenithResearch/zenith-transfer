"""Deletion boundaries: rollback, running apps, unknown content and symlinks."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location("prune", Path(__file__).with_name("prune-build-backups.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RetentionTests(unittest.TestCase):
    def test_retains_current_latest_rollback_and_busy_older_app(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            current = root / "Zenith Transfer.app"
            current.mkdir()
            backups = []
            for number in range(3):
                backup = root / f"transfer-previous.{number}"
                (backup / "Zenith Transfer.app").mkdir(parents=True)
                os.utime(backup, (number + 1, number + 1))
                backups.append(backup)
            module.prune(root, True, busy=lambda p: p == backups[0])
            self.assertTrue(current.exists())
            self.assertTrue(backups[0].exists())
            self.assertFalse(backups[1].exists())
            self.assertTrue(backups[2].exists())

    def test_dry_run_unknown_content_and_symlinks_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "source"
            outside.mkdir()
            (outside / "important").write_text("preserve")
            (root / "transfer-previous.alias").symlink_to(outside, target_is_directory=True)
            unknown = root / "transfer-previous.unknown"
            unknown.mkdir()
            (unknown / "notes").write_text("preserve")
            for number in range(3):
                (root / f"CastaliaWallet.previous.{number}.xcframework").mkdir()
            result = module.prune(root, busy=lambda _: False)
            self.assertEqual(len(result), 2)
            self.assertEqual(len(list(root.glob("CastaliaWallet.previous.*"))), 3)
            module.prune(root, True, busy=lambda _: False)
            self.assertEqual(len(list(root.glob("CastaliaWallet.previous.*"))), 1)
            self.assertTrue((outside / "important").exists())
            self.assertTrue((unknown / "notes").exists())
            self.assertTrue((root / "transfer-previous.alias").is_symlink())

    def test_lsof_errors_and_mapped_executables_are_kept(self):
        for result in [subprocess.CompletedProcess([], 0, "mapped executable", ""),
                       subprocess.CompletedProcess([], 1, "", "permission denied")]:
            with patch.object(module.subprocess, "run", return_value=result):
                self.assertTrue(module.in_use(Path("backup")))
        with patch.object(module.subprocess, "run", side_effect=FileNotFoundError):
            self.assertTrue(module.in_use(Path("backup")))
        with patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            self.assertFalse(module.in_use(Path("backup")))


if __name__ == "__main__":
    unittest.main()
