"""Guards for the Contabo backup/restore evidence and its scripts.

These tests only inspect static artifacts: they never touch Docker, the network or
production data, so they are safe to run in CI.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "CONTABO_BACKUP_RESTORE_20261026.md"
SCRIPTS = [ROOT / "scripts" / "contabo-backup.sh", ROOT / "scripts" / "contabo-restore-verify.sh"]
UNITS = [ROOT / "ops" / "systemd" / "fr3k-contabo-backup.service",
         ROOT / "ops" / "systemd" / "fr3k-contabo-backup.timer"]

# Patterns that must never appear in a document that is published in a public repo.
SECRET_PATTERNS = [
    r"BEGIN [A-Z ]*PRIVATE KEY",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"MYSQL_ROOT_PASSWORD=\S+",
    r"REDIS_PASSWORD=\S+",
    r"POSTGRES_PASSWORD=\S+",
    r"-----BEGIN PGP",
]


class EvidenceDocumentTests(unittest.TestCase):
    def test_document_exists(self):
        self.assertTrue(DOC.is_file(), f"missing evidence document {DOC}")

    def test_required_verdicts_present(self):
        text = DOC.read_text(encoding="utf-8")
        for marker in ("VERIFIED", "PARTIALLY_VERIFIED", "NOT_STARTED", "BLOCKED",
                       "MySQL", "Redis", "PostgreSQL", "restore"):
            self.assertIn(marker, text, f"evidence document lost required marker {marker!r}")

    def test_no_secret_material_published(self):
        text = DOC.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(re.search(pattern, text),
                              f"evidence document matches secret pattern {pattern!r}")

    def test_declares_unverified_scope(self):
        """An evidence document that claims everything is done is a red flag."""
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("does not claim", text.lower())


class ScriptTests(unittest.TestCase):
    def test_scripts_exist_and_executable(self):
        for script in SCRIPTS:
            self.assertTrue(script.is_file(), f"missing script {script}")
            self.assertTrue(script.stat().st_mode & 0o111, f"{script.name} is not executable")

    def test_scripts_are_valid_bash(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash unavailable")
        for script in SCRIPTS:
            proc = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{script.name} syntax error: {proc.stderr}")

    def test_restore_script_fails_closed(self):
        """A parity check must not report PASS on an empty comparison."""
        text = (ROOT / "scripts" / "contabo-restore-verify.sh").read_text(encoding="utf-8")
        self.assertIn("empty count set", text)
        self.assertNotIn('MYSQL_RESTORE_VERDICT: PASS (0 tables', text)
        self.assertIn("OVERALL=", text)

    def test_backup_script_never_echoes_passphrase(self):
        text = (ROOT / "scripts" / "contabo-backup.sh").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"cat\s+\"?\$?\{?KEYDIR")
        self.assertIn("key_passphrase_sha256_prefix", text)

    def test_units_are_not_installed_by_this_repository(self):
        """Enabling a timer is an operator decision; the repo only ships the files."""
        for unit in UNITS:
            self.assertTrue(unit.is_file(), f"missing unit {unit}")
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("not installed", doc)


if __name__ == "__main__":
    unittest.main()
