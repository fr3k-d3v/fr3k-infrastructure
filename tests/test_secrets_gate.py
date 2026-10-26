"""Tests for the fail-closed credential scanner.

Every fixture value is assembled at runtime so this test module never becomes a finding of
its own gate.  The redaction tests are the important ones: the scanner's output is
committed as evidence, so a finding must never carry the secret it found.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path

from fr3k_control import secrets_gate as sg

GIT = "/usr/bin/git"
PRIVATE_HEADER = "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def git(root: Path, *args: str) -> None:
    subprocess.run([GIT, *args], cwd=root, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "README.md").write_text("clean\n", encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "init")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def commit(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", f"add {relative}")

    def scan(self, history: bool = False) -> tuple[int, dict]:
        report = sg.evaluate(self.root, None, history)
        return (sg.EXIT_GO if report["verdict"] == "GO" else sg.EXIT_BLOCKED), report


class TreeScanTests(RepoCase):
    def test_clean_tree_goes_green(self) -> None:
        rc, report = self.scan()
        self.assertEqual(rc, sg.EXIT_GO, report)
        self.assertEqual(report["counts"]["findings"], 0)

    def test_github_token_blocks_and_is_redacted(self) -> None:
        self.commit("config/settings.py", f'token = "{GITHUB_TOKEN}"\n')
        rc, report = self.scan()
        self.assertEqual(rc, sg.EXIT_BLOCKED)
        self.assertIn("github-token", {finding["rule"] for finding in report["findings"]})
        rendered = json.dumps(report)
        self.assertNotIn(GITHUB_TOKEN, rendered)
        self.assertNotIn(GITHUB_TOKEN[-12:], rendered)

    def test_private_key_block_is_never_waivable(self) -> None:
        self.commit("keys/deploy", f"{PRIVATE_HEADER}\nnot-a-real-key\n")
        allowlist = self.root / "allow.json"
        allowlist.write_text(json.dumps({
            "schema": sg.ALLOWLIST_SCHEMA,
            "entries": [{"rule": "private-key-block", "path": "keys/deploy",
                         "reason": "pretend this is fine", "expires": "2099-01-01"}],
        }), encoding="utf-8")
        report = sg.evaluate(self.root, allowlist, False)
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertTrue(all(not finding["allowlisted"] for finding in report["findings"]))

    def test_live_allowlist_waives_with_reason_and_expiry(self) -> None:
        self.commit("config/app.ini", f'api_key = "{GITHUB_TOKEN}"\n')
        baseline = sg.evaluate(self.root, None, False)
        finding = baseline["findings"][0]
        allowlist = self.root / "allow.json"
        allowlist.write_text(json.dumps({
            "schema": sg.ALLOWLIST_SCHEMA,
            "entries": [{"rule": finding["rule"], "path": "config/app.ini",
                         "fingerprint": finding["fingerprint"],
                         "reason": "synthetic fixture for the redaction test",
                         "expires": "2099-01-01"}],
        }), encoding="utf-8")
        report = sg.evaluate(self.root, allowlist, False)
        self.assertEqual(report["verdict"], "GO", report["findings"])
        self.assertEqual(report["counts"]["waived"], 1)

    def test_expired_allowlist_does_not_waive(self) -> None:
        self.commit("config/app.ini", f'api_key = "{GITHUB_TOKEN}"\n')
        baseline = sg.evaluate(self.root, None, False)
        finding = baseline["findings"][0]
        allowlist = self.root / "allow.json"
        allowlist.write_text(json.dumps({
            "schema": sg.ALLOWLIST_SCHEMA,
            "entries": [{"rule": finding["rule"], "path": "config/app.ini",
                         "fingerprint": finding["fingerprint"],
                         "reason": "expired waiver should not silence this",
                         "expires": "2020-01-01"}],
        }), encoding="utf-8")
        report = sg.evaluate(self.root, allowlist, False)
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertTrue(any("expired" in problem for problem in report["problems"]))

    def test_dotenv_file_is_a_path_finding(self) -> None:
        self.commit(".env", "DATABASE_URL=postgres://user:pass@db.internal/xiaozhi\n")
        rc, report = self.scan()
        self.assertEqual(rc, sg.EXIT_BLOCKED)
        self.assertIn("dotenv-file", {finding["rule"] for finding in report["findings"]})

    def test_placeholder_is_not_a_finding(self) -> None:
        self.commit("README2.md", 'password = "your_password_here"\n')
        rc, report = self.scan()
        self.assertEqual(rc, sg.EXIT_GO, report["findings"])

    def test_long_identifier_and_url_are_not_findings(self) -> None:
        self.commit("notes.md", "See https://github.com/org/repo/blob/main/FINAL_ACCEPTANCE_EVIDENCE.md\n")
        self.commit("tests/example.py", "    def test_a_really_long_descriptive_test_name(self):\n        pass\n")
        rc, report = self.scan()
        self.assertEqual(rc, sg.EXIT_GO, report["findings"])


class HistoryScanTests(RepoCase):
    def test_secret_deleted_from_head_is_still_found_in_history(self) -> None:
        self.commit("secrets.txt", f"token: {GITHUB_TOKEN}\n")
        (self.root / "secrets.txt").unlink()
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "remove")
        rc_tree, tree_report = self.scan(history=False)
        self.assertEqual(rc_tree, sg.EXIT_GO, tree_report["findings"])
        rc_hist, hist_report = self.scan(history=True)
        self.assertEqual(rc_hist, sg.EXIT_BLOCKED)
        self.assertTrue(any(finding["location"].startswith("history:secrets.txt@")
                            for finding in hist_report["findings"]))
        self.assertNotIn(GITHUB_TOKEN, json.dumps(hist_report))

    def test_missing_repository_is_a_data_error(self) -> None:
        rc = sg.main(["--repo", str(self.root / "does-not-exist")])
        self.assertEqual(rc, sg.EXIT_DATA_ERROR)


if __name__ == "__main__":
    unittest.main()
