import copy
import unittest
from datetime import datetime, timedelta, timezone

from fr3k_control.evidence_consistency import (
    EvidenceMismatch,
    compare_gate_evidence,
)


NOW = datetime(2026, 10, 13, 8, 0, tzinfo=timezone.utc)


class GateEvidenceConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.committed = {
            "gate": "G0",
            "verdict": "BLOCKED",
            "blocking_controls": ["G0-01"],
            "evaluated_at": "2026-08-01T20:29:36+00:00",
            "controls": [
                {"id": "G0-01", "passed": False, "owner_ok": False, "evidence_ok": True},
            ],
        }
        self.generated = copy.deepcopy(self.committed)
        self.generated["evaluated_at"] = NOW.isoformat()

    def test_changing_timestamp_alone_is_permitted(self):
        compare_gate_evidence(self.committed, self.generated, now=NOW)

    def test_blocking_controls_cannot_change_silently(self):
        self.generated["blocking_controls"] = []
        with self.assertRaises(EvidenceMismatch):
            compare_gate_evidence(self.committed, self.generated, now=NOW)

    def test_verdict_cannot_change_silently(self):
        self.generated["verdict"] = "GO"
        with self.assertRaises(EvidenceMismatch):
            compare_gate_evidence(self.committed, self.generated, now=NOW)

    def test_control_evidence_cannot_change_silently(self):
        self.generated["controls"][0]["evidence_ok"] = False
        with self.assertRaises(EvidenceMismatch):
            compare_gate_evidence(self.committed, self.generated, now=NOW)

    def test_stale_generated_timestamp_is_rejected(self):
        self.generated["evaluated_at"] = (NOW - timedelta(hours=1)).isoformat()
        with self.assertRaises(EvidenceMismatch):
            compare_gate_evidence(self.committed, self.generated, now=NOW)

    def test_naive_timestamp_is_rejected(self):
        self.generated["evaluated_at"] = "2026-10-13T08:00:00"
        with self.assertRaises(EvidenceMismatch):
            compare_gate_evidence(self.committed, self.generated, now=NOW)


if __name__ == "__main__":
    unittest.main()
