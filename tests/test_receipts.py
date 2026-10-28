import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fr3k_control.receipts import (
    check_reuse,
    create_receipt,
    environment_hash,
    sign,
    stage_for_basis,
    validate_receipt,
)


def make_receipt(**overrides):
    body = create_receipt(
        name="deploy-check",
        command="python3 -m fr3k_control.gate control/gates/g0.json",
        revision="0" * 40,
        evidence_basis="verification_observed",
        result={"exit_code": 0, "summary": "gate passed"},
        artifacts=[],
        producer="test",
    )
    body.update(overrides)
    body.pop("signature", None)
    body["signature"] = sign(body)
    return body


class ReceiptTests(unittest.TestCase):
    def test_verified_basis_maps_to_verified_stage(self):
        self.assertEqual("verified", stage_for_basis("schema_valid"))
        self.assertEqual("verified", stage_for_basis("verification_observed"))
        self.assertEqual("verified", stage_for_basis("integration_ready"))
        self.assertEqual("reported_done", stage_for_basis("process_exit"))

    def test_create_verify_roundtrip_is_valid(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            artifact = base / "evidence" / "result.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"ok": true}\n', encoding="utf-8")
            import hashlib

            receipt = make_receipt(
                artifacts=[{"path": "evidence/result.json", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}]
            )
            self.assertEqual([], validate_receipt(receipt, base))

    def test_verify_rejects_tampered_artifact(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            artifact = base / "result.json"
            artifact.write_text("original\n", encoding="utf-8")
            import hashlib

            receipt = make_receipt(
                artifacts=[{"path": "result.json", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}]
            )
            artifact.write_text("tampered\n", encoding="utf-8")
            errors = validate_receipt(receipt, base)
            self.assertTrue(any("artifact hash mismatch" in e for e in errors))

    def test_verify_rejects_modified_body(self):
        receipt = make_receipt()
        receipt["producer"] = "someone-else"
        errors = validate_receipt(receipt, Path.cwd())
        self.assertTrue(any("signature mismatch" in e for e in errors))

    def test_process_exit_basis_cannot_claim_verified_stage(self):
        receipt = make_receipt(evidence_basis="process_exit", status_stage="verified")
        body = {k: v for k, v in receipt.items() if k != "signature"}
        body["signature"] = sign(body)
        errors = validate_receipt(body, Path.cwd())
        self.assertTrue(any("stage must be reported_done" in e for e in errors))

    def test_verified_receipt_requires_zero_exit(self):
        receipt = make_receipt(result={"exit_code": 1, "summary": "gate failed"})
        errors = validate_receipt(receipt, Path.cwd())
        self.assertTrue(any("exit_code == 0" in e for e in errors))

    def test_reuse_reusable_when_revision_command_environment_match(self):
        receipt = make_receipt()
        verdict = check_reuse(
            receipt,
            revision=receipt["revision"],
            command=receipt["command"],
            environment=receipt["environment_hash"],
        )
        self.assertEqual("REUSABLE", verdict["verdict"])
        self.assertEqual([], verdict["reasons"])

    def test_reuse_stale_when_command_or_revision_or_environment_differ(self):
        receipt = make_receipt()
        stale_command = check_reuse(receipt, receipt["revision"], "other command", receipt["environment_hash"])
        stale_revision = check_reuse(receipt, "1" * 40, receipt["command"], receipt["environment_hash"])
        stale_environment = check_reuse(receipt, receipt["revision"], receipt["command"], "sha256:other")
        for verdict in (stale_command, stale_revision, stale_environment):
            self.assertEqual("STALE", verdict["verdict"])
            self.assertNotEqual([], verdict["reasons"])
        # Same machine, same environment snapshot: reuse is legitimately allowed.
        self.assertEqual(
            "REUSABLE",
            check_reuse(receipt, receipt["revision"], receipt["command"], environment_hash())["verdict"],
        )

    def test_missing_required_field_is_invalid(self):
        receipt = make_receipt()
        receipt.pop("revision")
        body = {k: v for k, v in receipt.items() if k != "signature"}
        body["signature"] = sign(body)
        errors = validate_receipt(body, Path.cwd())
        self.assertTrue(any("missing field: revision" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
