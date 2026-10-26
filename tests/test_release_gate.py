"""Tests for the fail-closed OTA/APK pre-publication gate.

Fixtures are constructed here, not committed: a real Ed25519/ECDSA key is generated with
``openssl`` (skipped when the binary is absent), the manifest is signed over the exact
canonical bytes, and the APK is a synthetic zip with a real APK Signing Block structure.
The APK *cryptographic* path is exercised with a stub ``apksigner`` that emits the tool's
documented output; that tests the gate's parsing and pinning logic, not Android's crypto.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from fr3k_control import release_gate as rg

OPENSSL = shutil.which("openssl")


def make_apk(path: Path, abis=("arm64-v8a",), schemes=(0x7109871A, 0xF05368C0), v1: bool = True) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        if v1:
            archive.writestr("META-INF/CERT.RSA", b"synthetic-jar-signature-block")
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00synthetic-manifest")
        archive.writestr("classes.dex", b"dex\n035\x00synthetic")
        for abi in abis:
            archive.writestr(f"lib/{abi}/libblackwave.so", b"\x7fELF" + abi.encode())
    data = buffer.getvalue()
    if schemes:
        data = _insert_signing_block(data, schemes)
    path.write_bytes(data)


def _insert_signing_block(apk: bytes, schemes) -> bytes:
    pairs = b""
    for scheme in schemes:
        value = b"\x00" * 8  # opaque value: the gate only reads scheme ids here
        pairs += struct.pack("<Q", 4 + len(value)) + struct.pack("<I", scheme) + value
    block_size = len(pairs) + 8 + 16
    block = struct.pack("<Q", block_size) + pairs + struct.pack("<Q", block_size) + rg.APK_SIG_BLOCK_MAGIC
    eocd_index = apk.rfind(b"PK\x05\x06")
    cd_offset = int.from_bytes(apk[eocd_index + 16 : eocd_index + 20], "little")
    data = bytearray(apk[:cd_offset] + block + apk[cd_offset:])
    new_eocd_index = eocd_index + len(block)
    data[new_eocd_index + 16 : new_eocd_index + 20] = struct.pack("<I", cd_offset + len(block))
    return bytes(data)


class GateHarness:
    def __init__(self, root: Path, algorithm: str = "ed25519"):
        self.root = root
        self.keys = root / "keys"
        self.keys.mkdir(parents=True, exist_ok=True)
        self.artifacts = root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.candidates = root / "release" / "candidates"
        self.candidates.mkdir(parents=True, exist_ok=True)
        self.algorithm = algorithm
        self.private = self.keys / "ota.pem"
        self.public = self.keys / "ota.pub.pem"
        if algorithm == "ed25519":
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ed25519", "-out", str(self.private)],
                           check=True, capture_output=True)
        else:
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
                       check=True, capture_output=True)
        self.policy = {
            "schema": rg.POLICY_SCHEMA,
            "publish": {"allowed_roots": ["/srv/fr3k/releases/ota-public", "/srv/fr3k/releases/public/android/blackwave"]},
            "ota": {
                "channels": ["stable", "canary"],
                "devices": {"t-deck-plus": {"hardware_revisions": ["v1.0"]}},
                "signing_keys": {
                    "ota-test": {"algorithm": algorithm, "public_key_path": str(self.public),
                                 "not_after": "2099-01-01", "revoked": False}
                },
            },
            "apk": {
                "apksigner": "apksigner-not-installed",
                "packages": {"dev.fr3k.blackwave": {"allowed_abis": ["arm64-v8a"],
                                                    "min_version_code": 5}},
                "trusted_signer_cert_sha256": [],
            },
        }
        self.state = {"schema": "fr3k.release.state/v1", "ota": {}, "apk": {}}
        self.image = self.artifacts / "blackwave-tdeck-1.4.0.bin"
        self.image.write_bytes(b"\xe9" + b"firmware" * 8)
        self.manifest = {
            "schema": rg.MANIFEST_SCHEMA,
            "product": "blackwave",
            "device": "t-deck-plus",
            "hardware_revision": "v1.0",
            "channel": "stable",
            "version": "1.4.0",
            "security_version": 7,
            "build_id": "2026.10.26-1",
            "source_commit": "0" * 40,
            "issued_at": "2026-10-26T12:00:00Z",
            "image_url": str(self.image),
            "image_sha256": rg.sha256_file(self.image),
            "size_bytes": self.image.stat().st_size,
            "signature_algorithm": algorithm,
            "key_id": "ota-test",
        }

    def write(self) -> None:
        (self.root / "policy.json").write_text(json.dumps(self.policy), encoding="utf-8")
        (self.root / "state.json").write_text(json.dumps(self.state), encoding="utf-8")

    def sign(self, manifest: dict, algorithm: str | None = None) -> Path:
        payload = rg.canonical_bytes(manifest)
        signature = self.keys / "manifest.sig"
        algorithm = algorithm or self.algorithm
        openssl = OPENSSL or "openssl"
        payload_path = self.keys / "payload.bin"
        payload_path.write_bytes(payload)
        if algorithm == "ed25519":
            command = [openssl, "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
                       "-in", str(payload_path), "-out", str(signature)]
        else:
            command = [openssl, "dgst", "-sha256", "-sign", str(self.private),
                       "-out", str(signature), str(payload_path)]
        subprocess.run(command, check=True, capture_output=True)
        return signature

    def ota_candidate(self, name: str = "blackwave-1.4.0", manifest: dict | None = None, **overrides) -> dict:
        manifest = manifest or dict(self.manifest)
        signature = self.sign(manifest)
        candidate = {
            "schema": rg.CANDIDATE_SCHEMA,
            "id": name,
            "artifact": {"type": "ota_manifest", "path": "artifacts/manifest.json",
                         "sha256": "", "size_bytes": 0},
            "manifest": manifest,
            "signature": {"path": str(signature), "key_id": "ota-test"},
            "approval": {"approved_by": "Michael Insch", "approved_at": "2026-10-26T12:30:00Z",
                         "scope": "publish"},
            "review": {"reviewer": "Review Agent", "author": "Release Author", "ref": "PR#4"},
            "publish_path": "/srv/fr3k/releases/ota-public/v1/t-deck-plus/stable/manifest.json",
        }
        candidate.update(overrides)
        manifest_path = self.artifacts / "manifest.json"
        manifest_path.write_bytes(rg.canonical_bytes(manifest))
        candidate["artifact"]["sha256"] = rg.sha256_file(manifest_path)
        candidate["artifact"]["size_bytes"] = manifest_path.stat().st_size
        if "artifact" in overrides:
            candidate["artifact"] = overrides["artifact"]
        return candidate

    def write_candidate(self, candidate: dict) -> None:
        (self.candidates / f"{candidate['id']}.json").write_text(json.dumps(candidate), encoding="utf-8")

    def run(self) -> tuple[int, dict]:
        self.write()
        report = rg.evaluate(self.root / "policy.json", self.root / "state.json",
                             self.candidates, self.root)
        return (rg.EXIT_GO if report["verdict"] == "GO" else rg.EXIT_BLOCKED), report


def codes(report: dict) -> set[str]:
    return {gap["code"] for gap in report["gaps"]}


@unittest.skipUnless(OPENSSL, "openssl is required to generate and verify fixture keys")
class OtaGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.harness = GateHarness(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_signed_manifest_goes_green(self) -> None:
        self.harness.write_candidate(self.harness.ota_candidate())
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_GO, report["gaps"])
        self.assertEqual(report["verdict"], "GO")
        self.assertTrue(report["candidates"][0]["signature_verified"])

    def test_ecdsa_manifest_goes_green(self) -> None:
        harness = GateHarness(Path(self.tmp.name), algorithm="ecdsa-p256-sha256")
        harness.write_candidate(harness.ota_candidate())
        rc, report = harness.run()
        self.assertEqual(rc, rg.EXIT_GO, report["gaps"])

    def test_tampered_manifest_blocks(self) -> None:
        candidate = self.harness.ota_candidate()
        candidate["manifest"]["security_version"] = 99  # signed bytes no longer match
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_BLOCKED)
        self.assertIn("OTA_SIGNATURE_INVALID", codes(report))

    def test_rollback_below_published_floor_blocks(self) -> None:
        self.harness.state["ota"] = {"t-deck-plus": {"stable": {"version": "1.4.0", "security_version": 7}}}
        self.harness.write_candidate(self.harness.ota_candidate())
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_BLOCKED)
        self.assertIn("OTA_ROLLBACK", codes(report))

    def test_unknown_device_blocks(self) -> None:
        manifest = dict(self.harness.manifest, device="t-watch-ultra")
        self.harness.write_candidate(self.harness.ota_candidate(manifest=manifest))
        rc, report = self.harness.run()
        self.assertIn("OTA_DEVICE_UNKNOWN", codes(report))

    def test_revoked_key_blocks(self) -> None:
        self.harness.policy["ota"]["signing_keys"]["ota-test"]["revoked"] = True
        self.harness.write_candidate(self.harness.ota_candidate())
        rc, report = self.harness.run()
        self.assertIn("OTA_KEY_REVOKED", codes(report))

    def test_expired_key_blocks(self) -> None:
        self.harness.policy["ota"]["signing_keys"]["ota-test"]["not_after"] = "2020-01-01"
        self.harness.write_candidate(self.harness.ota_candidate())
        rc, report = self.harness.run()
        self.assertIn("OTA_KEY_EXPIRED", codes(report))

    def test_image_digest_mismatch_blocks(self) -> None:
        manifest = dict(self.harness.manifest, image_sha256="f" * 64)
        self.harness.write_candidate(self.harness.ota_candidate(manifest=manifest))
        rc, report = self.harness.run()
        self.assertIn("OTA_IMAGE_DIGEST_MISMATCH", codes(report))

    def test_placeholder_approver_blocks(self) -> None:
        candidate = self.harness.ota_candidate()
        candidate["approval"] = {"approved_by": "operator", "approved_at": "2026-10-26T12:30:00Z",
                                 "scope": "publish"}
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertIn("APPROVAL_PLACEHOLDER", codes(report))

    def test_self_review_blocks(self) -> None:
        candidate = self.harness.ota_candidate()
        candidate["review"] = {"reviewer": "Release Author", "author": "Release Author", "ref": "PR#4"}
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertIn("REVIEW_SELF", codes(report))

    def test_publish_outside_allowed_root_blocks(self) -> None:
        candidate = self.harness.ota_candidate(publish_path="/tmp/manifest.json")
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertIn("PUBLISH_PATH_NOT_ALLOWED", codes(report))

    def test_missing_artifact_blocks(self) -> None:
        candidate = self.harness.ota_candidate()
        candidate["artifact"]["sha256"] = "0" * 64
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", codes(report))

    def test_empty_staging_area_blocks(self) -> None:
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_BLOCKED)
        self.assertIn("NO_CANDIDATES", codes(report))

    def test_float_in_manifest_is_a_data_error(self) -> None:
        with self.assertRaises(rg.DataError):
            rg.canonical_bytes({"size_bytes": 1.5})


@unittest.skipUnless(OPENSSL, "openssl is required for the shared fixture harness")
class ApkGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.harness = GateHarness(self.root)
        self.apk = self.root / "artifacts" / "blackwave-1.0.0.apk"
        make_apk(self.apk)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def apk_candidate(self, **declared) -> dict:
        base = {"package": "dev.fr3k.blackwave", "version_code": 10, "abis": ["arm64-v8a"]}
        base.update(declared)
        return {
            "schema": rg.CANDIDATE_SCHEMA,
            "id": "apk-1.0.0",
            "artifact": {"type": "apk", "path": str(self.apk), "sha256": rg.sha256_file(self.apk),
                         "size_bytes": self.apk.stat().st_size},
            "apk": base,
            "approval": {"approved_by": "Michael Insch", "approved_at": "2026-10-26T12:30:00Z",
                         "scope": "publish"},
            "review": {"reviewer": "Review Agent", "author": "Release Author", "ref": "PR#4"},
            "publish_path": "/srv/fr3k/releases/public/android/blackwave/1.0.0/blackwave.apk",
        }

    def stub_apksigner(self, cert_sha: str, verify: bool = True) -> Path:
        stub = self.root / "apksigner"
        stub.write_text(
            "#!/bin/sh\n"
            "cat <<EOF\n"
            "Verifies\n"
            f"Verified using v1 scheme (JAR signing): {'true' if verify else 'false'}\n"
            f"Verified using v2 scheme (APK Signature Scheme v2): {'true' if verify else 'false'}\n"
            f"Signer #1 certificate SHA-256 digest: {cert_sha}\n"
            "EOF\n"
            f"exit {0 if verify else 1}\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return stub

    def test_signing_block_detected(self) -> None:
        self.assertIn("v2", rg.apk_scheme_ids(self.apk))
        self.assertIn("v3", rg.apk_scheme_ids(self.apk))
        self.assertEqual(rg.apk_abis(self.apk), ["arm64-v8a"])

    def test_missing_apksigner_blocks_never_passes(self) -> None:
        self.harness.write_candidate(self.apk_candidate())
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_BLOCKED)
        self.assertIn("APK_CRYPTO_UNVERIFIED", codes(report))

    def test_crypto_verified_but_unpinned_signer_blocks(self) -> None:
        cert = hashlib.sha256(b"signer-cert").hexdigest()
        self.harness.policy["apk"]["apksigner"] = str(self.stub_apksigner(cert))
        self.harness.write_candidate(self.apk_candidate(signer_cert_sha256=cert))
        rc, report = self.harness.run()
        self.assertIn("APK_SIGNER_UNTRUSTED", codes(report))

    def test_pinned_signer_goes_green(self) -> None:
        cert = hashlib.sha256(b"signer-cert").hexdigest()
        self.harness.policy["apk"]["apksigner"] = str(self.stub_apksigner(cert))
        self.harness.policy["apk"]["trusted_signer_cert_sha256"] = [cert]
        self.harness.write_candidate(self.apk_candidate(signer_cert_sha256=cert))
        rc, report = self.harness.run()
        self.assertEqual(rc, rg.EXIT_GO, report["gaps"])

    def test_version_code_rollback_blocks(self) -> None:
        cert = hashlib.sha256(b"signer-cert").hexdigest()
        self.harness.policy["apk"]["apksigner"] = str(self.stub_apksigner(cert))
        self.harness.policy["apk"]["trusted_signer_cert_sha256"] = [cert]
        self.harness.state["apk"] = {"dev.fr3k.blackwave": {"version_code": 10}}
        self.harness.write_candidate(self.apk_candidate(signer_cert_sha256=cert))
        rc, report = self.harness.run()
        self.assertIn("APK_ROLLBACK", codes(report))

    def test_declared_abi_mismatch_blocks(self) -> None:
        self.harness.write_candidate(self.apk_candidate(abis=["armeabi-v7a"]))
        rc, report = self.harness.run()
        self.assertIn("APK_ABI_MISMATCH", codes(report))

    def test_v1_only_apk_blocks(self) -> None:
        make_apk(self.apk, schemes=())
        candidate = self.apk_candidate()
        candidate["artifact"]["sha256"] = rg.sha256_file(self.apk)
        candidate["artifact"]["size_bytes"] = self.apk.stat().st_size
        self.harness.write_candidate(candidate)
        rc, report = self.harness.run()
        self.assertIn("APK_NO_SIGNING_BLOCK", codes(report))

    def test_malformed_policy_is_a_data_error(self) -> None:
        (self.root / "policy.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(rg.DataError):
            rg.evaluate(self.root / "policy.json", self.root / "state.json", self.harness.candidates, self.root)


if __name__ == "__main__":
    unittest.main()
