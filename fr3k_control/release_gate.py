"""Fail-closed pre-publication gate for BLACKWAVE OTA manifests and Android APKs.

The Contabo distribution host (``downloads.*`` / ``ota.*``) may only ever publish an
artifact that this gate has approved.  Everything the gate needs lives in Git:

* ``control/release-policy.json`` - which devices, channels, packages, ABIs, signing keys
  and publish roots are allowed (enrolment is an explicit, reviewable commit);
* ``control/release-state/baseline.json`` - anti-rollback floor per device/channel and per
  APK package, bumped only after a release is published;
* ``release/candidates/*.json`` - one descriptor per artifact, carrying the digest pins,
  the signing material, the operator approval and the review record.

Decision contract (same convention as ``fr3k_control.gate``):

* ``0`` - GO: every candidate passed every applicable check.
* ``2`` - BLOCKED: at least one gap, or no candidate at all (an empty staging area is not
  an approval).
* ``3`` - data error: policy/candidate JSON is unreadable or malformed.

Two rules are structural, not stylistic:

1. **Claims are not evidence.** A candidate's own ``claimed_verdicts`` never influence the
   decision; only mechanically checked facts do, plus a review record whose reviewer is a
   named human other than the author.
2. **No crypto, no GO.** Signature verification is delegated to ``openssl`` for OTA
   manifests and to ``apksigner`` for APK signature schemes v2/v3.  When either tool is
   absent the gate reports ``*_CRYPTO_UNVERIFIED`` and blocks; it never assumes a
   signature is valid because a ``.sig`` file exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "fr3k.release.gate/v1"
POLICY_SCHEMA = "fr3k.release.policy/v1"
CANDIDATE_SCHEMA = "fr3k.release.candidate/v1"
MANIFEST_SCHEMA = "fr3k.blackwave.ota.manifest/v1"
EXIT_GO = 0
EXIT_BLOCKED = 2
EXIT_DATA_ERROR = 3

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SCHEME_IDS = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}

PLACEHOLDER_APPROVERS = {
    "", "tbd", "tba", "unassigned", "unknown", "none", "n/a", "na", "placeholder",
    "operator", "human", "core team", "program lead", "release lead", "approved",
}

OTA_REQUIRED_FIELDS = (
    "schema",
    "product",
    "device",
    "hardware_revision",
    "channel",
    "version",
    "security_version",
    "build_id",
    "source_commit",
    "issued_at",
    "image_url",
    "image_sha256",
    "size_bytes",
    "signature_algorithm",
    "key_id",
)

GAP_REMEDIES = {
    "POLICY_INVALID": "fix control/release-policy.json (schema, types) - this is a data error, not a waiver",
    "CANDIDATE_INVALID": "fix the candidate descriptor: schema, required keys and types",
    "NO_CANDIDATES": "stage a candidate descriptor in release/candidates/ before asking for GO",
    "ARTIFACT_NOT_FOUND": "build/stage the artifact referenced by artifact.path",
    "ARTIFACT_DIGEST_MISMATCH": "recompute sha256 and set artifact.sha256 to the artifact you actually built",
    "ARTIFACT_SIZE_MISMATCH": "recompute size_bytes; a truncated upload must be rebuilt, not re-pinned",
    "APPROVAL_MISSING": "obtain explicit operator approval with name, UTC timestamp and scope",
    "APPROVAL_PLACEHOLDER": "name the accountable human, not a role or 'approved'",
    "REVIEW_MISSING": "record an independent review (reviewer/author/ref); self-review is not review",
    "REVIEW_SELF": "have someone other than the author review the candidate",
    "PUBLISH_PATH_NOT_ALLOWED": "publish only under an allowed root from the policy",
    "OTA_FIELD_MISSING": "complete the manifest; every required field is part of the OTA contract",
    "OTA_SCHEMA_INVALID": "set manifest.schema to the pinned manifest schema id",
    "OTA_NON_CANONICAL": "remove floats/unsupported types so the signed bytes are deterministic",
    "OTA_DEVICE_UNKNOWN": "enrol the device+hardware revision in the policy after a compatibility review",
    "OTA_CHANNEL_UNKNOWN": "use a channel declared in the policy",
    "OTA_IMAGE_DIGEST_MISMATCH": "the staged image does not match manifest.image_sha256; rebuild",
    "OTA_SIZE_MISMATCH": "manifest.size_bytes disagrees with the staged image",
    "OTA_ROLLBACK": "raise version/security_version above the published baseline; downgrades are refused",
    "OTA_KEY_UNKNOWN": "enrol the signing key id and its public key in the policy",
    "OTA_KEY_REVOKED": "sign with a current key; a revoked key can never publish",
    "OTA_KEY_EXPIRED": "rotate the signing key and re-sign; keys have a not_after date",
    "OTA_SIGNATURE_INVALID": "the manifest bytes do not verify against the pinned key; do not publish",
    "OTA_SIGNATURE_TOOL_MISSING": "install openssl in the release job; signatures are not trusted unverified",
    "APK_UNREADABLE": "the APK is not a readable zip; rebuild it",
    "APK_CRC_MISMATCH": "a zip entry is corrupt; rebuild the APK",
    "APK_NO_SIGNING_BLOCK": "sign the APK with apksigner (v2+); a v1-only APK is refused",
    "APK_V1_MISSING": "v1 (JAR) signature is absent; sign with apksigner so older devices can verify",
    "APK_PACKAGE_UNKNOWN": "enrol the applicationId in the policy with its ABI and versionCode floor",
    "APK_ROLLBACK": "versionCode must exceed the published baseline",
    "APK_ABI_NOT_ALLOWED": "ship only ABIs the policy allows for this package",
    "APK_ABI_MISMATCH": "the APK's real ABIs differ from the declared ABI set",
    "APK_CRYPTO_UNVERIFIED": "install apksigner in the release job; without it no APK can be approved",
    "APK_SIGNER_UNTRUSTED": "pin the signer certificate SHA-256 in the policy (key continuity), or refuse the release",
    "APK_CERT_MISMATCH": "the signing certificate does not match the declared pins; do not publish",
}

SECRET_KEY_HINT = re.compile(r"(?i)(secret|token|password|passphrase|private_key|apikey|api_key)")


class DataError(Exception):
    """Malformed policy/candidate input (exit 3), never a verdict."""


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(document: Any) -> bytes:
    """Deterministic serialization used for signing and for hash pins.

    Floats are rejected: two JSON writers can disagree about their rendering, which would
    silently change the bytes that were signed.
    """

    def _reject_floats(value: Any, path: str) -> None:
        if isinstance(value, float):
            raise DataError(f"non-canonical float at {path}; OTA manifests must use integers/strings")
        if isinstance(value, dict):
            for key, item in value.items():
                _reject_floats(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                _reject_floats(item, f"{path}[{index}]")

    _reject_floats(document, "$")
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_named_human(name: Any) -> bool:
    text = " ".join(str(name or "").strip().split())
    if not text or text.lower() in PLACEHOLDER_APPROVERS:
        return False
    if len(text) < 3:
        return False
    return not any(hint in text.lower() for hint in SECRET_KEY_HINT.pattern.strip("(?i)").split("|"))


def verify_openssl_signature(algorithm: str, public_key: Path, payload: bytes, signature: Path) -> tuple[bool, str]:
    """Return (ok, detail). A missing tool is a failure, never an assumption."""
    if not shutil.which("openssl"):
        return False, "openssl is not available; signatures cannot be verified on this host"
    if not public_key.exists():
        return False, f"pinned public key {public_key} is missing"
    if not signature.exists():
        return False, f"signature file {signature} is missing"
    algorithm = algorithm.lower()
    # openssl cannot read a pipe for -in/-signature in every version, so stage the exact
    # canonical bytes in a private temporary file instead of assuming stdin works.
    with tempfile.TemporaryDirectory(prefix="fr3k-sig-") as tmp:
        payload_path = Path(tmp) / "payload.bin"
        payload_path.write_bytes(payload)
        if algorithm == "ed25519":
            command = [
                "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                "-rawin", "-in", str(payload_path), "-sigfile", str(signature),
            ]
        elif algorithm in {"rsa-pkcs1v15-sha256", "ecdsa-p256-sha256"}:
            command = ["openssl", "dgst", "-sha256", "-verify", str(public_key),
                       "-signature", str(signature), str(payload_path)]
        else:
            return False, f"unsupported signature algorithm {algorithm!r}"
        proc = subprocess.run(command, capture_output=True, check=False, timeout=120)
    detail = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    return proc.returncode == 0, detail or f"openssl exited {proc.returncode}"


def apk_scheme_ids(apk: Path) -> list[str]:
    """Detect which APK Signature Scheme ids are present in the signing block."""
    data = apk.read_bytes()
    marker = data.rfind(APK_SIG_BLOCK_MAGIC)
    if marker < 0:
        return []
    block_end = marker + len(APK_SIG_BLOCK_MAGIC)
    if block_end + 8 > len(data):
        return []
    size_footer = int.from_bytes(data[marker - 8 : marker], "little")
    block_start = marker - size_footer + 8
    if block_start < 0 or int.from_bytes(data[block_start : block_start + 8], "little") != size_footer:
        return []
    position = block_start + 8
    schemes: list[str] = []
    while position + 12 <= marker - 8:
        pair_length = int.from_bytes(data[position : position + 8], "little")
        if pair_length <= 4:
            break
        pair_id = int.from_bytes(data[position + 8 : position + 12], "little")
        scheme = APK_SCHEME_IDS.get(pair_id)
        if scheme:
            schemes.append(scheme)
        position += 8 + pair_length
    return sorted(set(schemes))


def apk_abis(apk: Path) -> list[str]:
    abis: set[str] = set()
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            parts = PurePosixPath(name).parts
            if len(parts) >= 3 and parts[0] == "lib":
                abis.add(parts[1])
    return sorted(abis)


def run_apksigner(apk: Path, binary: str) -> tuple[bool, dict[str, Any], str]:
    """Run apksigner and return (verified, facts, detail)."""
    if not shutil.which(binary):
        return False, {}, f"{binary} is not installed; APK signature schemes cannot be verified here"
    proc = subprocess.run(
        [binary, "verify", "--verbose", "--print-certs", str(apk)],
        capture_output=True, check=False, timeout=180,
    )
    output = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    facts: dict[str, Any] = {"schemes": {}, "cert_sha256": []}
    for line in output.splitlines():
        match = re.search(r"Verified using (v[0-9.]+) scheme .*: (true|false)", line)
        if match:
            facts["schemes"][match.group(1)] = match.group(2) == "true"
        cert = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", line)
        if cert:
            facts["cert_sha256"].append(cert.group(1).lower())
        if "DOES NOT VERIFY" in line or line.strip().startswith("ERROR"):
            facts.setdefault("errors", []).append(line.strip()[:200])
    verified = proc.returncode == 0 and bool(facts["schemes"]) and all(facts["schemes"].values())
    return verified, facts, output.strip()[:4000] or f"apksigner exited {proc.returncode}"


class Gate:
    def __init__(self, policy: dict[str, Any], state: dict[str, Any], root: Path) -> None:
        self.policy = policy
        self.state = state
        self.root = root
        self.gaps: list[dict[str, Any]] = []

    # -- helpers -------------------------------------------------------
    def gap(self, code: str, candidate: str, detail: str) -> None:
        self.gaps.append({"code": code, "candidate": candidate, "detail": detail,
                          "remedy": GAP_REMEDIES.get(code, "no recorded remedy")})

    def _resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else (self.root / path)

    # -- candidate checks ---------------------------------------------
    def check(self, candidate: dict[str, Any], candidate_path: Path) -> dict[str, Any]:
        cid = str(candidate.get("id") or candidate_path.stem)
        artifact = candidate.get("artifact") or {}
        kind = artifact.get("type")
        facts: dict[str, Any] = {"id": cid, "type": kind, "checks": []}

        self._check_approval_review(candidate, cid, facts)
        path = Path(str(artifact.get("path", "")))
        target = self._resolve(str(artifact.get("path", "")))
        if not path.name or not target.is_file():
            self.gap("ARTIFACT_NOT_FOUND", cid, f"artifact {artifact.get('path')!r} is missing")
            return facts

        actual_sha = sha256_file(target)
        actual_size = target.stat().st_size
        if str(artifact.get("sha256", "")).lower() != actual_sha:
            self.gap("ARTIFACT_DIGEST_MISMATCH", cid, f"pinned {artifact.get('sha256')} != computed {actual_sha}")
        if _as_int(artifact.get("size_bytes"), -1) != actual_size:
            self.gap("ARTIFACT_SIZE_MISMATCH", cid, f"pinned {artifact.get('size_bytes')} != {actual_size} bytes")
        facts["sha256"] = actual_sha
        facts["size_bytes"] = actual_size

        publish_path = str(candidate.get("publish_path", ""))
        allowed_roots = [str(item) for item in self.policy.get("publish", {}).get("allowed_roots", [])]
        if not any(publish_path.startswith(root.rstrip("/") + "/") for root in allowed_roots):
            self.gap("PUBLISH_PATH_NOT_ALLOWED", cid, f"{publish_path!r} is outside {allowed_roots}")

        if kind == "ota_manifest":
            self._check_ota(candidate, cid, target, facts)
        elif kind == "apk":
            self._check_apk(candidate, cid, target, facts)
        else:
            self.gap("CANDIDATE_INVALID", cid, f"unknown artifact type {kind!r}")
        return facts

    def _check_approval_review(self, candidate: dict[str, Any], cid: str, facts: dict[str, Any]) -> None:
        approval = candidate.get("approval") or {}
        approver = str(approval.get("approved_by", ""))
        if not approver or not _is_named_human(approver):
            code = "APPROVAL_MISSING" if not approver else "APPROVAL_PLACEHOLDER"
            self.gap(code, cid, f"approved_by={approver!r} is not a named accountable human")
        if not str(approval.get("approved_at", "")).strip():
            self.gap("APPROVAL_MISSING", cid, "approved_at is required (UTC timestamp)")
        if str(approval.get("scope", "")).strip() not in {"publish", "staging"}:
            self.gap("APPROVAL_MISSING", cid, "scope must be 'publish' or 'staging'")
        facts["approved_by"] = approver

        review = candidate.get("review") or {}
        reviewer = str(review.get("reviewer", "")).strip()
        author = str(review.get("author", "")).strip()
        if not reviewer or not author or not str(review.get("ref", "")).strip():
            self.gap("REVIEW_MISSING", cid, "review.reviewer, review.author and review.ref are all required")
        elif reviewer.lower() == author.lower():
            self.gap("REVIEW_SELF", cid, f"reviewer and author are both {author!r}")

    def _check_ota(self, candidate: dict[str, Any], cid: str, target: Path, facts: dict[str, Any]) -> None:
        ota = self.policy.get("ota", {})
        manifest = candidate.get("manifest")
        if not isinstance(manifest, dict):
            self.gap("CANDIDATE_INVALID", cid, "candidate.manifest must be an object for an OTA candidate")
            return
        facts["device"] = manifest.get("device")
        facts["channel"] = manifest.get("channel")

        for field in OTA_REQUIRED_FIELDS:
            if field not in manifest or manifest[field] in ("", None):
                self.gap("OTA_FIELD_MISSING", cid, f"manifest.{field} is required")
        if manifest.get("schema") != MANIFEST_SCHEMA:
            self.gap("OTA_SCHEMA_INVALID", cid, f"expected {MANIFEST_SCHEMA}, got {manifest.get('schema')!r}")

        try:
            payload = canonical_bytes(manifest)
        except DataError as exc:
            self.gap("OTA_NON_CANONICAL", cid, str(exc))
            return
        facts["manifest_canonical_sha256"] = hashlib.sha256(payload).hexdigest()

        devices = ota.get("devices", {})
        device = str(manifest.get("device", ""))
        device_policy = devices.get(device)
        if not isinstance(device_policy, dict):
            self.gap("OTA_DEVICE_UNKNOWN", cid, f"device {device!r} is not enrolled in the policy")
        else:
            revisions = [str(item) for item in device_policy.get("hardware_revisions", [])]
            if revisions and str(manifest.get("hardware_revision", "")) not in revisions:
                self.gap("OTA_DEVICE_UNKNOWN", cid,
                         f"hardware_revision {manifest.get('hardware_revision')!r} not in {revisions}")
        channels = [str(item) for item in ota.get("channels", [])]
        if channels and str(manifest.get("channel", "")) not in channels:
            self.gap("OTA_CHANNEL_UNKNOWN", cid, f"channel {manifest.get('channel')!r} not in {channels}")

        image_value = str(manifest.get("image_url", ""))
        if image_value.startswith(("http://", "https://")):
            self.gap("OTA_IMAGE_DIGEST_MISMATCH", cid,
                     "image_url is remote; the gate verifies a staged image file, not a remote fetch")
        else:
            image = self._resolve(image_value) if image_value else None
            if image is None or not image.is_file():
                self.gap("OTA_FIELD_MISSING", cid, f"staged image {image_value!r} is missing")
            else:
                if sha256_file(image) != str(manifest.get("image_sha256", "")).lower():
                    self.gap("OTA_IMAGE_DIGEST_MISMATCH", cid, "staged image sha256 != manifest.image_sha256")
                if image.stat().st_size != _as_int(manifest.get("size_bytes"), -1):
                    self.gap("OTA_SIZE_MISMATCH", cid, "staged image size != manifest.size_bytes")

        # Anti-rollback against the published floor.
        baseline = (
            self.state.get("ota", {}).get(device, {}).get(str(manifest.get("channel", "")), {})
            if isinstance(self.state.get("ota"), dict) else {}
        )
        try:
            new_security = int(manifest.get("security_version"))
        except (TypeError, ValueError):
            new_security = -1
        if baseline:
            old_security = int(baseline.get("security_version", 0))
            if new_security <= old_security:
                self.gap("OTA_ROLLBACK", cid,
                         f"security_version {new_security} <= published floor {old_security}")
            if str(manifest.get("version", "")) == str(baseline.get("version", "")):
                self.gap("OTA_ROLLBACK", cid, f"version {manifest.get('version')!r} already published")

        # Signature.
        keys = ota.get("signing_keys", {})
        key_id = str(manifest.get("key_id", ""))
        key = keys.get(key_id)
        signature = candidate.get("signature") or {}
        if not isinstance(key, dict):
            self.gap("OTA_KEY_UNKNOWN", cid, f"key_id {key_id!r} is not enrolled in the policy")
            return
        if bool(key.get("revoked")):
            self.gap("OTA_KEY_REVOKED", cid, f"key {key_id!r} is revoked")
        not_after = str(key.get("not_after", "")).strip()
        if not_after:
            try:
                if date.fromisoformat(not_after) < _now().date():
                    self.gap("OTA_KEY_EXPIRED", cid, f"key {key_id!r} expired {not_after}")
            except ValueError:
                self.gap("POLICY_INVALID", cid, f"key {key_id!r} has an invalid not_after {not_after!r}")
        if str(signature.get("key_id", key_id)) != key_id:
            self.gap("OTA_SIGNATURE_INVALID", cid, "signature.key_id disagrees with manifest.key_id")
        if str(manifest.get("signature_algorithm", "")).lower() != str(key.get("algorithm", "")).lower():
            self.gap("OTA_SIGNATURE_INVALID", cid, "manifest.signature_algorithm disagrees with the pinned key")
        ok, detail = verify_openssl_signature(
            str(key.get("algorithm", "")),
            self._resolve(str(key.get("public_key_path", ""))),
            payload,
            self._resolve(str(signature.get("path", ""))),
        )
        facts["signature_verified"] = ok
        facts["signature_detail"] = detail[:300]
        if not ok:
            code = "OTA_SIGNATURE_TOOL_MISSING" if "not available" in detail else "OTA_SIGNATURE_INVALID"
            self.gap(code, cid, detail[:300])

    def _check_apk(self, candidate: dict[str, Any], cid: str, target: Path, facts: dict[str, Any]) -> None:
        apk_policy = self.policy.get("apk", {})
        declared = candidate.get("apk") or {}
        facts["package"] = declared.get("package")

        try:
            with zipfile.ZipFile(target) as archive:
                bad = archive.testzip()
                names = archive.namelist()
        except (zipfile.BadZipFile, OSError) as exc:
            self.gap("APK_UNREADABLE", cid, f"not a readable zip: {exc}")
            return
        if bad is not None:
            self.gap("APK_CRC_MISMATCH", cid, f"corrupt entry {bad}")
        v1 = [name for name in names if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not v1:
            self.gap("APK_V1_MISSING", cid, "no META-INF/*.RSA|DSA|EC (JAR signature) found")
        schemes = apk_scheme_ids(target)
        facts["schemes"] = schemes
        if not schemes:
            self.gap("APK_NO_SIGNING_BLOCK", cid, "no APK Signing Block v2/v3 scheme id found")
        if "v2" not in schemes and "v3" not in schemes:
            self.gap("APK_NO_SIGNING_BLOCK", cid, f"schemes present but no v2/v3: {schemes}")

        real_abis = apk_abis(target)
        facts["abis"] = real_abis
        declared_abis = sorted(str(item) for item in declared.get("abis", []))
        if declared_abis != real_abis:
            self.gap("APK_ABI_MISMATCH", cid, f"declared {declared_abis} != packaged {real_abis}")

        package = str(declared.get("package", ""))
        package_policy = (apk_policy.get("packages") or {}).get(package)
        if not isinstance(package_policy, dict):
            self.gap("APK_PACKAGE_UNKNOWN", cid, f"package {package!r} is not enrolled in the policy")
        else:
            allowed_abis = [str(item) for item in package_policy.get("allowed_abis", [])]
            for abi in real_abis:
                if abi not in allowed_abis:
                    self.gap("APK_ABI_NOT_ALLOWED", cid, f"ABI {abi!r} not in {allowed_abis}")
            floor = _as_int(package_policy.get("min_version_code"), 0)
            published = _as_int((self.state.get("apk", {}) or {}).get(package, {}).get("version_code"), 0)
            baseline = max(floor, published)
            version_code = _as_int(declared.get("version_code"), -1)
            if version_code <= baseline:
                self.gap("APK_ROLLBACK", cid, f"versionCode {version_code} <= baseline {baseline}")

        verified, apk_facts, detail = run_apksigner(target, str(apk_policy.get("apksigner", "apksigner")))
        facts["apksigner"] = {"verified": verified, "facts": apk_facts, "detail": detail[:300]}
        if not verified:
            self.gap("APK_CRYPTO_UNVERIFIED", cid, detail[:300])
            return
        trusted = {item.lower() for item in apk_policy.get("trusted_signer_cert_sha256", [])}
        certs = {item.lower() for item in apk_facts.get("cert_sha256", [])}
        facts["signer_cert_sha256"] = sorted(certs)
        if not certs:
            self.gap("APK_SIGNER_UNTRUSTED", cid, "apksigner reported no certificate digests")
        elif not certs & trusted:
            self.gap("APK_SIGNER_UNTRUSTED", cid,
                     "no signer certificate SHA-256 is pinned in the policy (key continuity not proven)")
        declared_cert = str(declared.get("signer_cert_sha256", "")).lower()
        if declared_cert and declared_cert not in certs:
            self.gap("APK_CERT_MISMATCH", cid, "declared signer certificate is not the real signer")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DataError(f"{label} {path} is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise DataError(f"{label} {path} must be a JSON object")
    return data


def evaluate(policy_path: Path, state_path: Path, candidates_dir: Path, root: Path) -> dict[str, Any]:
    policy = load_json(policy_path, "policy")
    if policy.get("schema") != POLICY_SCHEMA:
        raise DataError(f"policy schema must be {POLICY_SCHEMA}")
    state = load_json(state_path, "state") if state_path.exists() else {}

    gate = Gate(policy, state, root)
    candidate_files = sorted(candidates_dir.glob("*.json")) if candidates_dir.is_dir() else []
    facts: list[dict[str, Any]] = []
    for candidate_path in candidate_files:
        candidate = load_json(candidate_path, "candidate")
        if candidate.get("schema") != CANDIDATE_SCHEMA:
            gate.gap("CANDIDATE_INVALID", candidate_path.stem, f"expected schema {CANDIDATE_SCHEMA}")
            continue
        facts.append(gate.check(candidate, candidate_path))
    if not candidate_files:
        gate.gap("NO_CANDIDATES", "<none>", f"no candidate descriptors under {candidates_dir}")

    return {
        "schema": SCHEMA,
        "verdict": "GO" if not gate.gaps else "BLOCKED",
        "evaluated_at": _now().isoformat(),
        "inputs": {
            "policy": str(policy_path),
            "policy_sha256": sha256_file(policy_path),
            "state_sha256": sha256_file(state_path) if state_path.exists() else None,
            "candidates": [path.name for path in candidate_files],
        },
        "candidates": facts,
        "gap_count": len(gate.gaps),
        "gaps": gate.gaps,
        "notes": [
            "Claimed verdicts in a candidate descriptor never influence this decision.",
            "Signature verification is delegated to openssl (OTA) and apksigner (APK); a missing tool blocks.",
        ],
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed OTA/APK pre-publication release gate")
    parser.add_argument("--policy", type=Path, default=Path("control/release-policy.json"))
    parser.add_argument("--state", type=Path, default=Path("control/release-state/baseline.json"))
    parser.add_argument("--candidates", type=Path, default=Path("release/candidates"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        report = evaluate(args.policy, args.state, args.candidates, args.root)
    except DataError as exc:
        print(json.dumps({"schema": SCHEMA, "verdict": "ERROR", "gaps": [],
                          "problems": [str(exc)]}, indent=2))
        return EXIT_DATA_ERROR

    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return EXIT_GO if report["verdict"] == "GO" else EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
