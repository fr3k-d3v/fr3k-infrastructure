"""Verification receipts with strict reuse conditions.

Adopted from the oh-my-hermes evidence model: an executor reporting that a
job finished is never the same as the result having been checked. A receipt
records what ran, where, and what was actually observed. A receipt may be
reused as evidence only when the revision, the exact command and the
environment all match again on replay; any mismatch makes it STALE and the
work must be re-produced.

Every receipt carries a two-part status: the stage (what happened) and the
evidence basis (how sure we are). The strongest basis a receipt can declare
is bounded by what was observed, never by what the producer claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RECEIPT_VERSION = 1

# Evidence basis ladder, ordered weakest to strongest. A receipt whose
# strongest basis is process_exit alone stays "reported done": the command
# exited zero but nothing checked the result.
EVIDENCE_LADDER = ("process_exit", "schema_valid", "verification_observed", "integration_ready")

# Stage and basis are coupled: basis process_exit means nobody checked the
# result, so the stage is reported_done. Any observed check (schema or
# stronger) promotes the stage to verified.
REPORTED_DONE_BASIS = "process_exit"
VERIFIED_MIN_BASIS = "schema_valid"

STATUS_STAGES = ("plan_not_run", "running", "reported_done", "verified")

REQUIRED_FIELDS = (
    "receipt_version",
    "name",
    "created_at",
    "revision",
    "command",
    "environment_hash",
    "result",
    "status_stage",
    "evidence_basis",
    "producer",
    "signature",
)


def _canonical(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def environment_hash() -> str:
    """Stable hash of the execution environment a receipt was produced in."""
    snapshot = {
        "python_version": sys.version.split()[0],
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "hostname": socket.gethostname(),
    }
    return "sha256:" + hashlib.sha256(_canonical(snapshot).encode()).hexdigest()


def resolve_revision(path: Path) -> str:
    """Resolve the current HEAD commit of the git repository at path."""
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True
    )
    if out.returncode != 0:
        raise ValueError(f"not a git repository or no commit: {path}")
    return out.stdout.strip()


def sign(body: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    return "sha256:" + hashlib.sha256(_canonical(unsigned).encode()).hexdigest()


def stage_for_basis(basis: str) -> str:
    return "reported_done" if basis == REPORTED_DONE_BASIS else "verified"


def create_receipt(
    name: str,
    command: str,
    revision: str,
    evidence_basis: str,
    result: dict[str, Any],
    artifacts: list[dict[str, str]],
    producer: str,
) -> dict[str, Any]:
    if evidence_basis not in EVIDENCE_LADDER:
        raise ValueError(
            f"evidence basis must be one of {', '.join(EVIDENCE_LADDER)}: {evidence_basis}"
        )
    body: dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "name": name,
        "created_at": _now(),
        "revision": revision,
        "command": command,
        "environment_hash": environment_hash(),
        "result": result,
        "artifacts": artifacts,
        "status_stage": stage_for_basis(evidence_basis),
        "evidence_basis": evidence_basis,
        "producer": producer,
    }
    body["signature"] = sign(body)
    return body


def validate_receipt(receipt: dict[str, Any], base_dir: Path) -> list[str]:
    """Return every consistency error found; an empty list means valid."""
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in receipt:
            errors.append(f"missing field: {field}")
    if errors:
        return errors

    if receipt["receipt_version"] != RECEIPT_VERSION:
        errors.append(f"unsupported receipt_version: {receipt['receipt_version']}")
    if receipt["evidence_basis"] not in EVIDENCE_LADDER:
        errors.append(f"unknown evidence_basis: {receipt['evidence_basis']}")
    if receipt["status_stage"] not in STATUS_STAGES:
        errors.append(f"unknown status_stage: {receipt['status_stage']}")
    else:
        stage, basis = receipt["status_stage"], receipt["evidence_basis"]
        if basis == REPORTED_DONE_BASIS and stage != "reported_done":
            errors.append(
                f"basis {basis} means nobody checked the result; stage must be reported_done, got {stage}"
            )
        if basis != REPORTED_DONE_BASIS and stage != "verified":
            errors.append(
                f"basis {basis} means a check ran; stage must be verified, got {stage}"
            )

    result = receipt.get("result")
    if not isinstance(result, dict) or "exit_code" not in result:
        errors.append("result must be an object with exit_code")
    else:
        if stage_for_basis(receipt["evidence_basis"]) == "verified" and result["exit_code"] != 0:
            errors.append("verified receipts require result.exit_code == 0")

    if not isinstance(receipt.get("command"), str) or not receipt["command"].strip():
        errors.append("command must be a non-empty string")
    if not isinstance(receipt.get("revision"), str) or not receipt["revision"].strip():
        errors.append("revision must be a non-empty string")

    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifacts must be a list")
    else:
        for item in artifacts:
            if not isinstance(item, dict) or "path" not in item or "sha256" not in item:
                errors.append(f"artifact entry missing path or sha256: {item}")
                continue
            artifact = Path(item["path"])
            target = artifact if artifact.is_absolute() else base_dir / artifact
            if not target.is_file():
                errors.append(f"artifact missing on disk: {item['path']}")
            else:
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
                if digest != item["sha256"]:
                    errors.append(f"artifact hash mismatch: {item['path']}")

    expected = sign(receipt)
    if receipt["signature"] != expected:
        errors.append("signature mismatch: receipt body was modified after creation")
    return errors


def check_reuse(
    receipt: dict[str, Any],
    revision: str,
    command: str,
    environment: str,
) -> dict[str, Any]:
    """Decide whether a receipt may be reused as evidence for a replay.

    A receipt is REUSABLE only when the revision, the exact command and the
    environment hash all match again. Any mismatch is STALE.
    """
    reasons: list[str] = []
    if receipt.get("revision") != revision:
        reasons.append(f"revision changed: receipt {receipt.get('revision')} vs current {revision}")
    if receipt.get("command") != command:
        reasons.append("command differs from the receipt's exact command")
    if receipt.get("environment_hash") != environment:
        reasons.append("environment changed: receipt was produced in a different environment")
    verdict = "STALE" if reasons else "REUSABLE"
    return {
        "verdict": verdict,
        "reasons": reasons,
        "checked": {
            "revision": revision,
            "command": command,
            "environment_hash": environment,
        },
        "receipt_name": receipt.get("name"),
        "status_stage": receipt.get("status_stage"),
        "evidence_basis": receipt.get("evidence_basis"),
    }


def _hash_artifact(path: Path, base_dir: Path) -> dict[str, str]:
    target = path if path.is_absolute() else base_dir / path
    if not target.is_file():
        raise ValueError(f"artifact not found: {target}")
    return {"path": str(path), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}


def _load(path: Path) -> dict[str, Any]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("receipt file must contain a JSON object")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr3k_control.receipts", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="create a receipt for a completed command run")
    p_create.add_argument("--name", required=True)
    p_create.add_argument("--command", required=True, help="the exact command that was run")
    p_create.add_argument("--revision", default=None, help="git commit SHA (default: HEAD of cwd)")
    p_create.add_argument(
        "--evidence-basis",
        default=REPORTED_DONE_BASIS,
        choices=EVIDENCE_LADDER,
        help="strongest basis actually observed (default: process_exit)",
    )
    p_create.add_argument("--exit-code", type=int, required=True)
    p_create.add_argument("--summary", default="")
    p_create.add_argument("--artifact", action="append", default=[], help="path relative to base dir")
    p_create.add_argument("--producer", required=True)
    p_create.add_argument("--output", default=None, help="write receipt JSON here (default: stdout)")

    p_verify = sub.add_parser("verify", help="validate a receipt's structure, hashes and signature")
    p_verify.add_argument("receipt", type=Path)
    p_verify.add_argument("--base-dir", type=Path, default=Path.cwd())

    p_reuse = sub.add_parser("check-reuse", help="decide whether a receipt is reusable as evidence")
    p_reuse.add_argument("receipt", type=Path)
    p_reuse.add_argument("--revision", default=None, help="current revision (default: HEAD of cwd)")
    p_reuse.add_argument("--command", required=True)
    p_reuse.add_argument(
        "--environment-hash", default=None, help="current environment hash (default: computed)"
    )

    args = parser.parse_args(argv)

    try:
        if args.cmd == "create":
            revision = args.revision or resolve_revision(Path.cwd())
            artifacts = [_hash_artifact(Path(p), Path.cwd()) for p in args.artifact]
            receipt = create_receipt(
                name=args.name,
                command=args.command,
                revision=revision,
                evidence_basis=args.evidence_basis,
                result={"exit_code": args.exit_code, "summary": args.summary},
                artifacts=artifacts,
                producer=args.producer,
            )
            text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            if args.output:
                out = Path(args.output)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(text, encoding="utf-8")
                print(f"receipt written: {out}")
            else:
                print(text, end="")
            return 0

        if args.cmd == "verify":
            errors = validate_receipt(_load(args.receipt), args.base_dir)
            if errors:
                for error in errors:
                    print(f"INVALID: {error}", file=sys.stderr)
                return 1
            print(f"VALID: {args.receipt}")
            return 0

        if args.cmd == "check-reuse":
            receipt = _load(args.receipt)
            errors = validate_receipt(receipt, Path.cwd())
            if errors:
                for error in errors:
                    print(f"INVALID: {error}", file=sys.stderr)
                return 1
            revision = args.revision or resolve_revision(Path.cwd())
            environment = args.environment_hash or environment_hash()
            verdict = check_reuse(receipt, revision, args.command, environment)
            print(json.dumps(verdict, indent=2, sort_keys=True))
            return 0 if verdict["verdict"] == "REUSABLE" else 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
