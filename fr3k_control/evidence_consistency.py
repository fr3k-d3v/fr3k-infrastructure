"""Verify generated gate evidence without treating run timestamps as state changes.

The evaluation timestamp is run-specific provenance. All decision fields remain
byte-independent but semantically exact, including every blocker and control.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class EvidenceMismatch(ValueError):
    """Generated evidence is invalid, stale, or substantively different."""


def _timestamp(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceMismatch(f"{name} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceMismatch(f"{name} is not an ISO8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EvidenceMismatch(f"{name} must use UTC")
    return parsed.astimezone(timezone.utc)


def compare_gate_evidence(
    committed: dict[str, Any],
    generated: dict[str, Any],
    *,
    now: datetime | None = None,
    freshness: timedelta = timedelta(minutes=15),
) -> None:
    """Require a freshly evaluated result identical in every decision field.

    Committed timestamps can legitimately be historical; generated timestamps
    must come from the current invocation. Do not weaken G0 verdict or controls.
    """
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    older = _timestamp(committed.get("evaluated_at"), name="committed.evaluated_at")
    recent = _timestamp(generated.get("evaluated_at"), name="generated.evaluated_at")
    if older > current + timedelta(minutes=2):
        raise EvidenceMismatch("committed evidence claims a future timestamp")
    if not (-timedelta(minutes=2) <= (current - recent) <= freshness):
        raise EvidenceMismatch("generated evidence timestamp is not fresh")

    baseline = {k: v for k, v in committed.items() if k != "evaluated_at"}
    observed = {k: v for k, v in generated.items() if k != "evaluated_at"}
    if baseline != observed:
        raise EvidenceMismatch(
            "G0 substantive results differ from committed evidence: "
            "review blockers, owners, controls and verdict before merging"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--committed-ref", default="HEAD:evidence/g0-result.json",
        help="Exact Git blob ref of the previously committed evidence",
    )
    parser.add_argument(
        "--generated", type=Path, default=Path("evidence/g0-result.json"),
    )
    args = parser.parse_args()
    try:
        old = json.loads(
            subprocess.check_output(["git", "show", args.committed_ref], text=True)
        )
        new = json.loads(args.generated.read_text(encoding="utf-8"))
        compare_gate_evidence(old, new)
    except (EvidenceMismatch, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"G0 EVIDENCE BLOCKED: {exc}", file=sys.stderr)
        return 1
    print("G0 substantive evidence unchanged; new UTC evaluation timestamp verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
