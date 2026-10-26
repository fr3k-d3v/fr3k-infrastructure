"""Fail-closed credential scanner for the FR3K infrastructure control plane.

The gate answers one question: *does this repository, at this commit or anywhere in
its history, contain a credential that must not be public?*  It is deliberately
conservative in two directions:

* a finding is only reported when the matched value passes the rule's own format
  validation, so the report stays actionable instead of being entropy noise;
* nothing sensitive is ever printed.  Findings carry a rule id, a location and a
  truncated SHA-256 *fingerprint* of the value, never the value itself, because the
  gate's own output is committed as evidence.

Exit codes carry the contract (same convention as ``fr3k_control.gate``):

* ``0`` - GO: no findings.
* ``2`` - BLOCKED: at least one finding (or an expired allowlist entry hiding one).
* ``3`` - data error: not a repository, unreadable tree, malformed allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = "fr3k.secrets.report/v1"
ALLOWLIST_SCHEMA = "fr3k.secrets.allowlist/v1"
EXIT_GO = 0
EXIT_BLOCKED = 2
EXIT_DATA_ERROR = 3

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "node_modules"}

# Rules whose findings can never be waived: a committed private key is a rotation,
# not a discussion.  Everything else may be allowlisted with a reason and an expiry.
NON_WAIVABLE = frozenset({"private-key-block", "android-keystore-file", "dotenv-file"})

PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change_me",
    "example",
    "placeholder",
    "redacted",
    "todo",
    "none",
    "null",
    "your_key",
    "your_key_here",
    "your_token_here",
    "xxxx",
}

_PRIVATE_KEY_HEADER = "-----BEGIN " + r"(?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE" + r" KEY-----"


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    description: str
    validate: bool = False

    def looks_like_placeholder(self, value: str) -> bool:
        return looks_like_placeholder(value)


def looks_like_placeholder(value: str) -> bool:
    token = value.strip().strip("\"'`")
    lowered = token.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if lowered.startswith(("your_", "your-", "example_", "sample_", "fake_", "dummy_")):
        return True
    if token and set(token) <= {"x", "X", "0", "*", ".", "-"}:
        return True
    if token.startswith(("$", "${", "<", "%")) or token.endswith((">", "}")):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]*(?:changeme|placeholder|example|redacted|dummy|sample)[A-Za-z0-9_.-]*",
                    lowered or "x"):
        return True
    return False


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


RULES: tuple[Rule, ...] = (
    Rule("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
         "GitHub personal access / app token"),
    Rule("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), "AWS access key id"),
    Rule("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token"),
    Rule("stripe-live-key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "Stripe live secret key"),
    Rule("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "Anthropic API key"),
    Rule("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), "OpenAI-style secret key"),
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JSON Web Token"),
    Rule("private-key-block", re.compile(_PRIVATE_KEY_HEADER), "PEM private key block"),
    Rule(
        "generic-assignment",
        # name = "value" / name: value  -- value must be long enough to be a real credential
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
            r"|client[_-]?secret|auth[_-]?key|signing[_-]?key)\b\s*[:=]\s*"
            r"(?P<value>\"[^\"\n]{12,200}\"|'[^'\n]{12,200}'|[A-Za-z0-9/+_\-.]{16,200})"
        ),
        "credential-shaped assignment",
        validate=True,
    ),
    Rule(
        "high-entropy-token",
        # Base64/hex-ish only: dashes, dots and underscores mean a filename, path or shell
        # expansion, which is noise rather than a credential.
        re.compile(r"(?<![A-Za-z0-9+/=])(?P<value>[A-Za-z0-9+/=]{32,200})(?![A-Za-z0-9+/=])"),
        "high-entropy opaque token",
        validate=True,
    ),
    Rule("dotenv-file", re.compile(r"(?m)^[A-Z0-9_]{3,}\s*=\s*\S+"), "dotenv-style file with live values"),
    Rule("android-keystore-file", re.compile(r"\A(?:binary|text)\z"), "Android/Java signing keystore"),
    Rule("apk-signing-properties", re.compile(r"(?im)^\s*(?:storePassword|keyPassword|storeFile)\s*="),
         "APK keystore credentials"),
)

# Path-scoped rules: the rule id applies when the *path* matches, regardless of content.
PATH_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dotenv-file", re.compile(r"(^|/)\.env(\.(?!example$|sample$|template$)[A-Za-z0-9_.-]+)?$")),
    ("android-keystore-file", re.compile(r"(?i)\.(?:jks|keystore|p12|pfx)$")),
)

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz",
    ".woff", ".woff2", ".ttf", ".otf", ".so", ".dll", ".exe", ".apk", ".aab", ".jar", ".db", ".sqlite",
    ".xlsx", ".docx", ".pptx", ".pyc", ".bin", ".der", ".pem.der",
}


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _validate_generic(value: str, text: str = "", start: int = 0) -> bool:
    token = value.strip().strip("\"'`")
    if len(token) < 12:
        return False
    if looks_like_placeholder(token):
        return False
    has_digit = any(char.isdigit() for char in token)
    has_alpha = any(char.isalpha() for char in token)
    return has_digit and has_alpha


def _validate_entropy(value: str, text: str = "", start: int = 0) -> bool:
    token = value.strip()
    if looks_like_placeholder(token):
        return False
    if text and start:
        window = text[max(0, start - 200) : start]
        if re.search(r"[A-Za-z][A-Za-z0-9+.-]*://\S*$", window):
            return False  # part of a URL, not a credential
    if re.fullmatch(r"[0-9a-fA-F]+", token):  # hex digests are legitimate evidence
        return False
    if re.fullmatch(r"[0-9]+", token) or re.fullmatch(r"[A-Za-z]+", token):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", token):
        return False  # identifier / dotted name, e.g. a long snake_case test name
    classes = sum(
        (
            any(char.isupper() for char in token),
            any(char.islower() for char in token),
            any(char.isdigit() for char in token),
            any(char in "+/=" for char in token),
        )
    )
    if classes < 3:
        return False
    return _shannon_entropy(token) >= 4.2


VALIDATORS = {"generic-assignment": _validate_generic, "high-entropy-token": _validate_entropy}


@dataclass
class Finding:
    rule: str
    location: str
    detail: str
    fingerprint: str
    value_length: int
    allowlisted: bool = False
    allowlist_note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {
            "rule": self.rule,
            "location": self.location,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
            "value_length": self.value_length,
            "allowlisted": self.allowlisted,
        }
        if self.allowlist_note:
            data["allowlist_note"] = self.allowlist_note
        return data


@dataclass
class Allowlist:
    entries: list[dict[str, Any]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Allowlist":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != ALLOWLIST_SCHEMA:
            raise ValueError(f"allowlist schema must be {ALLOWLIST_SCHEMA}")
        entries = data.get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("allowlist entries must be a list")
        return cls(entries=entries)

    def match(self, finding: Finding, today: date) -> str | None:
        """Return a note when the finding is covered by a live waiver, else None."""
        if finding.rule in NON_WAIVABLE:
            return None
        path = finding.location.split(":", 1)[1] if ":" in finding.location else finding.location
        for entry in self.entries:
            if entry.get("rule") not in (finding.rule, "*"):
                continue
            prefix = str(entry.get("path", "")).strip()
            if prefix and not path.startswith(prefix):
                continue
            fingerprint = entry.get("fingerprint")
            if fingerprint not in (None, finding.fingerprint):
                continue
            reason = str(entry.get("reason", "")).strip()
            if len(reason) < 10:
                self.problems.append("allowlist entry without a >=10 character reason")
                continue
            try:
                expires = date.fromisoformat(str(entry.get("expires")))
            except ValueError:
                self.problems.append(f"allowlist entry has an invalid expires date: {entry.get('expires')!r}")
                continue
            if expires < today:
                self.problems.append(f"allowlist entry expired {expires.isoformat()} and was ignored")
                continue
            return f"waived until {expires.isoformat()}: {reason}"
        return None


def _iter_tree_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _read_text(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(path_label: str, text: str, allowlist: Allowlist, today: date) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    claimed: list[tuple[int, int]] = []
    lines = text.splitlines() or [""]

    for rule_id, path_pattern in PATH_RULES:
        if path_pattern.search(path_label):
            value = text.strip()
            finding = Finding(
                rule=rule_id,
                location=f"tree:{path_label}",
                detail=f"path matches {rule_id} rule",
                fingerprint=_fingerprint(value),
                value_length=len(value),
            )
            _apply_allowlist(finding, allowlist, today)
            findings.append(finding)

    for rule in RULES:
        if rule.id in {"dotenv-file", "android-keystore-file"}:
            continue
        for match in rule.pattern.finditer(text):
            if any(match.start() < end and match.end() > start for start, end in claimed):
                continue  # a more specific rule already reported this span
            value = match.group("value") if "value" in (match.re.groupindex or {}) else match.group(0)
            if rule.validate:
                validator = VALIDATORS.get(rule.id)
                if validator and not validator(value, text, match.start()):
                    continue
            elif rule.looks_like_placeholder(value):
                continue
            line_no = text.count("\n", 0, match.start()) + 1
            key = (rule.id, _fingerprint(value))
            if key in seen:
                continue
            seen.add(key)
            claimed.append((match.start(), match.end()))
            finding = Finding(
                rule=rule.id,
                location=f"tree:{path_label}:{line_no}",
                detail=rule.description,
                fingerprint=_fingerprint(value),
                value_length=len(value),
            )
            _apply_allowlist(finding, allowlist, today)
            findings.append(finding)
    return findings


def _apply_allowlist(finding: Finding, allowlist: Allowlist, today: date) -> None:
    note = allowlist.match(finding, today)
    if note:
        finding.allowlisted = True
        finding.allowlist_note = note


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, check=False, timeout=600
    )


def scan_working_tree(root: Path, allowlist: Allowlist, today: date) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_tree_files(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        text = _read_text(path)
        if text is None:
            continue
        findings.extend(scan_text(rel, text, allowlist, today))
    return findings


def _history_blobs(root: Path) -> tuple[list[tuple[str, str]], str | None]:
    """Return [(blob_oid, path)] across every ref, plus an optional error string."""
    listing = _git(root, "rev-list", "--objects", "--all")
    if listing.returncode != 0:
        return [], listing.stderr.decode("utf-8", "replace").strip() or "git rev-list failed"
    blobs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_line in listing.stdout.decode("utf-8", "replace").splitlines():
        parts = raw_line.split(" ", 1)
        oid = parts[0].strip()
        if not oid or oid in seen:
            continue
        seen.add(oid)
        blobs.append((oid, parts[1] if len(parts) > 1 else ""))
    return blobs, None


def _cat_file_batch(root: Path, oids: list[str]) -> tuple[dict[str, bytes], str | None]:
    if not oids:
        return {}, None
    payload = ("\n".join(oids) + "\n").encode()
    proc = subprocess.run(
        ["git", "cat-file", "--batch"], cwd=str(root), input=payload, capture_output=True, check=False, timeout=900
    )
    if proc.returncode != 0:
        return {}, proc.stderr.decode("utf-8", "replace").strip() or "git cat-file failed"
    data = proc.stdout
    out: dict[str, bytes] = {}
    index = 0
    while index < len(data):
        newline = data.find(b"\n", index)
        if newline == -1:
            break
        header = data[index:newline].decode("utf-8", "replace").split()
        index = newline + 1
        if len(header) < 3:
            break  # "<oid> missing"
        oid, obj_type, size_text = header[0], header[1], header[2]
        size = int(size_text)
        body = data[index : index + size]
        index += size + 1
        if obj_type == "blob" and size <= MAX_FILE_BYTES and b"\x00" not in body[:4096]:
            out[oid] = body
    return out, None


def scan_history(root: Path, allowlist: Allowlist, today: date) -> tuple[list[Finding], list[str]]:
    problems: list[str] = []
    blobs, error = _history_blobs(root)
    if error:
        problems.append(f"history scan unavailable: {error}")
        return [], problems
    oids = [oid for oid, _ in blobs]
    contents, cat_error = _cat_file_batch(root, oids)
    if cat_error:
        problems.append(f"history scan incomplete: {cat_error}")
    findings: list[Finding] = []
    for oid, path in blobs:
        body = contents.get(oid)
        if body is None:
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        label = path or "<unnamed>"
        for finding in scan_text(label, text, allowlist, today):
            finding.location = finding.location.replace(f"tree:{label}", f"history:{label}@{oid[:12]}")
            findings.append(finding)
    return findings, problems


def evaluate(root: Path, allowlist_path: Path | None, history: bool, today: date | None = None) -> dict[str, Any]:
    today = today or datetime.now(timezone.utc).date()
    allowlist = Allowlist.load(allowlist_path) if allowlist_path else Allowlist()
    findings = scan_working_tree(root, allowlist, today)
    problems: list[str] = list(allowlist.problems)
    if history:
        history_findings, history_problems = scan_history(root, allowlist, today)
        findings.extend(history_findings)
        problems.extend(history_problems)

    blocking = [finding for finding in findings if not finding.allowlisted]
    waived_breakdown: dict[str, int] = {}
    for finding in findings:
        if finding.allowlisted:
            waived_breakdown[finding.rule] = waived_breakdown.get(finding.rule, 0) + 1
    return {
        "schema": SCHEMA,
        "verdict": "GO" if not blocking and not problems else "BLOCKED",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {"root": str(root), "history": history},
        "counts": {
            "findings": len(findings),
            "blocking": len(blocking),
            "waived": len(findings) - len(blocking),
        },
        "waived_by_rule": waived_breakdown,
        "findings": [finding.as_dict() for finding in findings],
        "problems": problems,
        "notes": [
            "Findings never contain the matched value: only a truncated SHA-256 fingerprint.",
            f"Non-waivable rules: {', '.join(sorted(NON_WAIVABLE))}.",
        ],
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed credential scan for a git repository")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--allowlist", type=Path, default=None)
    parser.add_argument("--history", action="store_true", help="also scan every blob reachable from any ref")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = args.repo.resolve()
    if not (root / ".git").exists():
        print(json.dumps({"schema": SCHEMA, "verdict": "ERROR", "problems": [f"{root} is not a git repository"]}))
        return EXIT_DATA_ERROR
    try:
        report = evaluate(root, args.allowlist, args.history)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": SCHEMA, "verdict": "ERROR", "problems": [str(exc)]}))
        return EXIT_DATA_ERROR

    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return EXIT_GO if report["verdict"] == "GO" else EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
