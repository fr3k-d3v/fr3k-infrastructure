# P0 release gates: BLACKWAVE OTA manifests, Android APKs, credentials

Scope: issue #3 gates **D6** (Android APK release), the distribution half of **D5** (signed
BLACKWAVE OTA), and the **credential hygiene** item ("ensure no secrets in Git/issues").
Nothing here deploys, signs on the VPS, flashes hardware, or publishes an artifact.

The two gates enforce, mechanically, what the Contabo plan already requires in prose:

| Gate | Module | Question it answers |
|---|---|---|
| OTA/APK release | `fr3k_control/release_gate.py` | May this exact artifact be published on `downloads.*` / `ota.*`? |
| Credentials | `fr3k_control/secrets_gate.py` | Does this repository - now or anywhere in its history - contain a credential that must not be public? |

Both follow the repository's existing decision contract: **exit 0 = GO**, **exit 2 =
BLOCKED (a verdict with a gap list)**, **exit 3 = data error**. A crash never reads as a
pass, and BLOCKED never reads as success.

## 1. `release_gate.py` - pre-publication gate

Inputs are all in Git, so the gate can be run by CI, by the operator before an upload, and
by an auditor after the fact:

* `control/release-policy.json` - enrolment: allowed publish roots, OTA devices/channels,
  trusted OTA signing keys (`algorithm`, `public_key_path`, `not_after`, `revoked`), APK
  packages with allowed ABIs and a `versionCode` floor, and pinned APK signer certificate
  SHA-256 digests.
* `control/release-state/baseline.json` - the anti-rollback floor per device/channel and per
  package. It is bumped only after a release has actually been published and read back.
* `release/candidates/*.json` - one descriptor per artifact: digest/size pins, the manifest,
  the signature reference, the operator approval and the review record.

What is checked mechanically:

**Every candidate** - artifact exists; `sha256` and `size_bytes` match the staged file; the
publish path is under an allowed root; a named human approved it with a UTC timestamp and a
scope; an independent review exists with reviewer != author.

**OTA manifest** - all required contract fields present; `schema` pinned; the manifest is
serialised canonically (sorted keys, no floats - a float would make "the bytes that were
signed" ambiguous); device, hardware revision and channel enrolled in the policy; the staged
image's SHA-256 and size match the manifest; `security_version` and `version` are above the
published floor (anti-rollback); the signing key is enrolled, not revoked and not expired;
`signature_algorithm` agrees with the pinned key; and the signature is **actually verified**
with `openssl` over the canonical bytes (Ed25519 via `pkeyutl -rawin`, ECDSA-P256/RSA-2048
via `dgst -sha256 -verify`).

**APK** - readable zip with all entry CRCs intact; a real APK Signing Block with a v2 and/or
v3 scheme id; a v1 (JAR) signature present; packaged ABIs read from `lib/<abi>/` and compared
with the declared set and the policy allow-list; `versionCode` above the floor; and
`apksigner verify --verbose --print-certs` must report verification success with a
certificate SHA-256 **pinned in the policy** (key continuity).

### Why the gate can refuse even when everything "looks" signed

* **A signature file is not evidence.** Without `openssl` the OTA branch reports
  `OTA_SIGNATURE_TOOL_MISSING`; without `apksigner` the APK branch reports
  `APK_CRYPTO_UNVERIFIED`. Both block.
* **No pins, no release.** The shipped policy has no OTA signing key and no APK signer
  certificate, so no real artifact can reach GO until an operator enrols a public key or a
  certificate digest in a reviewed commit.
* **Claims are ignored.** `claimed_verdicts` in a descriptor never enters the decision, and
  self-review is a gap (`REVIEW_SELF`), not a formality.
* **An empty staging area is BLOCKED**, not vacuously green (`NO_CANDIDATES`).

Every gap code has a remedy row in `GAP_REMEDIES` (rendered into the JSON report), so a
BLOCKED result is actionable rather than noise.

## 2. `secrets_gate.py` - credential gate

Scans the working tree **and** every blob reachable from every ref (`git rev-list --objects
--all` + `git cat-file --batch`), which is what catches a credential that was committed and
then deleted.

* Format rules with validation: GitHub tokens/`github_pat_`, AWS access key ids, Slack,
  Stripe live, Anthropic, OpenAI-style, Google API keys, JWTs, PEM private-key blocks,
  credential-shaped assignments, and a constrained high-entropy rule (base64-ish only, >= 3
  character classes, Shannon entropy >= 4.2 - so URLs, filenames, hex digests and long
  identifiers stay silent). Path rules: `.env*` files and `*.jks/keystore/p12/pfx`.
* **Redaction is structural.** Findings carry `rule`, `location` and a 12-hex SHA-256
  fingerprint of the value; the value itself is never written, because the report is
  committed as evidence.
* **Waivers are bounded.** `control/secrets-allowlist.json` entries need a >= 10 character
  reason and an `expires` date; an expired waiver is ignored and reported as a problem. A
  PEM private-key block, a keystore file and a `.env` file are **non-waivable** - the remedy
  is rotation, not paperwork.
* Overlapping matches are de-duplicated so one token produces one finding, not three.

## 3. Wiring

```bash
python -m fr3k_control.secrets_gate --repo . --history                 # 0 clean / 2 findings / 3 error
python -m fr3k_control.release_gate --candidates release/candidates     # 0 GO / 2 BLOCKED / 3 data error
```

CI runs the suite and both gates (a BLOCKED result is expected and asserted as exit 2 while
no candidate exists and no key is enrolled).

## 4. Status of the underlying gates (unchanged by this PR)

| Gate | Status | Why |
|---|---|---|
| D5 signed BLACKWAVE OTA | **BLOCKED** | No signing key enrolled, no firmware/OTA inspection done, no device-side verification demonstrated. The gate exists; the trust anchor and the real manifest do not. |
| D6 Android APK release | **BLOCKED** | No signed APK exists; no signer certificate can be pinned; no physical clean-install/upgrade test. |
| Credential hygiene | **VERIFIED (this repository)** | 0 findings across the tree and all history blobs. This proves *this* repo, not the operator's password storage or the Gitea instance. |

The remaining D5/D6 work is human-gated and cannot be produced on this host: signing keys
must never live on the VPS or in CI, and both gates require a physical device (canary OTA,
APK install/upgrade) plus an authorised signed build.

## 5. Non-goals

* No APK is built, signed or published here; no OTA manifest is signed with a real key.
* The gate does not talk to the distribution host - it verifies a *staged* artifact before
  upload. Post-upload read-back (served hash == approved hash) remains an operator step.
* `apksigner`'s own output is trusted only as far as its exit code plus the pinned
  certificate digest; the gate does not reimplement Android signature scheme cryptography.
