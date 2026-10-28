# FR3K Infrastructure

Operational control plane for **Free Communications. Open Infrastructure. AI Driven. Community Built.**

This repository converts Implementation Pack v1.1 into executable gates and evidence. It does **not** authorise RF transmission, procurement, or field deployment.

## Current status

- Pack checksum integrity: PASS
- Pack operational consistency: BLOCKED
- G0 decision gate: BLOCKED
- Existing Reticulum/LXMF virtual/LAN baseline: ACCEPTED
- Physical RF/RNode: NOT TESTED

## Run

```bash
python3 -m unittest discover -s tests -v
python3 -m fr3k_control.pack_audit docs/source-pack/v1.1 --output evidence/pack-audit.json
python3 -m fr3k_control.gate control/gates/g0.json --output evidence/g0-result.json
```

A non-zero exit from either operational check is intentional while blockers exist.

## Hard boundaries

1. Reticulum/LXMF transport remains independent of Hermes and optional services.
2. No transmission or deployment without an exact RF configuration and current ACMA review.
3. No public/third-party installation without written authority and maintenance/removal ownership.
4. No AI-generated artefact is deployment evidence.
5. No P0 control closes without a named human and retained evidence.

## Verification receipts

Adopted from the [oh-my-hermes](https://github.com/rlaope/oh-my-hermes) evidence model: an executor
reporting that a job finished is never the same as the result having been checked. A receipt records
what ran, where, and what was observed, and may be reused as evidence only when the revision, the
exact command and the environment all match again.

Every receipt carries a two-part status — the stage, and how sure we are:

- `process_exit` basis → stage `reported_done`: the command exited zero, nobody checked the result.
- `schema_valid`, `verification_observed`, `integration_ready` basis → stage `verified`: a check
  actually ran against the result.

```bash
# Create a receipt for a run whose result was genuinely observed
python3 -m fr3k_control.receipts create --name g0-decision \
  --command "python3 -m fr3k_control.gate control/gates/g0.json" \
  --evidence-basis verification_observed --exit-code 0 \
  --artifact evidence/g0-result.json --producer <name> \
  --output evidence/receipts/g0-decision.json

# Validate structure, artifact hashes and signature
python3 -m fr3k_control.receipts verify evidence/receipts/g0-decision.json

# Reuse check: REUSABLE (exit 0) only when revision + exact command + environment all match
python3 -m fr3k_control.receipts check-reuse evidence/receipts/g0-decision.json \
  --command "python3 -m fr3k_control.gate control/gates/g0.json"
```

`check-reuse` exits `0` (REUSABLE), `1` (invalid receipt) or `2` (STALE with named reasons). A STALE
receipt is not an error in the record — it is proof that the old evidence no longer applies and the
work must be re-produced.

## Related technical baseline

[`fr3kchy/hermes-reticulum-platform`](https://github.com/fr3kchy/hermes-reticulum-platform) is the accepted virtual/LAN gateway baseline. FR3K governance and field acceptance live here; transport implementation remains separate.
