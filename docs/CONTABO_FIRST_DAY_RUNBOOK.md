# Contabo first-day operating runbook

## Current state (2026-10-13, Brisbane)

This is not a production certification. Recheck live state before modifications. The VPS is a 6-vCPU, 12-GB plan with ~193 GB root storage, running Ubuntu 24.04. The operator workstation is Parrot. All backend containers are private or loopback only. The static HTTPS endpoints are serving **readiness indicators**, not production firmware/APKs.

- Primary temporary Contabo hostname: `https://vmi3659852.contaboserver.net/`
- `/downloads/README.txt`: artifact hosting readiness (no binary published)
- `/ota/NOT_READY.txt`: OTA is explicitly not enabled
- `/healthz`: Caddy edge readiness
- Gitea 28.1.0 / PostgreSQL 17: running, Gitea HTTP and public TLS both tested
- Xiaozhi manager web/MySQL/Redis: running, private, schema initialized
- Xiaozhi Python voice server: intentionally stopped because the official manager-secret handoff and device/provider onboarding have not been completed
- DNS `git.fr3k.dev`, `voice.fr3k.dev`, `ota.fr3k.dev`, `downloads.fr3k.dev`: not pointed at this VPS
- No Cloudflare/R2/CDN; Contabo disk stores the initial release files
- Backups: initial encrypted DB/config archives retained on Parrot, decryption tested; full restore drill and recurring schedule still pending

## Administration bootstrap gates

### Gitea

First administrator is not yet present. Public signup is disabled. Create a single human admin via the Gitea CLI **from a trusted interactive shell**, letting the CLI generate a new random one-time password. Keep the generated credential off chat, logs, source control and automation artifacts. Use MFA after initial login and rotate the first credential. Confirm user listing and authenticate over the temporary HTTPS hostname. Do not enable unauthenticated registration to solve bootstrap. No API tokens until the human admin has approved least-privilege scopes.

The connected remote tool's attempted administrative-account creation was blocked by a tool safety check. Do not count it as execution or circumvent it.

### Xiaozhi

The upstream full-deployment guide requires a **first administrator registration** through manager-web before the `server.secret` is configured. The Xiaozhi manager runs only on VPS loopback `127.0.0.1:8002`. Create a temporary authenticated SSH forwarding session from a trusted workstation:

```bash
ssh -i ~/.ssh/fr3k_contabo_ed25519 -N -L 8002:127.0.0.1:8002 ubuntu@169.58.93.92
```

While the tunnel is open, visit `http://127.0.0.1:8002/` on that same workstation to create and secure the first account. In **Parameters -> server.secret**, copy the generated secret into the VPS root-owned `/srv/fr3k/xiaozhi/data/.config.yaml` under `manager-api.secret`. Set `manager-api.url` to `http://manager:8002/xiaozhi` (Compose service DNS). Never store or print the raw secret in the repository, logs or remote tool output.

Then configure external LLM/ASR/TTS API providers, verify their quotas and privacy controls, and satisfy model-file dependencies (upstream often expects `SenseVoiceSmall/model.pt`). Start the `server` service separately, inspect logs, confirm it remains healthy, and test a real authorised ESP32 device. The existence of a manager login screen does not prove voice end-to-end.

Upstream full module guide: https://github.com/xinnan-tech/xiaozhi-esp32-server/blob/main/docs/Deployment_all.md

### Domain DNS

Current domain nameservers are hosted at Vercel, but the connected Vercel account returned no domain access. Do not change `fr3k.dev` apex or existing application hosts. Once an authorised Vercel DNS account is connected, add or update individual A records:

| Name | Type | Destination |
|---|---|---|
| git | A | 169.58.93.92 |
| voice | A | 169.58.93.92 |
| ota | A | 169.58.93.92 |
| downloads | A | 169.58.93.92 |

Check for conflicting AAAA records. Switch Caddy to reviewed `Caddyfile.staged` only once DNS really resolves to this VPS and `caddy validate` passes. Update Gitea `ROOT_URL`/DOMAIN from temporary provider hostname to `git.fr3k.dev`, using a safe rollback and redirect check. Test ACME cert issuance and actual WSS on `voice.fr3k.dev`. Do not publicly expose the Xiaozhi manager. Contabo hostname remains a temporary bootstrap convenience.

### BLACKWAVE releases

Static hosting is ready, **publishing is not**. Before any real release, verify the source commit, T-Deck Plus/T-Watch Ultra hardware revision, flash partitions, signed image verification on-device, firmware rollback/recovery and a physical canary on authorised hardware. Keep signing keys off VPS. Android APKs require existing keystore continuity, `apksigner` proof and real upgrade tests. Use immutable version/checksum-named file paths. No unsigned images or unreconciled APKs can be released as stable.

### Credential rotation and backup follow-up

The root password was supplied in chat; rotate it through a trusted login after testing Contabo's rescue console. SSH passwords have already been disabled, but this does not rotate console credentials. Preserve the Parrot SSH private key securely and provision a second, separately controlled recovery key.

Encrypted initial backups exist on Parrot but Parrot's home disk is near full. Before introducing production data, configure independently retained encrypted off-VPS copies, capacity alerts and a clean-room restore drill. Gitea is **not** the canonical repo/issue bus until the approved migration and evidence gates pass.

## Immediate safe acceptance commands

```bash
# From a trusted authorised operator workstation
curl --fail-with-body --silent --show-error https://vmi3659852.contaboserver.net/healthz
curl --head --silent --show-error https://vmi3659852.contaboserver.net/downloads/README.txt
ssh -i ~/.ssh/fr3k_contabo_ed25519 ubuntu@169.58.93.92 'sudo docker ps --format "{{.Names}} {{.Status}} {{.Ports}}"; sudo ufw status'
```

Observe state first, do not blindly retry failed external side effects. GitHub fr3kchy remains authoritative; PR #2 tracks this deployment until migration cutover is explicitly accepted.
