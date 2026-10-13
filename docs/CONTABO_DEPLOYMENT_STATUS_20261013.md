# Contabo Deployment Evidence, 2026-10-13

Repository: fr3kchy/fr3k-infrastructure. Source: observed remote SSH sessions from the authorised Parrot machine, not a simulated deployment. This status is a dated snapshot; reobserve before taking consequential action.

## Verified baseline
- Target VPS (public IP omitted from this repository); Ubuntu 24.04.5 LTS, x86_64, 6 vCPU, approximately 11 GiB usable RAM, 193 GB ext4 / (~191 GB initially free).
- Dedicated SSH Ed25519 key created locally on Parrot at `~/.ssh/fr3k_contabo_ed25519`. User `ubuntu` accepts key login and has passwordless sudo. Root SSH key remains for emergency until recovery arrangement reviewed.
- `sshd -T`: `passwordauthentication no`, `permitrootlogin without-password`. Authentication via password over SSH is disabled.
- UFW active default-deny inbound; only ports 22/tcp, 80/tcp, 443/tcp allowed. Fail2ban enabled. Docker Engine 29.1.3 and Compose 2.40.3, Caddy 2.6.2 installed.
- Public service ports 3000 and 5432 are not exposed. This must be reverified after service changes.

## Forge deployment
- Dedicated `fr3k-forge` Docker Compose stack: Gitea 28.1.0 and PostgreSQL 17-alpine.
- PostgreSQL healthcheck passed. Gitea initial database migration completed and its local HTTP endpoint returned 200.
- Docker publishes Gitea only on 127.0.0.1:3000. Separate database is not published.
- Database and internal application credentials generated on VPS under root-owned /etc/fr3k-cloud/forge.env, not committed to Git.
- Registration disabled and sign-in enforced until private administration is established.

## Open gates
- Gitea first human admin, login, 2FA and Git clone/push: NOT TESTED until independent verified evidence.
- Xiaozhi stack, hardware voice handshake and provider configuration: NOT TESTED.
- DNS records `git.fr3k.dev`, `voice.fr3k.dev`, `ota.fr3k.dev`, `downloads.fr3k.dev` did not resolve to the VPS at initial inventory. Domain DNS access not established through connected Vercel account, so **no DNS change is claimed**.
- Caddy public TLS and signed BLACKWAVE OTA / APKs: NOT TESTED.
- All backups and restore drills: NOT TESTED.
- Source-of-truth Gitea cutover and Hermes queue migration: BLOCKED pending complete test/approval.
- Never add Contabo root password, signing keys, API secrets or raw environment contents to this repo.

## Security follow-up
The initial root password was shared in chat. After recoverability is tested, rotate it using an approved secure procedure and do not publish the new credential. SSH password authentication is already disabled, but console authentication may still accept the original password. Check Contabo provider-side firewall rules independently.

## Canonical approval
Existing repo G0 HOLD still applies to public/physical RF transmission or installation. No BLACKWAVE physical updates/flashes occurred.

## Additional observed deployment evidence

- A Contabo-assigned DNS hostname `vmi3659852.contaboserver.net` resolves to the VPS. Caddy successfully obtained a trusted TLS certificate: external HTTPS probe reported HTTP 200 and `ssl_verify_result=0`. This uses Contabo DNS, **not Cloudflare**.
- A temporary HTTPS Gitea route serves its home page from the Contabo hostname (HTTP 200). The Compose `ROOT_URL` was adjusted to the temporary hostname. The original `git.fr3k.dev` hostname remains unpointed; its future cutover requires registrar DNS access.
- Static distribution routes `/downloads/` and `/ota/` work over trusted HTTPS. Startup indicator files are intentionally **not firmware images**. Mutating HTTP verbs POST/PUT/PATCH/DELETE/OPTIONS were independently probed and all returned HTTP 405 after the method guard was added. No production firmware, APK, or signed OTA manifest has been published.
- Xiaozhi full stack images pulled and started: MySQL 8.4 and Redis 8.0 healthy, manager frontend returned local HTTP 200, MySQL schema tables exist. The Python voice server failed because its manager API secret is a non-production placeholder. It was intentionally stopped to avoid unattended restart loops. **Voice end-to-end is NOT_TESTED.** User/administrator onboarding and upstream manager secret handoff are required before enabling.
- Both upstream Xiaozhi images are now referenced by observed SHA-256 image digests in the staged Compose configuration; these are image identities, not tests of service functionality.
- Encrypted Gitea database + application-data backup stored off VPS on Parrot; decryption and archive/listing checks completed. Encrypted Xiaozhi MySQL backup was re-created using `--no-tablespaces` after an initial tablespace privilege failure, with the complete mysqldump footer observed. No isolated full restore drill has passed yet.
- Parrot home partition was approximately 99% utilised (about 25 GB free), so this is only a provisional backup target; capacity and geographic independence require improvement.
- An attempt to bootstrap a Gitea administrator via remote tooling was blocked by tool safety checks. **No first admin is claimed.** Keep public registration disabled until administrator ownership is securely established. Do not bypass the guard.
- The root credential supplied in chat is sensitive and should be changed using the Contabo console or a verified secure SSH session once an independent recovery path is confirmed. SSH password authentication was disabled, but this does not establish that console/root passwords were rotated.

### Temporary URLs (initial validation, not production approval)

- Gitea: `https://vmi3659852.contaboserver.net/`
- Artifacts: `https://vmi3659852.contaboserver.net/downloads/README.txt`
- OTA readiness: `https://vmi3659852.contaboserver.net/ota/NOT_READY.txt`

Public access to the *Xiaozhi manager* has **not** been enabled. Production custom domains, signed firmware publishing, physical device tests and canonical GitHub-to-Gitea migration remain pending.
