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
