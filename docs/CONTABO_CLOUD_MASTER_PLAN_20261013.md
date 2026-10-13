# FR3KD3V Contabo Cloud: Complete Implementation Plan

**Date:** 2026-10-13 · **Owner:** fr3kchy / FR3KD3V
**Status:** DESIGN / NOT DEPLOYED
**Target:** One purchased Contabo VPS (12 GB RAM); hardware/disk/OS/IP not yet verified.
**Phase 1 excludes:** Cloudflare, R2, CDNs, hosted GPU inference, and additional paid cloud services.

> This plan is a design, not authorization for unreviewed infrastructure mutation, firmware flashing, physical deployment or RF transmission. Existing FR3K infrastructure governance, including its G0 HOLD, remains in force. Publish no credentials, actual network access secrets, private keys, identifying customer data, or signed release keys in GitHub.

## 1. Executive architecture

The Contabo VPS will be the **central FR3KD3V control and distribution host**. It will host:

1. **Gitea** as the eventual GitHub replacement: repositories, organisations, teams, issues/PRs, release metadata, packages and canonical agent task queue.
2. **Xiaozhi full server stack**: ESP32 AI voice WebSocket service, manager API/web UI, MySQL and Redis, with external AI inference APIs initially.
3. **BLACKWAVE OTA distribution**: signed/versioned firmware manifest endpoints for T-Deck Plus and T-Watch Ultra, immutable release binaries and controlled rollout channels.
4. **Software download portal**: Android APKs, later Windows/Linux installers, hashes and release notes, directly served from Contabo disk over HTTPS.
5. **Operations**: Caddy automatic HTTPS, security controls, monitoring, off-VPS encrypted backups and documented restoration.

The VPS must **not** host general untrusted CI jobs, device flashing operations, OTA signing keys or heavyweight GPU inference. Authorised development work stays on existing local developer machines, which publish only approved outputs. GitHub is canonical **until** Gitea migration is reconciled and explicitly cut over. Gitea then becomes the sole canonical issue/approval bus; Hermes executes and returns evidence.

### Traffic diagram

~~~text
Internet / ESP32 / Android / authorised developers
                      |
        Registrar DNS -> Contabo public IP
                      |
              Contabo firewall
                      |
                Host firewall
                      |
              Caddy 80/443 TLS
                 /    |     \
      git.fr3k.dev    |    downloads.fr3k.dev
        Gitea          |       immutable artifacts
        Postgres   voice.fr3k.dev     |
                      Xiaozhi WS    ota.fr3k.dev
                      manager API    signed manifests
                      MySQL + Redis

Private operator -> SSH tunnel -> admin console
Local isolated builders -> review/sign -> staging -> release publisher
Off-VPS storage <- encrypted backup export (no Cloudflare)
~~~

## 2. Verify purchased VPS and recovery access first

Only **12 GB RAM purchased** is confirmed by the user's statement. Do not assume 6 vCPU, 200 GB disk, x86_64, IPv6, location, backup subscription, operating system, existing root access, provider firewall or clean empty disks.

Record the following in a **redacted inventory** with observed timestamp:

| Discovery | Commands or evidence | Pass condition |
|---|---|---|
| OS/host | `hostnamectl`, `cat /etc/os-release`, Contabo customer panel | Supported Linux identified |
| Architecture | `uname -m`, `lscpu`, `nproc` | Prefer x86_64; Xiaozhi images verified for it |
| Memory | `free -h` | ~12 GB installed; headroom measured |
| Disks | `lsblk -f`, `df -hT`, `findmnt` | Capacity, filesystem, mounts and existing data documented |
| Network | `ip -brief address`, `ss -lntup`, external DNS and port tests | Correct public route and listening services identified |
| Recovery | Contabo console/VNC/rescue, SSH second session | Two independently usable access methods |
| Existing workloads | `docker ps -a`, `systemctl --failed`, process inventory | Nothing overwritten accidentally |
| Commercial limits | actual Contabo plan details | Disk expansion, traffic allowance and snapshots verified |

Prefer Ubuntu Server 24.04 LTS or a currently supported Debian stable image. An OS reinstall is destructive and must never be implicit. Take a baseline snapshot if available after checking the plan; snapshots **are not** downloadable offsite backups and may expire.

**Gate D0:** verified host identity and inventory; live SSH-key login in second session; tested provider console/rescue route; record of pre-existing state.

## 3. Domain and ingress plan: NO CLOUDFLARE

Keep DNS at the existing domain registrar or current DNS host. Direct DNS **A** records point to the Contabo IPv4 address. Only add **AAAA** after tested IPv6 and IPv6 firewall rules. Set short TTL during setup; do not enable proxies/CDNs or route artifacts through R2.

| DNS name | Service | Phase-one exposure |
|---|---|---|
| `git.fr3k.dev` | Gitea HTTPS/clone | Public HTTPS, authentication for changes |
| `voice.fr3k.dev` | Xiaozhi WSS | Public device connection with verified auth |
| `downloads.fr3k.dev` | Immutable firmware/APK/installer files | Public HTTPS approved releases |
| `ota.fr3k.dev` | Signed manifests | Public HTTPS approved channels |
| `xiaozhi.fr3k.dev` | Admin UI | Reserved, private via SSH tunnel initially |
| `status.fr3k.dev` | Minimal redacted status | Future, not phase one |

**Inbound firewall:** 22/tcp for SSH (source restricted if viable), 80/tcp for HTTPS/ACME redirection, 443/tcp for HTTPS/WSS. Optionally 2222/tcp for Gitea Git SSH **after** review. Deny 3000, 5432, 3306, 6379, 8000, 8002, 8003 externally; only internal Compose networks or loopback bind addresses. Docker published ports can bypass simplistic UFW assumptions, so use **both** provider firewall and host firewall plus independent external scans. Never activate default-deny firewall until known-working SSH and Contabo console recovery are verified.

Caddy manages ACME certificates directly without Cloudflare. Persist Caddy's certificate/config volumes, verify HTTP challenge accessibility and certificate renewal. WebSocket upgrades are proxied automatically by Caddy. Restrict file server to **GET/HEAD**, no directory listing, public filesystem read-only, separate staging inaccessible by URL.

Illustrative Caddy routes, to be reviewed before use:

~~~caddyfile
git.fr3k.dev {
    encode zstd gzip
    reverse_proxy gitea:3000
}
voice.fr3k.dev {
    reverse_proxy xiaozhi-server:8000
}
downloads.fr3k.dev {
    root * /srv/releases/public
    file_server
}
ota.fr3k.dev {
    root * /srv/releases/ota-public
    file_server
}
~~~

Do not treat this as a final configuration until upstream Xiaozhi WebSocket paths, auth, upload behavior, headers, public API route requirements and release cache policy are tested. Serve manifests with conservative cache freshness; serve versioned digest-addressed firmware/APKs as immutable files.

**Gate D1:** verified DNS resolution, certificate identity, HTTPS redirects, WSS handshake, no admin/DB ports remotely reachable, and provider firewall policy captured.

## 4. Resource allocation and persistent storage

Conservative **planning** RAM budgets for a 12 GB VPS, not guaranteed measured consumption:

| Stack | Budget |
|---|---:|
| Xiaozhi Python core + manager with remote AI APIs | 3.0 GB |
| Xiaozhi MySQL | 1.2 GB |
| Xiaozhi Redis | 0.3 GB |
| Gitea | 1.5 GB |
| Gitea PostgreSQL | 0.75 GB |
| Caddy/static host/health probes | 0.2 GB |
| Host/services/logging | 0.75 GB |
| Reserve, page cache and spikes | **4.3 GB** |

The full Xiaozhi API-backed installation documents a 2-core/4-GB baseline; the actual combined service load needs observation. No local FunASR/LLM deployment until capacity is measured and a budget approved. Configure health checks, graceful restart behavior, resource controls and out-of-memory alerts. Avoid overcommit causing kernel OOM.

If and **only if** actual disk is 200 GB, an initial allocation can be OS 18 GB; containers 22 GB; Gitea repo/LFS/packages 45 GB; Gitea DB 10 GB; Xiaozhi data 18 GB; published releases 50 GB; logs/staging 12 GB; free reserve 25 GB. If disk is smaller, revise retention and limits. Separate cloud object storage is deliberately omitted.

Disk controls: alert at **70%** occupied; prevent new bulk release uploads at **85%**; incident at **90%**. Monitor **inode exhaustion**, not just bytes. Keep multiple last-known-good OTA binaries, but trim regenerable caches first. Measure public download traffic versus Contabo's real bandwidth policy. Build caches stay off VPS.

Suggested hierarchy:

~~~text
/opt/fr3k-cloud/compose/{edge,forge,voice,artifacts}/
/opt/fr3k-cloud/config/            # reviewed non-secret configuration
/opt/fr3k-cloud/scripts/           # approved operator procedures
/srv/fr3k/forge/                   # Gitea DB/repos/attachments
/srv/fr3k/xiaozhi/                 # MySQL/Redis/uploads/config/models
/srv/fr3k/releases/staging/       # NOT web served
/srv/fr3k/releases/public/        # immutable vetted binaries
/srv/fr3k/releases/ota-public/    # signed manifests
/srv/fr3k/backup-staging/          # temporary; not sole backup
/etc/fr3k-cloud/                  # root-owned secrets NEVER in Git
~~~

Use discrete Compose projects and private networks. Databases have no published WAN ports and do not join the shared edge proxy network. Mount public release roots read-only into Caddy. Use owner/mode appropriate to each service, not `chmod 777`.

## 5. Linux, Docker, security and secrets baseline

1. Verify second-key login/Contabo rescue before changing the SSH daemon.
2. Update OS; create non-root sudo operator and separate service accounts. SSH key-only after validation; restrict root/password login only after tested recovery.
3. Configure unattended security fixes, reboot windows, time sync and log rotation.
4. Apply Contabo and host firewall rules; independently scan from outside.
5. Install official Docker Engine and Compose plugin; no public Docker API, no app access to `/var/run/docker.sock`.
6. Adopt reviewed image versions **pinned to immutable digests** after a compatibility/security check. No blind `latest` updates; backup before changes.
7. Use health checks, startup dependencies, restart policies, limited Linux capabilities, read-only mounts and minimal filesystem access where supported.
8. Generate unique random DB passwords and Xiaozhi manager secret. Store as strictly permissioned runtime secrets, not in the repository, Compose examples, container logs or screenshots.
9. Review upstream Xiaozhi Compose: it includes example database password values and `seccomp:unconfined`; neither may be copied uncritically to a public production system. Test hardened sandbox settings and document any needed exceptions.
10. Enable MFA in Gitea and registrar; close registration after controlled admin bootstrap; use scoped service tokens and expiry/rotation.
11. Configure timeouts, bounded API attempts, connection throttles, reverse proxy body limits and audit logs; avoid audio/transcript logging without explicit privacy policy.
12. Never run untrusted CI in the production VPS Docker daemon.

**Gate D2:** reboot survival, SSH recovery, provider/OS firewalls, secret scans, restricted volumes and clean administrative authentication verified.

## 6. Gitea design and GitHub migration

**Platform:** official Gitea container + dedicated PostgreSQL; pinned validated stable releases. Postgres major upgrades need dump/restore or documented `pg_upgrade`, not an automatic tag bump. Gitea HTTP internally at port 3000; external root URL `https://git.fr3k.dev/`; optional SSH Git service on 2222 later. Protect default branches and PR reviews. Configure organisations, teams, public/private repo permissions, LFS quota, attachment and package caps, repository webhooks and audit retention.

### Canonical task/evidence contract

- Github is currently the authoritative state bus. During migration, no competing Gitea execution queue is to be accepted as operationally authoritative.
- After explicit, verified cutover: Gitea becomes canonical for tasks, approvals, evidence and releases; Hermes is execution/collection only.
- Issue work IDs must be idempotent. `heartbeat != progress`. Queue states must reflect observed results, not optimistic calls.
- Production, release and physical device operations remain approval gated.
- The RTX 3060 12-GB workstation retains a **maximum 8-GB VRAM operational workload ceiling**.

### Migration stages

1. Inventory all fr3kchy repos using authenticated GitHub tooling: repo visibility, owner, branches, tags, LFS, submodules, wiki, GitHub releases/assets, issues, PRs, labels, comments, milestones, workflows, discussions and webhooks.
2. Create a dependency/prioritisation list: BLACKWAVE, Hermes, FR3K infrastructure, active experiments, archive. Do not transfer unrelated sensitive user records into public repositories.
3. Bootstrap isolated Gitea admin+org and test with a disposable, noncritical repository. Disable public registration after first-admin setup.
4. Use Gitea built-in GitHub migration where feasible; independently verify refs, HEAD SHA, tags, default branch, LFS objects and wiki. Test private permission boundaries and protected pushes.
5. Validate issues/PRs/reviews separately: GitHub and Gitea IDs differ, and API exports/imports can lose review/thread metadata or GitHub-specific statuses. Maintain audited old/new URL mapping.
6. Port workflows individually; Gitea Actions compatibility is not guaranteed for every GitHub Action. Runners must operate on isolated local machines or dedicated sandboxes, never the production VPS host socket.
7. Audit release artifacts, packages, git submodules, webhook destinations, dependency credentials and Hermes control-plane endpoints.
8. Approve a cutover window, freeze or gate writes on the source, perform final sync, compare counts and hashes, switch remotes/agents, and validate PR+issue lifecycle. Do not force-push or delete GitHub until separately authorised.
9. Retain GitHub as archival history while accessible. The migration must be *reversible* during acceptance.

**Gitea acceptance:** HTTPS clone, authenticated push, rejected unauthorised push, LFS round-trip, protected PR, create/read/close issue, release metadata, Postgres backup/restoration, Hermes issue acknowledgment, mapping ledger and final count comparisons.

## 7. Xiaozhi ESP32 server

**Upstream:** `xinnan-tech/xiaozhi-esp32-server`. Full stack includes core Python server, Java manager API/Web UI, MySQL and Redis. Upstream examples expose WebSocket port **8000**, manager **8002**, and HTTP/vision/OTA **8003**. Package architecture and routes must be verified against a **locked** release. Upstream documentation indicates x86 Docker images; x86_64 VPS preferred.

### Implementation

1. Inspect a tagged upstream commit and dependency/image manifest, license, security issues and deployed protocol compatibility. Record lockfile/commit/digests in the repository.
2. Adapt upstream full-module Compose into the restricted voice project with service-specific credentials and private DBs. Do **not** expose manager/MySQL/Redis/port 8003 publicly without a route-by-route protocol/auth review.
3. Configure manager `server.secret` shared with Xiaozhi core securely. Initialise the first admin through local SSH tunnel or restricted bootstrap, then close uncontrolled admin creation.
4. Choose remote LLM, ASR and TTS providers to minimise RAM, with quotas, hard spend caps, timeouts, exponential backoff, explicit provider failure classifications and no unlimited retries. Confirm whether upstream requires a downloaded local model file even with remote provider settings.
5. Publish only a validated device WSS endpoint via `voice.fr3k.dev`; check authentication and firmware provisioning/activation routes. Preserve device certificate validation and scheme correctness.
6. Test one authorised ESP32 end-to-end (WSS connect, provisioning, audio, speech recognition, provider request, speech playback, reconnect). Expand to multiple devices after resource measurements.
7. Monitor service stats, latency, concurrent streams, memory, errors and cloud API spending without storing raw conversations unnecessarily.
8. Maintain strict distinction between **Xiaozhi provisioning OTA** and **BLACKWAVE firmware OTA**. They are different product/version/protocol contracts.

**Gate D4:** physical ESP32 voice test, bounded provider behavior, no anonymous admin access, voice reconnection after restart and persisted configuration across reboot.

## 8. BLACKWAVE OTA and release contracts

Firmware targets begin with **LilyGO T-Deck Plus** and **T-Watch Ultra**, with separate device IDs and distinct hardware/SoC/bootloader/partition compatibility contracts. Future devices require a reviewed new target identity. A manifest filename is not proof of secure OTA.

Public object layout on **Contabo's own disk**:

~~~text
/srv/fr3k/releases/public/blackwave/t-deck-plus/{stable,beta}/<version>/<sha256>/firmware.bin
/srv/fr3k/releases/public/blackwave/t-watch-ultra/{stable,beta}/<version>/<sha256>/firmware.bin
/srv/fr3k/releases/public/android/blackwave/<version>/<sha256>/blackwave-arm64-v8a.apk
/srv/fr3k/releases/public/desktop/{windows,linux}/<version>/<sha256>/...
/srv/fr3k/releases/ota-public/v1/<device>/<channel>/manifest.json
/srv/fr3k/releases/ota-public/v1/<device>/<channel>/manifest.sig
~~~

Manifest minimum schema (illustrative only, not a live protocol): `schema`, `product`, `device`, `hardware_revision`, `channel`, `version`, `build_id`, `source_commit`, `issued_at` (UTC), minimum bootloader/partition compatibility, immutable HTTPS image URL, SHA-256, `size_bytes`, signature algorithm/key ID, rollout cohort and canonical approval evidence. Define a *canonical serialized representation* for signing, and pin trusted verification keys in device firmware. Manifest signatures and firmware signatures both need **device-side verification**. Hashes over HTTP without a trust anchor are insufficient against an attacker controlling the release server.

### Firmware promotion gates

1. Inspect real target firmware and OTA implementation, SoC, flash map, partitions, bootloader, signing and recovery options. **NOT TESTED** means no automatic OTA claim.
2. Create deterministic build evidence: exact source commit, dependencies/toolchain, build config, binary size/hash, tests, provenance/SBOM where practical.
3. Sign verified binaries with protected key held **off-VPS**, off normal CI machines if possible; never publish keys or Android keystore.
4. Stage into a non-public filesystem with exclusive access. Validate sha256, signature, target hardware and known compatible firmware versions.
5. Publish a versioned immutable binary path; probe that HTTPS URL and match full returned hash; then atomically replace the correct channel manifest after approval.
6. Sequence channels: **internal -> one canary -> beta -> stable**. A field device or physical flash requires separate authorisation and device-owner approval.
7. Device must reject mismatched device/revision, invalid signature, unsupported bootloader, downgraded security version and truncated/tampered downloads.
8. Use ESP-IDF OTA partition fallback and first-boot self-test/confirmation **only if demonstrated in the actual port**. Secure boot/eFuse/anti-rollback configuration is a separate potentially irreversible hardware approval.
9. Record downloads, install attempts, first boot, verification, active partition, and failure/rollback. A heartbeat alone must never mark deployment complete.
10. Keep last-known-good stable and manual USB recovery image. Stop a rollout on crashes, boot failure or unexpected RF regression.

**Gate D5:** one authorised hardware canary, negative signature/device tests, download interruptions, explicit rollback/manual recovery and canonical evidence record.

## 9. Android APK and desktop releases

- Build and test on an authorised development machine; the VPS does not create APK signing identities.
- Preserve Android application ID and signing-key continuity. Refuse an upgrade signed by a different key; ensure monotonically increasing versionCode and known ABI/minSdk.
- Run `apksigner verify --verbose --print-certs`, hash `sha256sum`, inspect permissions and packaged library ABIs, then test both clean install and upgrade on physical target phones.
- Publish immutable versioned HTTPS URLs, SHA-256 and changelog, supported device/OS matrix, installation notes, release provenance and rollback caveats.
- Apply analogous OS code signing where feasible for Windows/macOS, and package integrity for Linux; don't claim signed artifacts until actually signed.
- Caddy serves files read-only. No web file manager or unsecured upload route; release publisher writes to staging then publishes atomically.

**Gate D6:** independent download hash and physical Android clean/install upgrade tests with documented outputs.

## 10. Release state machine and approved publisher

`DRAFT -> BUILT -> VERIFIED -> STAGED -> CANARY -> APPROVED -> PUBLISHED`; errors lead to `FAILED/REVOKED` without erasing historical artifacts. Only the controlling, protected issue and required human reviewers authorize stable rollout. Approval controls remain distinct from observed execution status.

Publisher requirements:

- Strictly validate image file, size, digest, signature, target and path; reject path traversal and mismatched device IDs.
- Verify all prerequisites and backup/rollback assets before promotion.
- Key by immutable build+target+channel for idempotency; never overwrite a digest-addressed binary.
- Atomically change only the channel manifest (temp+fsync+rename). No manifest may reference a nonexistent file.
- Verify remotely served content after write; record observed result and exact URLs back to canonical task.
- On ambiguous side effects, **inspect destination state first**, do not retry blindly.
- No upload, DELETE or POST available on public artifact/OTA hosts.
- Signing keys remain under offline/restricted custody and are never made available to the publisher or publicly exposed VPS.

## 11. Backup, monitoring and restore

Contabo snapshots are convenience rollback aids and may be unavailable, time limited and non-downloadable. They do **not** replace independent off-VPS backups. Phase 1: make consistent, encrypted backups from the VPS, then transfer to existing separately controlled Parrot storage or another off-VPS destination over hardened SSH/SFTP. Verify capacity; if Parrot is the only backup and offline, classify DR as **PARTIALLY_VERIFIED**, not resilient.

Backup set: Gitea repo storage/LFS, Gitea DB/config and uploads; Xiaozhi MySQL and Redis persistence, manager config and uploaded data; Caddy ACME state; public release binaries and signed manifests; secret recovery instructions and encrypted key material managed separately. Use transaction-consistent dumps. Gitea upstream specifically advises quiescing/shutting down during consistent snapshot-style backups; document the maintenance window or tested alternative.

Proposed cadence after verifying capacity: 7 daily + 4 weekly + 3 monthly copies, with daily RPO target <=24 hours and restore-time *goal* <=4 hours (not a claim of observed performance). Run periodic restore to **isolated** environment, verify DB row counts, Git refs, release hash, Caddy/voice service recovery and record actual minutes. Never overwrite live Gitea to rehearse backup restoration.

Watch memory/OOM, load, disk bytes+inodes, DB volume free, reverse-proxy and WSS readiness, certificate expiry, Gitea DB health, Xiaozhi API failures, manifest signature validation, artifacts 404/hash mismatches, authentication errors and last successful off-VPS backup. Warn around 70% disk, hard-stop bulk upload at 85%, page/incident at 90%. Alerts should be bounded and actionable; exclude raw secrets/audio.

**Gate D7:** a verified independent encrypted backup, successful test restoration and a practiced recovery decision tree.

## 12. Phased work packages and proof

| Phase | Deliverables | Exit gate |
|---|---|---|
| 0 - Discover | Actual Contabo inventory, disk/OS/network, recovery and current repo state | D0 |
| 1 - Harden | Nonroot access, SSH keys, provider/host firewall, Docker, patching | D1/D2 |
| 2 - Ingress | Registrar DNS, Caddy, direct ACME TLS, WSS proxy, static roots | D1 |
| 3 - Git | Gitea+Postgres, admin MFA, private sample repos, backup | D3 partial |
| 4 - Voice | Xiaozhi full-module, external AI APIs, private admin, ESP32 E2E | D4 |
| 5 - Downloads | Immutable binaries, static HTTPS, signatures/hashes, publisher | D5/D6 partial |
| 6 - OTA | Board matrix, signed client verification, canary and recovery | D5 |
| 7 - Android | Signed APK upload, clean install, upgrade and checksum | D6 |
| 8 - Migrate | GitHub inventory, refs/LFS/issues/PRs, Hermes queue and cutover | D3 full |
| 9 - DR | Monitors, alerts, offsite backup, isolated restore | D7 |
| 10 - Switch | Approval, canonical authority change, old/new URL mapping | Explicit human gate |

Track these as **issues in the current canonical FR3K infrastructure repository** when starting implementation. Avoid creating a parallel queue. Every task needs owner, prerequisites, allowed effects, rollback, evidence and acceptance checks. Do not equate deployment script output, compiled artifacts or passed unit tests with a successful physical OTA.

### Read-only first-session checks

~~~bash
date -u
hostnamectl
uname -m
cat /etc/os-release
nproc
free -h
lsblk -f
df -hT
ip -brief address
ss -lntup
sudo ufw status verbose
docker version || true
docker compose version || true
systemctl --failed
~~~

Before any state change, check Contabo's provider firewall, console, disk quotas and snapshots; confirm SSH recovery. Redact outputs before creating repository evidence, and never commit private addresses or credentials.

## 13. Acceptance criteria, negative tests and risk register

- [ ] Verified Contabo host CPU, memory, disk, OS, recovery/SSH.
- [ ] Registrar DNS and valid direct ACME TLS from multiple external networks.
- [ ] Public ports only as approved; admin, database and raw container ports unreachable externally.
- [ ] Gitea MFA, branch protection, private repo access isolation, cloned/pushed repo and LFS/backup tested.
- [ ] Full Xiaozhi multi-container stack works and one real device communicates via WSS after controlled restart.
- [ ] Gitea/GitHub migration includes checksums, refs, LFS, issues, PR/review limitations and canonical queue handoff evidence.
- [ ] Signed firmware accepted for correct LilyGO hardware, mismatched/revoked/unsigned firmware rejected.
- [ ] OTA interrupted download and failed-first-boot recovery are physically tested when supported.
- [ ] Stable release requires human approval and verified canary; no autonomous device flashing.
- [ ] APK has expected signer, ABI, hashes, incremented versionCode and successful clean/upgrade install.
- [ ] Immutable Contabo-hosted artifacts, no upload method from web, no directory listing, no missing manifest references.
- [ ] Alerts fire for disk growth, backup age, certificate expiry, service failure and auth anomalies.
- [ ] Backups restorable away from production and signing secrets absent from VPS/Git.
- [ ] Existing FR3K community infrastructure RF field G0 HOLD remains unchanged.

Risks to retain in open task tracking: a single VPS is a single failure domain; unknown actual disk allotment; Contabo bandwidth and disk extension pricing; Xiaozhi upstream sample seccomp/credentials; imported GitHub metadata loss; local backup dependence; OTA port-specific rollback support; irreversible secure-boot/eFuse changes; lost Android signing key; an exposed Gitea initial-registration flow; unattended container upgrades.

## 14. Approved repository layout as execution progresses

~~~text
docs/CONTABO_CLOUD_MASTER_PLAN_20261013.md   # this master plan
docs/cloud/architecture.md                    # final observed design
docs/cloud/operations.md                      # startup/upgrade/rollback
docs/cloud/disaster-recovery.md               # restoration procedure
docs/cloud/github-gitea-migration.md          # mapping/evidence
docs/cloud/blackwave-release-contract.md      # approved schemas & signatures
control/cloud/acceptance-gates.yaml           # versioned gates, after approval
ops/contabo/compose/                           # review-pinned services
ops/contabo/caddy/                             # no-secret edge configuration
ops/contabo/scripts/                           # idempotent operator tooling
evidence/cloud/README.md                      # redacted evidence register
~~~

Do not generate fake proof files or completed checkmarks; add evidence only when observed. No deployment was attempted as part of authoring this plan.

## 15. References and technical anchors (checked 2026-10-13)

- Xiaozhi overview and full-server requirements: https://github.com/xinnan-tech/xiaozhi-esp32-server/blob/main/docs/readme/README_en.md
- Xiaozhi full-module setup: https://github.com/xinnan-tech/xiaozhi-esp32-server/blob/main/docs/Deployment_all.md
- Xiaozhi upstream Compose (security review required): https://github.com/xinnan-tech/xiaozhi-esp32-server/blob/main/main/xiaozhi-server/docker-compose_all.yml
- Gitea Docker/Postgres installation: https://docs.gitea.com/installation/install-with-docker/
- Gitea migration from GitHub: https://docs.gitea.com/usage/repository/migration/
- Gitea runner trust/isolation: https://docs.gitea.com/runner/
- Gitea backup/restore: https://docs.gitea.com/administration/backup-and-restore/
- Caddy automatic HTTPS: https://caddyserver.com/docs/quick-starts/https
- Contabo VPS operations: https://docs.contabo.com/docs/servers-hosting/vps/
- Contabo provider firewall: https://docs.contabo.com/docs/network-services/firewall/
- Contabo snapshots (not backups): https://help.contabo.com/en/support/solutions/articles/103000270385-how-do-i-create-a-snapshot-of-my-server-
- Espressif OTA integrity/rollback: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/ota.html
- FR3K field G0 HOLD: docs/G0_DECISION_20260802.md

**Decision:** Contabo VPS only for cloud hosting and artifact storage in phase 1. External AI inference services permitted; Cloudflare and R2 intentionally excluded. **Implementation status:** NOT_TESTED until independently observed gates are satisfied.
