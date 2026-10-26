# Contabo backup, off-VPS vault and isolated restore — evidence 2026-10-26

**Task:** P0 recovery gate D7 (durable encrypted off-VPS backup, retention/capacity
alerts, isolated restore drill) for the Contabo VPS that hosts the FR3K estate.
**Source issue:** [#3 Contabo cloud: finish Gitea, Xiaozhi, BLACKWAVE release and recovery gates](https://github.com/fr3kchy/fr3k-infrastructure/issues/3)
**Performed by:** root operator session on the Contabo host, 2026-10-26.
**Mutation scope:** none on production services, databases, credentials, firewall or
DNS. The only writes were new files under the host backup root, a new root-only
passphrase file, and a new **private** GitHub vault repository.

Sanitisation: no credentials, environment contents, private keys, hostnames or IP
addresses appear below. Backup artifacts stay encrypted; only sizes and SHA-256 values
are published here.

## 1. Verdict summary

| Claim | Status | Proof |
|---|---|---|
| Read-only estate inventory captured with timestamp | **VERIFIED** | §2 |
| Encrypted backup set created (MySQL, Redis, Gitea PG, config, manifests) | **VERIFIED** | §3 |
| Ciphertext published off-VPS and read back byte-identical | **VERIFIED** | §4 |
| Isolated restore of MySQL with per-table row parity | **VERIFIED** | §5.1 |
| Isolated restore of Redis with key-count parity | **VERIFIED** | §5.2 |
| Isolated restore of Gitea PostgreSQL with table/row parity | **VERIFIED** | §5.3 |
| Production untouched during drill (no restarts, no writes) | **VERIFIED** | §5.4 |
| Backup automation running on a schedule | **NOT_STARTED — approval needed** | §7.1 |
| Passphrase held off-host (true disaster recovery) | **BLOCKED — operator action** | §7.2 |
| Capacity/quota alerting active | **NOT_STARTED — approval needed** | §7.3 |

Success criterion for this card — *actual restore verification* — is met: the restore
drill was executed against the ciphertext **re-downloaded from the off-VPS vault**, not
against the local copy.

## 2. Inventory snapshot (read-only)

Observation window: 2026-10-26 12:09–12:18 UTC. Re-observe before acting; this is a
snapshot, not a standing truth.

- Host: Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic, container runtime 29.1.3,
  compose 2.40.3, root filesystem 193 GB with 155 GB free (20 % used).
- Memory 11 GiB total, ~4.9 GiB available, no swap configured.
- 11 containers running: voice server, voice manager, voice MySQL 8.4, voice Redis 8,
  Gitea 28.1.0, Gitea PostgreSQL 17, llama.cpp server, LLM router, web UI theme,
  and two Gitea Actions runners.
- Only 22, 80 and 443 are bound publicly; every application port is loopback-bound.
- One failed unit at audit time: `systemd-networkd-wait-online.service` (boot-order
  noise, not a service outage).
- Durable state that matters for recovery, and where it lives:

| State | Location class | In backup |
|---|---|---|
| Voice-stack relational data | MySQL 8.4 container | logical dump (§3) |
| Voice-stack hot state | Redis 8 container | RDB snapshot (§3) |
| Gitea users/repos/issues/actions | PostgreSQL 17 container + git data dir | `pg_dump -Fc` + tar (§3) |
| Compose files, service config, env files | host config directory | tar inside ciphertext (§3) |
| Model weights (~0.9 GB), published binaries (~0.6 GB) | host data dirs | intentionally excluded — reproducible artifacts, not state |

## 3. Backup set

Backup id `20261026T121051Z`, root-only directory (0700, files 0600) under the host
backup root.

| Artifact | Size (B) | SHA-256 |
|---|---|---|
| `xiaozhi_mysql.sql.gz` | 59 553 | `7489f370fbd2a26f0e2ea0cf6f22b7100bd1304b18a0858421cf49e1025daf93` |
| `redis_dump.rdb` | 14 581 | `20cc78fc1dc5fca726274c34e0e619e82f149793acf70e1871d878a40fa8d144` |
| `forge_gitea.dump` | 386 807 | `ce11511cfecdbab604a828b1fc684ff28349c21ad30144907e233734379cf8a6` |
| `fr3k-config.tgz` | 628 578 | `f863e0f78909d26a3effe6ef68563c1bcf0f521fb0e63aa010c35cd11fc1882f` |
| `fr3k-contabo-backup-20261026T121051Z.tar.zst.gpg` | 765 577 | `cd3e177452b58d4767ab481b0e7686056c4169bf292a06b7fd638a2998f723f7` |

Collection methods: `mysqldump --single-transaction --quick --routines --triggers
--events` (consistent snapshot, no table locks, no downtime), `redis-cli SAVE` +
container copy, `pg_dump -Fc`, `tar` of config and Gitea git data. Integrity gates run
during collection: `gzip -t` OK, `tar -tzf` OK, per-member `sha256sum -c` OK (8 members).

Encryption: OpenPGP symmetric, AES-256, SHA-512 S2K, mode 3, 65 011 712 iterations,
binary output. A decrypt round-trip was executed before upload.

## 4. Off-VPS publication

- Private vault repository: `fr3k-d3v/fr3k-contabo-backup` (visibility **private**;
  created for this purpose).
- Published: `backups/fr3k-contabo-backup-20261026T121051Z.tar.zst.gpg` (765 577 B)
  plus a `SHA256SUMS` entry.
- Read-back verification: GitHub reported the stored blob size as 765 577 B, identical
  to the local ciphertext; the SHA-256 published in the vault matched the downloaded
  bytes during the drill (§5).
- The vault contains ciphertext only. Plaintext never left the host; the passphrase is
  not in the repository.

## 5. Isolated restore drill

Runner: `scripts/contabo-restore-verify.sh --fetch --backup-id 20261026T121051Z`
(downloads the ciphertext from the vault, verifies the published hash, decrypts,
verifies member checksums, then restores into throwaway containers).

Every restore target is a disposable container with `--network none`, a tmpfs data
directory, an ephemeral random password and no published ports. Production was only
read (`COUNT(*)`, `DBSIZE`). Drill window 12:15:42–12:16:42 UTC.

### 5.1 MySQL — PASS

- Published bundle hash matched downloaded bytes before decryption.
- Dump load exit 0; authenticated readiness poll (not `mysqladmin ping`) used.
- **30 / 30 tables present, 0 row-count mismatches, 694 rows restored.**
- Per-table comparison, not a single total, so a compensating error cannot hide.

### 5.2 Redis — PASS

- `dump.rdb` loaded into `redis:8.0-alpine` with persistence disabled.
- Production `DBSIZE` 39, restored `DBSIZE` 39.

### 5.3 Gitea PostgreSQL — PASS

- `pg_dump -Fc` restored with `pg_restore --no-owner --no-privileges`.
- **117 / 117 tables present, 0 row-count mismatches (139 rows).**
- Readiness used an authenticated `SELECT 1` against the target database: `pg_isready`
  answers against the temporary initdb server and produced a false "shutting down"
  failure on the first attempt, so the script now requires a stable authenticated
  query before restoring (same class of bug as `mysqladmin ping`).

### 5.4 Production untouched

- All 11 containers were up before and after the drill, with unchanged uptime strings.
- The Hermes gateway unit kept `MainPID` 4136727, `NRestarts=0`, `SubState=running`.
- The drill's only production reads were `information_schema`/`COUNT(*)` and `DBSIZE`.
- Cleanup verified: 0 `restore-test-*` containers remained afterwards.

## 6. Deliverables in this repository

| Path | Purpose |
|---|---|
| `scripts/contabo-backup.sh` | backup producer: dumps, pack, encrypt, publish, verify read-back, `--no-upload` and `--prune` modes, free-disk guard |
| `scripts/contabo-restore-verify.sh` | isolated restore drill with per-table/per-key parity and hard PASS/FAIL verdicts |
| `ops/systemd/fr3k-contabo-backup.service` | oneshot backup unit (not installed) |
| `ops/systemd/fr3k-contabo-backup.timer` | daily schedule with capacity guard (not installed) |
| `docs/CONTABO_BACKUP_RESTORE_20261026.md` | this evidence document |

Reproduce end to end:

```bash
# backup (writes ciphertext locally, then uploads to the private vault)
FR3K_BACKUP_ROOT=/var/backups/fr3k-voice ./scripts/contabo-backup.sh
# restore proof against the off-VPS copy
FR3K_BACKUP_PASSFILE=/root/.fr3k-backup-keys/<id>.pass \
  ./scripts/contabo-restore-verify.sh --fetch --backup-id <id>
```

## 7. Remaining blockers

### 7.1 Scheduled backups are not enabled (needs approval)

The unit and timer in `ops/systemd/` are prepared but **not installed**. Enabling a
timer changes host state and is a production mutation, so it is held for explicit
operator approval. Until then backups are operator-triggered.

### 7.2 Key custody is the real disaster-recovery gap — BLOCKED on a human

Each backup generates its own passphrase, stored root-only on the same host as the
data. The off-VPS copy is therefore **only recoverable if the operator exports that
passphrase** to a password manager or hardware token. The verification fingerprint of
the passphrase (SHA-256 prefix) is kept in the private operator handover and is
deliberately not published here. This is the one item no agent can close on the
operator's behalf; until it is done, "off-VPS backup" is verified but "survive total
host loss" is **PARTIALLY_VERIFIED**.

### 7.3 Capacity and retention alerting is not active

Retention is a policy, not an automatic action. The script refuses to run under 10 GB
free, and `--prune` only *lists* candidates: a bundle may be deleted only after a newer
bundle has passed a drill. Adding alerting on vault size/incomplete uploads requires
credentials or a monitoring endpoint the operator must nominate.

### 7.4 Parrot-side storage

The earlier deployment record notes the operator's Parrot machine is near full. That
remains a constraint on any second off-VPS copy; the GitHub vault is currently the only
verified off-host destination.

## 8. What this evidence does not claim

- Not a claim that a bare-metal rebuild is scripted or timed. No restore of the
  operating system, container images or model weights was exercised.
- Not a claim that the Gitea Actions runners or LLM router state are fully captured
  (runner registration tokens and router volume data are configuration, re-creatable,
  and excluded by design).
- Not a claim of approval for the scheduled timer, key export, or any pruning.
