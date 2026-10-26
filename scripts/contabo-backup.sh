#!/usr/bin/env bash
# FR3K Contabo — encrypted off-VPS backup producer.
#
# Collects the state that actually matters for recovery (logical DB dumps, Redis RDB,
# service/compose config, deploy manifests), packs it, encrypts it locally with
# AES-256 OpenPGP symmetric encryption and publishes the ciphertext to the private
# vault repository. Nothing leaves the host in plaintext.
#
# Usage:
#   ./contabo-backup.sh                 # backup + publish
#   ./contabo-backup.sh --no-upload     # backup only (still encrypted)
#   ./contabo-backup.sh --prune         # prune vault bundles beyond FR3K_BACKUP_KEEP
#
# Environment:
#   FR3K_BACKUP_ROOT    host backup root           (default /var/backups/fr3k-voice)
#   FR3K_BACKUP_KEYDIR  passphrase dir, root 0700  (default /root/.fr3k-backup-keys)
#   FR3K_BACKUP_KEEP    bundles to retain in vault (default 7)
#   VAULT_REPO          private vault repo         (default fr3k-d3v/fr3k-contabo-backup)
#   MIN_FREE_GB         abort below this free disk (default 10)
#
# Key custody: the passphrase for each backup is generated here and never leaves the
# host automatically. Export it to the operator password manager after every run,
# otherwise the off-VPS copy is unrecoverable if this host is lost.
set -euo pipefail

BACKUP_ROOT="${FR3K_BACKUP_ROOT:-/var/backups/fr3k-voice}"
KEYDIR="${FR3K_BACKUP_KEYDIR:-/root/.fr3k-backup-keys}"
KEEP="${FR3K_BACKUP_KEEP:-7}"
VAULT_REPO="${VAULT_REPO:-fr3k-d3v/fr3k-contabo-backup}"
MIN_FREE_GB="${MIN_FREE_GB:-10}"

MYSQL_SRC="${MYSQL_SRC:-fr3k-voice-mysql-1}"
REDIS_SRC="${REDIS_SRC:-fr3k-voice-redis-1}"
PG_SRC="${PG_SRC:-fr3k-forge-db-1}"

UPLOAD=1 ; PRUNE=0
for a in "$@"; do
  case "$a" in
    --no-upload) UPLOAD=0 ;;
    --prune) PRUNE=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

if [ "$PRUNE" = 1 ]; then
  mapfile -t old < <(gh api "repos/$VAULT_REPO/contents/backups" --jq '.[].name' 2>/dev/null | sort)
  n=${#old[@]}
  log "vault_bundles=$n keep=$KEEP"
  if [ "$n" -le "$KEEP" ]; then log "prune=noop"; exit 0; fi
  for ((i=0; i<n-KEEP; i++)); do
    f="${old[$i]}"
    log "PRUNE candidate $f — only after the newest bundle passed a restore drill"
  done
  log "prune is deliberately manual: delete via the GitHub UI/API once an evidence doc cites the replacement"
  exit 0
fi

free_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then log "ABORT free disk ${free_gb}G < ${MIN_FREE_GB}G"; exit 1; fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
B="$BACKUP_ROOT/$TS"
install -d -m 700 "$B"
log "backup_id=$TS dir=$B"

# --- MySQL: consistent snapshot, no table locks, no downtime ---
docker exec "$MYSQL_SRC" sh -c 'exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" \
  --single-transaction --quick --routines --triggers --events --databases xiaozhi_esp32_server' \
  2>/dev/null | gzip -9 > "$B/xiaozhi_mysql.sql.gz"
gzip -t "$B/xiaozhi_mysql.sql.gz"
log "mysql=OK $(stat -c%s "$B/xiaozhi_mysql.sql.gz")B"

# --- Redis: on-disk RDB via SAVE (no downtime, no flush) ---
docker exec "$REDIS_SRC" sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning SAVE' >/dev/null
docker cp "$REDIS_SRC:/data/dump.rdb" "$B/redis_dump.rdb"
log "redis=OK $(stat -c%s "$B/redis_dump.rdb")B"

# --- Gitea PostgreSQL: custom-format logical dump ---
docker exec "$PG_SRC" sh -c 'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$B/forge_gitea.dump"
log "gitea_pg=OK $(stat -c%s "$B/forge_gitea.dump")B"

# --- Config + Forge git/gitea data (secrets inside the encrypted payload) ---
tar -czf "$B/fr3k-config.tgz" -C / \
  opt/fr3k-cloud/xiaozhi opt/fr3k-cloud/forge opt/fr3k-cloud/webui \
  srv/fr3k/forge/data/git srv/fr3k/forge/data/gitea
tar -tzf "$B/fr3k-config.tgz" >/dev/null
log "config=OK $(stat -c%s "$B/fr3k-config.tgz")B"

# --- Deploy manifests (no secrets) ---
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > "$B/containers.txt"
docker images --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}} {{.Size}}' > "$B/images.txt"
docker volume ls > "$B/volumes.txt"
{ echo "ts_utc=$(date -u +%FT%TZ)"; hostname; . /etc/os-release; echo "$PRETTY_NAME"; uname -r
  echo "docker=$(docker version --format '{{.Server.Version}}')"
  free -h | head -2; df -h /; ss -ltn; } > "$B/host-inventory.txt" 2>&1

( cd "$B" && sha256sum ./*.gz ./*.rdb ./*.dump ./*.tgz ./*.txt > SHA256SUMS )

cat > "$B/BACKUP-META.json" <<META
{"backup_id":"$TS","created_utc":"$(date -u +%FT%TZ)","host":"$(hostname)",
 "sources":{"mysql":"$MYSQL_SRC","redis":"$REDIS_SRC","postgres":"$PG_SRC"},
 "excluded":["model weights","release binaries","raw database datadirs"],
 "encryption":"gpg AES-256 symmetric; passphrase file root-only, operator must export"}
META

# --- Pack + encrypt (plaintext tarball never leaves the host) ---
tar --zstd -cf "$B/fr3k-contabo-backup-$TS.tar.zst" -C "$B" \
  BACKUP-META.json SHA256SUMS xiaozhi_mysql.sql.gz redis_dump.rdb forge_gitea.dump \
  fr3k-config.tgz containers.txt images.txt volumes.txt host-inventory.txt
install -d -m 700 "$KEYDIR"
umask 077
openssl rand -base64 32 > "$KEYDIR/$TS.pass"
gpg --batch --yes --quiet --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 \
  --s2k-mode 3 --s2k-count 65011712 --passphrase-file "$KEYDIR/$TS.pass" \
  -o "$B/fr3k-contabo-backup-$TS.tar.zst.gpg" "$B/fr3k-contabo-backup-$TS.tar.zst"
rm -f "$B/fr3k-contabo-backup-$TS.tar.zst"
log "encrypted=OK $(stat -c%s "$B/fr3k-contabo-backup-$TS.tar.zst.gpg")B"
log "key_passphrase_sha256_prefix=$(sha256sum "$KEYDIR/$TS.pass" | cut -c1-16) (export this passphrase off-host now)"

# --- Publish ciphertext to the private vault (off-VPS copy) ---
if [ "$UPLOAD" = 1 ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  git clone -q "https://github.com/$VAULT_REPO.git" "$work/vault"
  install -m 600 "$B/fr3k-contabo-backup-$TS.tar.zst.gpg" "$work/vault/backups/"
  ( cd "$work/vault/backups" && sha256sum "fr3k-contabo-backup-$TS.tar.zst.gpg" > ../SHA256SUMS )
  ( cd "$work/vault" && git add -A \
    && git -c user.name=fr3k-d3v -c user.email=fr3k-d3v@users.noreply.github.com \
         commit -q -m "vault: encrypted Contabo backup $TS" && git push -q origin main )
  # read back: the remote blob size must match what we uploaded
  remote_size=$(gh api "repos/$VAULT_REPO/contents/backups/fr3k-contabo-backup-$TS.tar.zst.gpg" --jq '.size')
  local_size=$(stat -c%s "$B/fr3k-contabo-backup-$TS.tar.zst.gpg")
  if [ "$remote_size" = "$local_size" ]; then
    log "off_vps_copy=VERIFIED ($VAULT_REPO, $remote_size bytes)"
  else
    log "off_vps_copy=MISMATCH remote=$remote_size local=$local_size"; exit 1
  fi
else
  log "upload=skipped (--no-upload)"
fi

log "BACKUP_ID=$TS"
log "NEXT: run scripts/contabo-restore-verify.sh --fetch --backup-id $TS with FR3K_BACKUP_PASSFILE=$KEYDIR/$TS.pass"
