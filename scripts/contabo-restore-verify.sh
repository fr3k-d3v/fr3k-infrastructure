#!/usr/bin/env bash
# FR3K Contabo — isolated restore drill for an encrypted off-VPS backup bundle.
#
# Reads a gpg-encrypted bundle (AES-256 symmetric), decrypts it into a scratch
# directory, verifies every member checksum, then restores MySQL, Redis and the
# Gitea PostgreSQL dump into throwaway containers:
#   * --network none, tmpfs datadir, ephemeral random password, no published ports
#   * production is only ever READ (COUNT(*), DBSIZE, information_schema)
#   * every test container is removed at the end
#
# Usage:
#   FR3K_BACKUP_PASSFILE=/root/.fr3k-backup-keys/<id>.pass \
#   ./contabo-restore-verify.sh --bundle <file.tar.zst.gpg> --sums SHA256SUMS
#
#   ./contabo-restore-verify.sh --fetch --backup-id <id>   # pull from the vault repo
#
# Exit: 0 = every restore verdict PASS, 1 = any FAIL, 2 = usage/precondition error.
set -uo pipefail

VAULT_REPO="${VAULT_REPO:-fr3k-d3v/fr3k-contabo-backup}"
MYSQL_SRC="${MYSQL_SRC:-fr3k-voice-mysql-1}"
REDIS_SRC="${REDIS_SRC:-fr3k-voice-redis-1}"
PG_SRC="${PG_SRC:-fr3k-forge-db-1}"
MYSQL_IMAGE="${MYSQL_IMAGE:-mysql:8.4}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:8.0-alpine}"
PG_IMAGE="${PG_IMAGE:-postgres:17-alpine}"
WORKDIR="${WORKDIR:-/var/lib/fr3k-hermes/cache/scratch}"

BUNDLE="" ; SUMS="" ; BACKUP_ID="" ; FETCH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --sums) SUMS="$2"; shift 2 ;;
    --backup-id) BACKUP_ID="$2"; shift 2 ;;
    --fetch) FETCH=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
fail() { log "FAIL $*"; RC=1; }

RC=0
: "${FR3K_BACKUP_PASSFILE:?set FR3K_BACKUP_PASSFILE to the passphrase file}"
[ -r "$FR3K_BACKUP_PASSFILE" ] || { log "passphrase file not readable"; exit 2; }
command -v gpg >/dev/null || { log "gpg missing"; exit 2; }
command -v zstd >/dev/null || { log "zstd missing"; exit 2; }

DRILL="$WORKDIR/restore-drill-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$DRILL"
log "drill_dir=$DRILL"

# ---------------------------------------------------------------- 1. obtain bundle
if [ "$FETCH" = 1 ]; then
  [ -n "$BACKUP_ID" ] || { log "--fetch needs --backup-id"; exit 2; }
  gh api "repos/$VAULT_REPO/contents/backups/fr3k-contabo-backup-$BACKUP_ID.tar.zst.gpg" \
     --jq '.content' | base64 -d > "$DRILL/bundle.gpg" || { log "download failed"; exit 2; }
  gh api "repos/$VAULT_REPO/contents/SHA256SUMS" --jq '.content' | base64 -d > "$DRILL/SHA256SUMS.remote"
  BUNDLE="$DRILL/bundle.gpg"; SUMS="$DRILL/SHA256SUMS.remote"
  log "fetched bundle from github $VAULT_REPO ($(stat -c%s "$BUNDLE") bytes)"
fi
[ -n "$BUNDLE" ] && [ -r "$BUNDLE" ] || { log "bundle not readable"; exit 2; }

# ------------------------------------------------------------ 2. integrity of upload
if [ -n "$SUMS" ] && [ -r "$SUMS" ]; then
  base=$(basename "$BUNDLE")
  [ -n "$BACKUP_ID" ] && base="fr3k-contabo-backup-$BACKUP_ID.tar.zst.gpg"
  want=$(awk -v b="$base" '$2==b || $2=="./"b {print $1}' "$SUMS")
  got=$(sha256sum "$BUNDLE" | awk '{print $1}')
  if [ -n "$want" ] && [ "$want" = "$got" ]; then
    log "bundle_sha256=$got (matches published SHA256SUMS)"
  else
    fail "bundle sha256 mismatch (published=${want:-none} actual=$got)"
  fi
else
  log "WARN no SHA256SUMS supplied — bundle hash unchecked"
fi

# ------------------------------------------------------------------ 3. decrypt
gpg --batch --quiet --decrypt --passphrase-file "$FR3K_BACKUP_PASSFILE" \
    --output "$DRILL/bundle.tar.zst" "$BUNDLE" 2>"$DRILL/gpg.err" \
  && log "decrypt=OK" || { log "decrypt FAILED: $(head -2 "$DRILL/gpg.err")"; exit 1; }
tar --zstd -xf "$DRILL/bundle.tar.zst" -C "$DRILL" && log "extract=OK" || { log "extract FAILED"; exit 1; }
( cd "$DRILL" && sha256sum -c SHA256SUMS >"$DRILL/member-sums.log" 2>&1 ) \
  && log "member_checksums=OK ($(wc -l < "$DRILL/member-sums.log") members)" \
  || fail "member checksum mismatch (see member-sums.log)"

# ------------------------------------------------- 4. production truth (read only)
log "reading production row counts (read-only)"
mysql_query() { docker exec -i "$1" sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N --batch' ; }
TABLES=$(docker exec -i "$MYSQL_SRC" sh -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N --batch' <<'SQL'
SELECT table_name FROM information_schema.tables
 WHERE table_schema='xiaozhi_esp32_server' AND table_type='BASE TABLE' ORDER BY table_name;
SQL
)
TABLE_N=$(printf '%s\n' "$TABLES" | grep -c . || true)
log "production_tables=$TABLE_N"
{
  first=1
  for t in $TABLES; do
    [ $first = 1 ] || echo "UNION ALL"
    first=0
    printf "SELECT '%s', COUNT(*) FROM \`xiaozhi_esp32_server\`.\`%s\`\n" "$t" "$t"
  done
  echo ";"
} > "$DRILL/counts.sql"
mysql_query "$MYSQL_SRC" < "$DRILL/counts.sql" | sort > "$DRILL/prod_mysql_counts.tsv" || fail "production count query failed"

PG_ENV=$(docker inspect "$PG_SRC" --format '{{range .Config.Env}}{{println .}}{{end}}')
pg_user=$(printf '%s\n' "$PG_ENV" | sed -n 's/^POSTGRES_USER=//p')
pg_db=$(printf '%s\n' "$PG_ENV" | sed -n 's/^POSTGRES_DB=//p')
# exact per-table counts via query_to_xml (read-only, no psql loop needed)
PG_COUNT_SQL="SELECT relname||E'\\t'||(xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', schemaname, relname), false, true, '')))[1]::text FROM pg_stat_user_tables ORDER BY relname"
docker exec "$PG_SRC" sh -c "exec psql -U \"$pg_user\" -d \"$pg_db\" -Atc \"$PG_COUNT_SQL\"" \
  > "$DRILL/prod_pg_counts.tsv" 2>"$DRILL/prod_pg.err" && log "production_pg_tables=$(grep -c . "$DRILL/prod_pg_counts.tsv")" || fail "production pg count query failed"

PROD_DBSIZE=$(docker exec "$REDIS_SRC" sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning DBSIZE' | tr -d '\r')
log "production_redis_dbsize=$PROD_DBSIZE"

# --------------------------------------------------------- 5. MySQL isolated restore
PW=$(openssl rand -hex 16)
ctr_mysql="restore-test-mysql-$$"
docker rm -f "$ctr_mysql" >/dev/null 2>&1
docker run -d --name "$ctr_mysql" --network none -e MYSQL_ROOT_PASSWORD="$PW" \
  --tmpfs /var/lib/mysql:rw,size=2g "$MYSQL_IMAGE" >/dev/null || { log "mysql container start FAILED"; exit 1; }
ready=0
for _ in $(seq 1 90); do
  if docker exec "$ctr_mysql" sh -c "exec mysql -uroot -p'$PW' -N -e 'SELECT 1'" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ $ready = 1 ]; then log "mysql_restore_target_ready=yes"; else fail "mysql restore target never became ready"; fi
if [ $ready = 1 ]; then
  gunzip -c "$DRILL/xiaozhi_mysql.sql.gz" | docker exec -i "$ctr_mysql" sh -c "exec mysql -uroot -p'$PW'" 2>"$DRILL/mysql_load.err" \
    && log "mysql_dump_load=OK" || fail "mysql dump load failed: $(tail -2 "$DRILL/mysql_load.err")"
  docker exec -i "$ctr_mysql" sh -c "exec mysql -uroot -p'$PW' -N --batch" < "$DRILL/counts.sql" | sort > "$DRILL/restored_mysql_counts.tsv" \
    || fail "restored count query failed"
  if [ ! -s "$DRILL/restored_mysql_counts.tsv" ] || [ ! -s "$DRILL/prod_mysql_counts.tsv" ]; then
    fail "MYSQL_RESTORE_VERDICT: FAIL (empty count set — comparison meaningless)"
  elif diff -q "$DRILL/prod_mysql_counts.tsv" "$DRILL/restored_mysql_counts.tsv" >/dev/null; then
    log "MYSQL_RESTORE_VERDICT: PASS ($(grep -c . "$DRILL/restored_mysql_counts.tsv") tables, 0 mismatches, $(awk -F'\t' '{s+=$2} END{print s}' "$DRILL/restored_mysql_counts.tsv") rows)"
  else
    fail "MYSQL_RESTORE_VERDICT: FAIL"; diff "$DRILL/prod_mysql_counts.tsv" "$DRILL/restored_mysql_counts.tsv" | head -20
  fi
fi
docker rm -f "$ctr_mysql" >/dev/null 2>&1

# --------------------------------------------------------- 6. Redis isolated restore
ctr_redis="restore-test-redis-$$"
chmod 0644 "$DRILL/redis_dump.rdb"   # redis runs as uid 999 inside the throwaway container
docker rm -f "$ctr_redis" >/dev/null 2>&1
docker run -d --name "$ctr_redis" --network none \
  -v "$DRILL/redis_dump.rdb:/data/dump.rdb:ro" "$REDIS_IMAGE" \
  redis-server --dir /data --dbfilename dump.rdb --save "" --appendonly no >/dev/null \
  || fail "redis container start failed"
sleep 4
REST_DBSIZE=$(docker exec "$ctr_redis" redis-cli DBSIZE 2>/dev/null | tr -d '\r')
if [ "$REST_DBSIZE" = "$PROD_DBSIZE" ]; then
  log "REDIS_RESTORE_VERDICT: PASS (prod=$PROD_DBSIZE restored=$REST_DBSIZE)"
else
  fail "REDIS_RESTORE_VERDICT: FAIL (prod=$PROD_DBSIZE restored=${REST_DBSIZE:-none})"
fi
docker rm -f "$ctr_redis" >/dev/null 2>&1

# ------------------------------------------------------ 7. PostgreSQL isolated restore
ctr_pg="restore-test-pg-$$"
docker rm -f "$ctr_pg" >/dev/null 2>&1
docker run -d --name "$ctr_pg" --network none -e POSTGRES_PASSWORD="$PW" -e POSTGRES_USER="$pg_user" -e POSTGRES_DB="$pg_db" \
  --tmpfs /var/lib/postgresql/data:rw,size=1g "$PG_IMAGE" >/dev/null || fail "pg container start failed"
ready=0
# pg_isready answers against the temporary initdb server, where the target database
# does not exist yet ("database system is shutting down" on the real start). Poll an
# authenticated query against the target DB, and require the real server.
for _ in $(seq 1 90); do
  if docker exec "$ctr_pg" sh -c "exec psql -U \"$pg_user\" -d \"$pg_db\" -Atc 'SELECT 1'" >/dev/null 2>&1; then
    sleep 2
    if docker exec "$ctr_pg" sh -c "exec psql -U \"$pg_user\" -d \"$pg_db\" -Atc 'SELECT 1'" >/dev/null 2>&1; then ready=1; break; fi
  fi
  sleep 1
done
[ $ready = 1 ] && log "pg_restore_target_ready=yes" || fail "pg restore target never became ready"
if [ $ready = 1 ]; then
  pg_ok=0
  for attempt in 1 2 3; do
    if docker exec -i "$ctr_pg" sh -c "exec pg_restore -U \"$pg_user\" -d \"$pg_db\" --no-owner --no-privileges" < "$DRILL/forge_gitea.dump" 2>"$DRILL/pg_restore.err"; then
      pg_ok=1; break
    fi
    log "pg_restore attempt $attempt failed: $(tail -1 "$DRILL/pg_restore.err"); retrying after reset"
    docker exec "$ctr_pg" sh -c "exec psql -U \"$pg_user\" -d postgres -Atc 'DROP DATABASE IF EXISTS \"$pg_db\"' -c 'CREATE DATABASE \"$pg_db\"'" >/dev/null 2>&1 || true
    sleep 3
  done
  [ $pg_ok = 1 ] && log "pg_dump_restore=OK" || fail "pg_restore failed: $(tail -2 "$DRILL/pg_restore.err")"
  docker exec "$ctr_pg" sh -c "exec psql -U \"$pg_user\" -d \"$pg_db\" -Atc \"$PG_COUNT_SQL\"" \
    > "$DRILL/restored_pg_counts.tsv" 2>/dev/null || fail "restored pg count query failed"
  if [ ! -s "$DRILL/restored_pg_counts.tsv" ]; then
    fail "PG_RESTORE_VERDICT: FAIL (no tables restored)"
  elif diff -q "$DRILL/prod_pg_counts.tsv" "$DRILL/restored_pg_counts.tsv" >/dev/null; then
    log "PG_RESTORE_VERDICT: PASS ($(grep -c . "$DRILL/restored_pg_counts.tsv") tables, 0 row-count mismatches)"
  else
    fail "PG_RESTORE_VERDICT: FAIL (table/row counts differ)"
    diff "$DRILL/prod_pg_counts.tsv" "$DRILL/restored_pg_counts.tsv" | head -10
  fi
fi
docker rm -f "$ctr_pg" >/dev/null 2>&1

# ------------------------------------------------------------------ 8. cleanliness
leftover=$(docker ps -a --format '{{.Names}}' | grep -c '^restore-test-' || true)
[ "$leftover" = 0 ] && log "cleanup=OK (0 restore containers remain)" || fail "cleanup: $leftover test containers remain"

log "DRILL_DIR=$DRILL"
log "OVERALL=$([ $RC = 0 ] && echo PASS || echo FAIL)"
exit $RC
