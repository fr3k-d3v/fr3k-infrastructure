#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'sudo required' >&2; exit 1; }
umask 077
install -d -m0755 /srv/fr3k/forge/data /srv/fr3k/forge/postgres /opt/fr3k-cloud/forge
install -d -m0700 /etc/fr3k-cloud
if [[ ! -f /etc/fr3k-cloud/forge.env ]]; then
  {
    for var in GITEA_DB_PASSWORD GITEA_SECRET_KEY GITEA_INTERNAL_TOKEN GITEA_LFS_SECRET; do
      printf '%s=%s\n' "$var" "$(openssl rand -hex 32)"
    done
  } > /etc/fr3k-cloud/forge.env
fi
chmod 0600 /etc/fr3k-cloud/forge.env
install -m0644 /tmp/compose-forge.yml /opt/fr3k-cloud/forge/compose.yml
cd /opt/fr3k-cloud/forge
docker compose --env-file /etc/fr3k-cloud/forge.env config --quiet
docker compose --env-file /etc/fr3k-cloud/forge.env pull
docker compose --env-file /etc/fr3k-cloud/forge.env up -d
echo FORGE_CONTAINERS
docker compose --env-file /etc/fr3k-cloud/forge.env ps
echo FORGE_DEPLOY_STARTED
