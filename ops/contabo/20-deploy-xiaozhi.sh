#!/usr/bin/env bash
# Private deployment only. Hardware/API onboarding requires independent checks.
set -euo pipefail
test "$(id -u)" = 0 || { echo 'sudo required' >&2; exit 1; }
umask 077
install -d -m 0755 /srv/fr3k/xiaozhi/data /srv/fr3k/xiaozhi/models/SenseVoiceSmall /srv/fr3k/xiaozhi/mysql /srv/fr3k/xiaozhi/redis /srv/fr3k/xiaozhi/uploads /opt/fr3k-cloud/xiaozhi
install -d -m 0700 /etc/fr3k-cloud
if [[ ! -s /etc/fr3k-cloud/xiaozhi.env ]]; then
  {
    printf 'XIAOZHI_DB_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 32)"
    printf 'XIAOZHI_DB_PASSWORD=%s\n' "$(openssl rand -hex 32)"
  } >/etc/fr3k-cloud/xiaozhi.env
fi
chmod 0600 /etc/fr3k-cloud/xiaozhi.env
if [[ ! -s /srv/fr3k/xiaozhi/data/.config.yaml ]]; then
  curl --retry 3 -fLsS 'https://raw.githubusercontent.com/xinnan-tech/xiaozhi-esp32-server/main/main/xiaozhi-server/config_from_api.yaml' -o /srv/fr3k/xiaozhi/data/.config.yaml
fi
chmod 0600 /srv/fr3k/xiaozhi/data/.config.yaml
install -m0644 /tmp/compose-xiaozhi.yml /opt/fr3k-cloud/xiaozhi/compose.yml
cd /opt/fr3k-cloud/xiaozhi
docker compose --env-file /etc/fr3k-cloud/xiaozhi.env config --quiet
docker compose --env-file /etc/fr3k-cloud/xiaozhi.env pull
# Do not start the Python voice server before the admin-generated manager.secret is set.
docker compose --env-file /etc/fr3k-cloud/xiaozhi.env up -d mysql redis manager
docker compose --env-file /etc/fr3k-cloud/xiaozhi.env stop server || true
docker compose --env-file /etc/fr3k-cloud/xiaozhi.env ps
echo XIAOZHI_MANAGER_READY_VOICE_WAITING_FOR_ADMIN_AND_MODEL_CONFIGURATION
