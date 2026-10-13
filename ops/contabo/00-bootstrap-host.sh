#!/usr/bin/env bash
# FR3KD3V Contabo baseline hardening. Requires tested ubuntu SSH key and sudo.
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run as root/sudo' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
echo '[01] SSH key-only, root password SSH disabled'
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/01-fr3k-cloud.conf <<'SSH'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 4
SSH
/usr/sbin/sshd -t
systemctl reload ssh
/usr/sbin/sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication) '
echo '[02] System updates and host firewall'
apt-get update -qq
apt-get install -y -qq ufw fail2ban unattended-upgrades ca-certificates curl gnupg docker.io docker-compose-v2 caddy jq rsync sqlite3 python3-yaml
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH-key-only'
ufw allow 80/tcp comment 'ACME HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable
systemctl enable --now docker fail2ban caddy
cat >/etc/fail2ban/jail.d/fr3k-sshd.local <<'JAIL'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
JAIL
systemctl restart fail2ban
echo '[03] Private directories and safe initial HTTP health check'
install -d -m 0755 /srv/fr3k/releases/public /srv/fr3k/releases/ota-public /opt/fr3k-cloud
install -d -m 0700 /srv/fr3k/releases/staging /etc/fr3k-cloud
cat >/etc/caddy/Caddyfile <<'CADDY'
:80 {
    respond /healthz "FR3KD3V_EDGE_BOOTSTRAP" 200
    respond "Not configured" 404
}
CADDY
caddy fmt --overwrite /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
echo '[04] Diagnostics'
docker --version
docker compose version
ufw status verbose
ss -lntp | grep -E ':(22|80|443)\\b' || true
echo BOOTSTRAP_COMPLETE
