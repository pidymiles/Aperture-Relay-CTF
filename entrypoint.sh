#!/bin/sh
set -eu

mkdir -p /run/sshd /var/log/aperture /data/portal
ssh-keygen -A >/dev/null 2>&1
python3 /app/init_challenge.py
chpasswd < /data/ssh_login.txt
chown -R portal:portal /data/portal
chmod 711 /data
chmod 750 /data/portal
/usr/sbin/sshd
exec /usr/sbin/runuser -u portal -- python3 /app/app.py
