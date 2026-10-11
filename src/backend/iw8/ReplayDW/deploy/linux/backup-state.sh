#!/bin/sh
set -eu
# Stop the writer for a consistent snapshot. Restore service even if tar fails.
exec 9>/run/replay-dw-backup.lock
flock -n 9 || exit 0
active=0
if systemctl is-active --quiet replay-dw; then active=1; fi
restore() { if [ "$active" = 1 ]; then systemctl start replay-dw; fi; }
trap restore EXIT HUP INT TERM
systemctl stop replay-dw
umask 077
mkdir -p /var/backups/replay-dw
name="/var/backups/replay-dw/state-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar --exclude=server.log --exclude='server.log.*' -czf "$name.pending" -C /var/lib/replay-dw .
mv "$name.pending" "$name"
sha256sum "$name" > "$name.sha256"
# Retain seven days plus the initial migration snapshot stored separately.
find /var/backups/replay-dw -maxdepth 1 -type f -name 'state-*' -mtime +7 -delete
