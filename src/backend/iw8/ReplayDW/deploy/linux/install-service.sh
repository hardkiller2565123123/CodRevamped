#!/bin/sh
set -eu
# Run as root after deploying a hash-verified binary and migrated runtime state.
test "$(id -u)" = 0
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
id replay-dw >/dev/null 2>&1 || useradd --system --home /var/lib/replay-dw --shell /usr/sbin/nologin replay-dw
install -d -m 700 -o replay-dw -g replay-dw /var/lib/replay-dw
install -d -m 700 /var/backups/replay-dw
chown -R replay-dw:replay-dw /var/lib/replay-dw
find /var/lib/replay-dw -type d -exec chmod 700 {} +
find /var/lib/replay-dw -type f -exec chmod 600 {} +
install -m 644 "$source_dir/replay-dw.service" /etc/systemd/system/
install -m 644 "$source_dir/replay-dw-backup.service" /etc/systemd/system/
install -m 644 "$source_dir/replay-dw-backup.timer" /etc/systemd/system/
install -m 755 "$source_dir/backup-state.sh" /opt/replay-dw/backup-state.sh
install -m 644 "$source_dir/replay-dw.logrotate" /etc/logrotate.d/replay-dw
systemctl daemon-reload
systemctl enable replay-dw replay-dw-backup.timer
# Keep SSH reachable; only expose the native emulator endpoints.
ufw allow 22/tcp
ufw allow 8085/tcp
ufw allow 8443/tcp
ufw allow 3075/tcp
ufw allow 3076:3109/udp
ufw --force enable
systemctl start replay-dw replay-dw-backup.timer
