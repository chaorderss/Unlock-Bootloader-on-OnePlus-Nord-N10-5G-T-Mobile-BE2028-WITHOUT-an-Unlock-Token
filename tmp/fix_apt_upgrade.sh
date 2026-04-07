#!/bin/bash
set -e

# 1. remount root rw
mount -o remount,rw /
echo "[1/5] root remounted rw"

# 2. /var/lib/dpkg -> userdata
UDPKG=/userdata/system-data/var-lib-dpkg
if [ ! -d "$UDPKG" ]; then
    cp -a /var/lib/dpkg/. "$UDPKG/"
    echo "[2/5] dpkg copied to userdata"
else
    echo "[2/5] dpkg dir already on userdata"
fi
mount --bind "$UDPKG" /var/lib/dpkg

# 3. /var/cache/debconf -> userdata
UDEBCONF=/userdata/system-data/var-cache-debconf
if [ ! -d "$UDEBCONF" ]; then
    cp -a /var/cache/debconf/. "$UDEBCONF/"
    echo "[3/5] debconf copied to userdata"
else
    echo "[3/5] debconf dir already on userdata"
fi
mount --bind "$UDEBCONF" /var/cache/debconf

# 4. /var/log/apt -> userdata
mkdir -p /userdata/system-data/var-log-apt
cp -a /var/log/apt/. /userdata/system-data/var-log-apt/ 2>/dev/null || true
mount --bind /userdata/system-data/var-log-apt /var/log/apt
echo "[4/5] log/apt mounted"

# 5. systemd units for persistence
cat > /etc/systemd/system/rootfs-writable.service << 'UNIT'
[Unit]
Description=Remount root filesystem read-write
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount -o remount,rw /

[Install]
WantedBy=sysinit.target
UNIT

cat > /etc/systemd/system/var-lib-dpkg.mount << 'UNIT'
[Unit]
Description=Writable bind mount for /var/lib/dpkg
DefaultDependencies=no
After=local-fs.target rootfs-writable.service
Requires=rootfs-writable.service

[Mount]
What=/userdata/system-data/var-lib-dpkg
Where=/var/lib/dpkg
Type=none
Options=bind

[Install]
WantedBy=local-fs.target
UNIT

cat > /etc/systemd/system/var-cache-debconf.mount << 'UNIT'
[Unit]
Description=Writable bind mount for /var/cache/debconf
DefaultDependencies=no
After=local-fs.target rootfs-writable.service
Requires=rootfs-writable.service

[Mount]
What=/userdata/system-data/var-cache-debconf
Where=/var/cache/debconf
Type=none
Options=bind

[Install]
WantedBy=local-fs.target
UNIT

cat > /etc/systemd/system/var-log-apt.mount << 'UNIT'
[Unit]
Description=Writable bind mount for /var/log/apt
DefaultDependencies=no
After=local-fs.target rootfs-writable.service
Requires=rootfs-writable.service

[Mount]
What=/userdata/system-data/var-log-apt
Where=/var/log/apt
Type=none
Options=bind

[Install]
WantedBy=local-fs.target
UNIT

systemctl enable rootfs-writable.service
systemctl enable var-lib-dpkg.mount
systemctl enable var-cache-debconf.mount
systemctl enable var-log-apt.mount
systemctl daemon-reload
echo "[5/5] systemd units enabled"

echo ""
echo "=== Running apt upgrade ==="
apt upgrade -y 2>&1
