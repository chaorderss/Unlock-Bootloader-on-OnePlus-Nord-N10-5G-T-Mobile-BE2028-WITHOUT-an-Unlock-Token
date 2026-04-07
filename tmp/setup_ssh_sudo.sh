#!/bin/bash
# Run as root: sudo bash /home/phablet/setup_ssh_sudo.sh
set -e

echo "[1/5] Fixing ssh.service broken dependency..."
mkdir -p /etc/systemd/system/ssh.service.d/
cat > /etc/systemd/system/ssh.service.d/fix-deps.conf << 'EOF'
[Unit]
RequiresMountsFor=
Wants=ssh-generate-hostkeys.service
After=network.target auditd.service ssh-generate-hostkeys.service
EOF

echo "[2/5] Setting up persistent sudoers NOPASSWD..."
mkdir -p /home/phablet/.sudoers.d/
cat > /home/phablet/.sudoers.d/phablet-nopasswd << 'EOF'
phablet ALL=(ALL) NOPASSWD: ALL
EOF
chmod 440 /home/phablet/.sudoers.d/phablet-nopasswd
chmod 750 /home/phablet/.sudoers.d/

# Immediate bind mount for this session
mount --bind /home/phablet/.sudoers.d/ /etc/sudoers.d/

echo "[3/5] Creating systemd service for persistent sudoers bind mount..."
cat > /etc/systemd/system/sudoers-nopasswd.service << 'EOF'
[Unit]
Description=Bind mount writable sudoers.d
DefaultDependencies=no
After=local-fs.target
Before=sudo.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount --bind /home/phablet/.sudoers.d /etc/sudoers.d

[Install]
WantedBy=sysinit.target
EOF

echo "[4/5] Enabling services and reloading systemd..."
systemctl daemon-reload
systemctl enable sudoers-nopasswd.service

echo "[5/5] Starting SSH..."
systemctl start ssh

echo ""
echo "=== Done! ==="
systemctl status ssh --no-pager | head -15
echo ""
echo "Your device IP:"
ip addr show wlan0 2>/dev/null | grep 'inet ' || ip addr show | grep 'inet ' | grep -v '127.0.0.1'
