#!/bin/bash
set -euo pipefail

echo "============================================================"
echo "   Wazuh ProcMon Prerequisites Installer (AlmaLinux/RHEL)   "
echo "============================================================"

# 1. Install auditd if missing
if ! rpm -q audit >/dev/null 2>&1; then
  echo "ℹ️  Installing auditd..."
  dnf -y install audit audit-libs || { echo "❌ Failed to install auditd"; exit 1; }
else
  echo "✅ auditd already installed."
fi

# 2. Enable + start auditd
echo "ℹ️  Enabling and starting auditd service..."
systemctl enable --now auditd
systemctl status auditd --no-pager

# 3. Configure audit rules for process exec monitoring
RULE_FILE="/etc/audit/rules.d/wazuh-exec-monitor.rules"
echo "ℹ️  Installing audit rule for execve monitoring -> $RULE_FILE"

cat > "$RULE_FILE" <<'EOF'
# Wazuh ProcMon: monitor process executions
-a always,exit -F arch=b64 -S execve -k wazuh_execmon
-a always,exit -F arch=b32 -S execve -k wazuh_execmon
EOF

# Reload rules
echo "ℹ️  Reloading audit rules..."
augenrules --load
auditctl -l | grep execve || echo "⚠️ Execve audit rule not active!"

# 4. Ensure Podman container has audit log mount
CONTAINER="wazuh-agent-host"
if podman ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "✅ Container $CONTAINER is running."
  echo "ℹ️  Checking if /var/log/audit is mounted..."
  if ! podman inspect "$CONTAINER" | grep -q "/var/log/audit"; then
    echo "⚠️  Audit log not mounted. Re-run your Wazuh container with:"
    echo "    podman run -d --name wazuh-agent-host \\"
    echo "      -v /var/log/audit:/host/root/var/log/audit:ro \\"
    echo "      (plus your existing options...)"
  else
    echo "✅ /var/log/audit is mounted into container."
  fi
else
  echo "⚠️  Wazuh agent container not running. Start it with audit log mount."
fi

echo "============================================================"
echo "✅ Prerequisites installed. auditd is running & execve rules active."
echo "   Logs: tail -f /var/log/audit/audit.log"
echo "   You should now see exec events that ProcMon can parse in Wazuh."
echo "============================================================"
