#!/bin/bash
# wfim-podman.sh - FIM configurator (AlmaLinux RPM) — tuned to critical files + /home + baseline helpers
# Updated to include high/medium priority monitoring and baseline creation.

CONTAINER_NAME="wazuh-agent-host"
MANAGER_IP="206.162.244.158"

# --- Helpers ---
check_container() {
    if ! podman ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}\$"; then
        echo "❌ Error: Container '$CONTAINER_NAME' is not running."
        exit 1
    fi
}

backup_config() {
    echo "✅ Creating backup of current configuration..."
    podman exec "$CONTAINER_NAME" bash -c "cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%F-%T) || true"
}

restart_agent() {
    echo "🔄 Restarting Wazuh agent..."
    podman exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control stop || true
    sleep 2
    podman exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control start || true
    echo "✅ Agent restarted."
}

apply_config() {
    # $1 = syscheck block (full XML fragment)
    CONFIG_BLOCK="$1"

    # remove old syscheck block (if any)
    podman exec "$CONTAINER_NAME" bash -c "sed -i '/<syscheck>/,/<\/syscheck>/d' /var/ossec/etc/ossec.conf || true"

    # insert the config block before </ossec_config>
    podman exec -i "$CONTAINER_NAME" bash -c "awk -v block='${CONFIG_BLOCK}' '
/<\/ossec_config>/ { print block }
{ print }
' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf"

    # set perms
    podman exec "$CONTAINER_NAME" bash -c "chown root:ossec /var/ossec/etc/ossec.conf || true; chmod 640 /var/ossec/etc/ossec.conf || true"

    restart_agent
}

create_baselines() {
    echo "🗂 Creating baselines (SUID/SGID + crontabs)..."
    # Create baseline files inside the container under /var/ossec/etc so they persist with container fs
    # SUID/SGID baseline (host paths are mounted as /host/root inside container)
    podman exec "$CONTAINER_NAME" bash -c "mkdir -p /var/ossec/etc/baselines || true"
    podman exec "$CONTAINER_NAME" bash -c "set -o pipefail; find /host/root -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -print0 2>/dev/null | xargs -0 --no-run-if-empty sha256sum > /var/ossec/etc/baselines/suid_sgid_baseline.sha256 || true"
    echo "  - SUID/SGID baseline saved to /var/ossec/etc/baselines/suid_sgid_baseline.sha256 (inside container)"

    # Crontab dump for all users & system cron dirs
    podman exec "$CONTAINER_NAME" bash -c "ls -la /host/root/etc/cron.* /host/root/etc/cron.d /host/root/var/spool/cron 2>/dev/null || true"
    podman exec "$CONTAINER_NAME" bash -c "for u in \$(cut -d: -f1 /host/root/etc/passwd); do crontab -u \"\$u\" -l 2>/dev/null | sed \"s/^/# cron for \$u: /\" ; done > /var/ossec/etc/baselines/all_crontabs.txt || true"
    echo "  - Crontabs dumped to /var/ossec/etc/baselines/all_crontabs.txt (inside container)"

    # Also capture the list of monitored SUID path files (human readable)
    podman exec "$CONTAINER_NAME" bash -c "find /host/root -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -l {} \\; > /var/ossec/etc/baselines/suid_sgid_list.txt || true"

    echo "✅ Baselines created."
    echo "You can copy them out with: podman cp ${CONTAINER_NAME}:/var/ossec/etc/baselines ./"
}

# --- Full rebuild option (keeps only essential client block and syscheck placeholder) ---
full_rebuild_config() {
    echo "🔧 Rebuilding full ossec.conf with AlmaLinux FIM configuration..."
    podman exec "$CONTAINER_NAME" bash -c "cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>${MANAGER_IP}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>generic</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Log analysis (RPM-based systems) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/root/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/host/root/var/log/messages</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
  </active-response>

  <!-- Minimal syscheck placeholder (recommended to run baseline after) -->
  <syscheck>
    <directories check_all=\"yes\">/host/root/etc</directories>
  </syscheck>

</ossec_config>
EOF"
    podman exec "$CONTAINER_NAME" bash -c "chown root:ossec /var/ossec/etc/ossec.conf || true; chmod 640 /var/ossec/etc/ossec.conf || true"
    restart_agent
    create_baselines
}

# --- Interactive Menu ---
check_container
clear
echo "================================================================"
echo "   Wazuh Podman Agent FIM Configurator (RPM / AlmaLinux)        "
echo "================================================================"
echo ""
echo "⚠️ WARNING: Monitoring too much can cause high CPU and a flood of alerts."
echo ""
PS3="Please select an option: "
options=("Smart Defaults (Recommended)" "Monitor Everything (Noisy)" "Custom Host Monitoring" "Create Baselines (SUID/Crontabs)" "Full Rebuild (Clean Slate)" "Abort")
select opt in "${options[@]}"; do
    case $opt in
        "Smart Defaults (Recommended)")
            echo "👍 Applying Smart Defaults..."
            backup_config
            # Focused, low-noise: critical system files realtime + /home realtime + high/medium (periodic).
            CONFIG_BLOCK='<syscheck>
  <!-- Critical system files - realtime -->
  <directories check_all="yes" realtime="yes">/host/root/etc/passwd</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/shadow</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/group</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/gshadow</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/sudoers</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/sudoers.d</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/ssh/sshd_config</directories>
  <directories check_all="yes" realtime="yes">/host/root/root/.ssh</directories>

  <!-- Home directories (monitor user files & uploads) -->
  <directories check_all="yes" realtime="yes">/host/root/home</directories>

  <!-- High priority persistence/priv-esc locations - realtime small trees -->
  <directories check_all="yes" realtime="yes">/host/root/etc/pam.d</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/ld.so.preload</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/ld.so.conf.d</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/modprobe.d</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/systemd/system</directories>
  <directories check_all="yes" realtime="yes">/host/root/usr/lib/systemd/system</directories>
  <directories check_all="yes" realtime="yes">/host/root/var/spool/cron</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/cron.d</directories>

  <!-- Medium/large areas - periodic scans -->
  <directories check_all="yes">/host/root/boot</directories>
  <directories check_all="yes">/host/root/lib/modules</directories>
  <directories check_all="yes">/host/root/opt</directories>
  <directories check_all="yes">/host/root/usr/local</directories>
  <directories check_all="yes">/host/root/var/www</directories>

  <!-- Frequency: periodic scan every hour -->
  <frequency>3600</frequency>

  <!-- Helpful ignores to reduce noise -->
  <ignore>/host/root/proc</ignore>
  <ignore>/host/root/sys</ignore>
  <ignore>/host/root/dev</ignore>
  <ignore>/host/root/var/log</ignore>
  <ignore>/host/root/var/cache</ignore>
  <ignore>/host/root/var/tmp</ignore>
  <ignore>/host/root/tmp</ignore>
</syscheck>'
            apply_config "$CONFIG_BLOCK"
            # create baselines automatically for Smart Defaults
            create_baselines
            break
            ;;
        "Monitor Everything (Noisy)")
            echo "🚨 Monitoring entire host filesystem..."
            backup_config
            CONFIG_BLOCK='<syscheck>
  <directories check_all="yes" realtime="yes">/host/root</directories>
  <ignore>/host/root/proc</ignore>
  <ignore>/host/root/sys</ignore>
  <ignore>/host/root/dev</ignore>
  <ignore>/host/root/tmp</ignore>
  <ignore>/host/root/var/log</ignore>
  <ignore>/host/root/var/cache</ignore>
  <ignore>/host/root/var/tmp</ignore>
  <ignore>/host/root/run</ignore>
  <ignore>/host/root/mnt</ignore>
  <ignore>/host/root/media</ignore>
</syscheck>'
            apply_config "$CONFIG_BLOCK"
            # recommend creating baselines after choosing noisy mode too
            create_baselines
            break
            ;;
        "Custom Host Monitoring")
            echo "🎯 Applying custom RPM-based monitoring..."
            backup_config
            # lighter custom baseline: critical etc + home + usr bins + web/opt
            CONFIG_BLOCK='<syscheck>
  <directories check_all="yes" realtime="yes">/host/root/etc/passwd</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/shadow</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/sudoers</directories>
  <directories check_all="yes" realtime="yes">/host/root/etc/ssh/sshd_config</directories>
  <directories check_all="yes" realtime="yes">/host/root/root/.ssh</directories>
  <directories check_all="yes" realtime="yes">/host/root/home</directories>
  <directories check_all="yes">/host/root/usr/bin,/host/root/usr/sbin</directories>
  <directories check_all="yes">/host/root/bin,/host/root/sbin</directories>
  <directories check_all="yes">/host/root/opt</directories>
  <directories check_all="yes">/host/root/var/www</directories>
  <ignore>/host/root/var/log</ignore>
  <ignore>/host/root/var/cache</ignore>
  <ignore>/host/root/var/tmp</ignore>
  <ignore>/host/root/tmp</ignore>
  <ignore>/host/root/proc</ignore>
  <ignore>/host/root/sys</ignore>
  <ignore>/host/root/dev</ignore>
  <frequency>3600</frequency>
</syscheck>'
            apply_config "$CONFIG_BLOCK"
            create_baselines
            break
            ;;
        "Create Baselines (SUID/Crontabs)")
            echo "🗂 Creating baselines only (no config changes)..."
            backup_config
            create_baselines
            break
            ;;
        "Full Rebuild (Clean Slate)")
            echo "🛠 Performing full rebuild..."
            full_rebuild_config
            break
            ;;
        "Abort")
            echo "Aborting. No changes made."
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done

echo ""
echo "🎉 Configuration complete!"
echo "To check logs: podman logs $CONTAINER_NAME"
echo "To view config: podman exec $CONTAINER_NAME cat /var/ossec/etc/ossec.conf"
echo "SUID/SGID baseline & crontab dump (if created) are at: /var/ossec/etc/baselines/ inside the container."
