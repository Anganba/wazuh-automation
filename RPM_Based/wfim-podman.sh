#!/bin/bash

CONTAINER_NAME="wazuh-agent-host"
MANAGER_IP="206.162.244.158"

# --- Helpers ---
check_container() {
    if ! podman ps | grep -q "$CONTAINER_NAME"; then
        echo "❌ Error: Container '$CONTAINER_NAME' is not running."
        exit 1
    fi
}

backup_config() {
    echo "✅ Creating backup of current configuration..."
    podman exec "$CONTAINER_NAME" cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%F-%T)
}

restart_agent() {
    echo "🔄 Restarting Wazuh agent..."
    podman exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control stop
    sleep 2
    podman exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control start
    echo "✅ Agent restarted."
}

apply_config() {
    CONFIG_BLOCK="$1"

    # Remove old syscheck block
    podman exec "$CONTAINER_NAME" bash -c "sed -i '/<syscheck>/,/<\/syscheck>/d' /var/ossec/etc/ossec.conf"

    # Safely insert syscheck block before </ossec_config>
    podman exec -i "$CONTAINER_NAME" bash -c "awk -v block='${CONFIG_BLOCK}' '
        /<\/ossec_config>/ { print block }
        { print }
    ' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf"

    restart_agent
}

# --- Full fix option ---
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

</ossec_config>
EOF"
    podman exec "$CONTAINER_NAME" chown root:ossec /var/ossec/etc/ossec.conf
    podman exec "$CONTAINER_NAME" chmod 640 /var/ossec/etc/ossec.conf
    restart_agent
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
options=("Smart Defaults (Recommended)" "Monitor Everything (Noisy)" "Custom Host Monitoring" "Full Rebuild (Clean Slate)" "Abort")
select opt in "${options[@]}"; do
    case $opt in
        "Smart Defaults (Recommended)")
            echo "👍 Applying Smart Defaults..."
            backup_config
            CONFIG_BLOCK='<syscheck>
  <directories check_all="yes">/host/root/etc,/host/root/usr/bin,/host/root/usr/sbin,/host/root/bin,/host/root/sbin</directories>
  <directories check_all="yes">/host/root/home</directories>
  <directories check_all="yes">/host/root/var/www,/host/root/opt</directories>
  <directories check_all="yes">/host/root/root</directories>
</syscheck>'
            apply_config "$CONFIG_BLOCK"
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
            break
            ;;
        "Custom Host Monitoring")
            echo "🎯 Applying custom RPM-based monitoring..."
            backup_config
            CONFIG_BLOCK='<syscheck>
  <directories check_all="yes">/host/root/etc</directories>
  <directories check_all="yes">/host/root/home</directories>
  <directories check_all="yes">/host/root/root</directories>
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
</syscheck>'
            apply_config "$CONFIG_BLOCK"
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

