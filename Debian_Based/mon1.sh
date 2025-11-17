#!/bin/bash

# This script configures FIM for a Dockerized Wazuh agent
# Run this on the host machine (Kali)

CONTAINER_NAME="wazuh-agent-host"

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Error: Container '$CONTAINER_NAME' is not running."
    echo "Please start your Wazuh agent container first."
    exit 1
fi

# --- Main Functions ---

backup_config() {
    echo "✅ Creating backup of current configuration..."
    docker exec "$CONTAINER_NAME" cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%F-%T)
}

restart_agent() {
    echo "🔄 Restarting the Wazuh agent to apply changes..."
    docker exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control restart
    echo "✅ Agent restarted successfully."
}

# --- Script Start ---
clear
echo "================================================================"
echo "    Wazuh Docker Agent FIM (File Monitoring) Configurator      "
echo "================================================================"
echo ""
echo "⚠️  **WARNING** ⚠️"
echo "This will configure the Dockerized Wazuh agent to monitor the host Kali system."
echo "Monitoring everything can cause:"
echo "  - High CPU and disk I/O on this server."
echo "  - A very large number of alerts (noise) on your dashboard."
echo "  - Slower performance for applications running on this server."
echo ""
echo "The 'Smart Defaults' option is strongly recommended for most use cases."
echo ""

# --- User Choice ---
PS3="Please select an option: "
options=("Monitor Smart Defaults (Recommended)" "Monitor Everything (Noisy Option)" "Custom Host Monitoring" "Abort")
select opt in "${options[@]}"; do
    case $opt in
        "Monitor Smart Defaults (Recommended)")
            echo "👍 You've chosen the recommended 'Smart Defaults' option."
            backup_config

            # Create the XML block for smart defaults - monitoring host directories
            CONFIG_BLOCK='<syscheck>
      <directories check_all="yes">/host/root/etc,/host/root/usr/bin,/host/root/usr/sbin,/host/root/bin,/host/root/sbin</directories>
      <directories check_all="yes">/host/root/home</directories>
      <directories check_all="yes">/host/root/var/www,/host/root/opt</directories>
      <directories check_all="yes">/host/root/root</directories>
    </syscheck>'

            # Apply configuration inside container
            docker exec "$CONTAINER_NAME" bash -c "
                sed -i '/<syscheck>/,/<\/syscheck>/d' /var/ossec/etc/ossec.conf
                sed -i \"/<\/ossec_config>/i ${CONFIG_BLOCK}\" /var/ossec/etc/ossec.conf
            "

            echo "✅ Configuration updated with smart defaults for host monitoring."
            restart_agent
            break
            ;;
        "Monitor Everything (Noisy Option)")
            echo "🚨 You've chosen to monitor the entire host filesystem."
            backup_config

            # Create the XML block for monitoring everything on host
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

            # Apply configuration inside container
            docker exec "$CONTAINER_NAME" bash -c "
                sed -i '/<syscheck>/,/<\/syscheck>/d' /var/ossec/etc/ossec.conf
                sed -i \"/<\/ossec_config>/i ${CONFIG_BLOCK}\" /var/ossec/etc/ossec.conf
            "

            echo "✅ Configuration updated to monitor everything on host."
            restart_agent
            break
            ;;
        "Custom Host Monitoring")
            echo "🎯 Custom monitoring for security-focused Kali machine."
            backup_config

            # Kali-specific important directories
            CONFIG_BLOCK='<syscheck>
      <directories check_all="yes">/host/root/etc</directories>
      <directories check_all="yes">/host/root/home</directories>
      <directories check_all="yes">/host/root/root</directories>
      <directories check_all="yes">/host/root/usr/bin,/host/root/usr/sbin</directories>
      <directories check_all="yes">/host/root/bin,/host/root/sbin</directories>
      <directories check_all="yes">/host/root/opt</directories>
      <directories check_all="yes">/host/root/var/www</directories>
      <directories check_all="yes">/host/root/usr/share/wordlists</directories>
      <directories check_all="yes">/host/root/usr/share/metasploit-framework</directories>
      
      <ignore>/host/root/var/log</ignore>
      <ignore>/host/root/var/cache</ignore>
      <ignore>/host/root/var/tmp</ignore>
      <ignore>/host/root/tmp</ignore>
      <ignore>/host/root/proc</ignore>
      <ignore>/host/root/sys</ignore>
      <ignore>/host/root/dev</ignore>
    </syscheck>'

            # Apply configuration inside container
            docker exec "$CONTAINER_NAME" bash -c "
                sed -i '/<syscheck>/,/<\/syscheck>/d' /var/ossec/etc/ossec.conf
                sed -i \"/<\/ossec_config>/i ${CONFIG_BLOCK}\" /var/ossec/etc/ossec.conf
            "

            echo "✅ Configuration updated with Kali-specific monitoring."
            restart_agent
            break
            ;;
        "Abort")
            echo "Aborting. No changes have been made."
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done

echo ""
echo "🎉 Configuration complete!"
echo ""
echo "To check the agent logs, run:"
echo "  docker logs $CONTAINER_NAME"
echo ""
echo "To view current configuration:"
echo "  docker exec $CONTAINER_NAME cat /var/ossec/etc/ossec.conf"
