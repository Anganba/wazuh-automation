#!/bin/bash

CONTAINER_NAME="wazuh-agent-host"

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Error: Container '$CONTAINER_NAME' is not running."
    exit 1
fi

echo "🔧 Fixing Wazuh FIM Configuration..."

# Step 1: Create a complete ossec.conf with proper FIM configuration
docker exec "$CONTAINER_NAME" bash -c 'cat > /var/ossec/etc/ossec.conf << "EOF"
<ossec_config>
  <client>
    <server>
      <address>MANAGER_IP</address>
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

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Monitor host system directories -->
    <directories check_all="yes">/host/root/etc</directories>
    <directories check_all="yes">/host/root/home</directories>
    <directories check_all="yes">/host/root/root</directories>
    <directories check_all="yes">/host/root/usr/bin</directories>
    <directories check_all="yes">/host/root/usr/sbin</directories>
    <directories check_all="yes">/host/root/bin</directories>
    <directories check_all="yes">/host/root/sbin</directories>
    <directories check_all="yes">/host/root/opt</directories>
    <directories check_all="yes">/host/root/var/www</directories>
    
    <!-- Ignore noisy directories -->
    <ignore>/host/root/var/log</ignore>
    <ignore>/host/root/var/cache</ignore>
    <ignore>/host/root/var/tmp</ignore>
    <ignore>/host/root/tmp</ignore>
    <ignore>/host/root/proc</ignore>
    <ignore>/host/root/sys</ignore>
    <ignore>/host/root/dev</ignore>
    <ignore>/host/root/run</ignore>
    <ignore>/host/root/var/lib/docker</ignore>
    
    <!-- File types to ignore -->
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
    
    <auto_ignore frequency="10" timeframe="3600">yes</auto_ignore>
    <alert_new_files>yes</alert_new_files>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/root/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/host/root/var/log/syslog</location>
  </localfile>

  <!-- Active response (optional) -->
  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
EOF'

echo "✅ Configuration file created."

# Step 2: Replace MANAGER_IP with actual IP
docker exec "$CONTAINER_NAME" sed -i 's/MANAGER_IP/206.162.244.158/' /var/ossec/etc/ossec.conf

echo "✅ Manager IP updated."

# Step 3: Ensure proper permissions
docker exec "$CONTAINER_NAME" chown root:ossec /var/ossec/etc/ossec.conf
docker exec "$CONTAINER_NAME" chmod 640 /var/ossec/etc/ossec.conf

echo "✅ Permissions set."

# Step 4: Restart the agent
echo "🔄 Restarting Wazuh agent..."
docker exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control stop
sleep 2
docker exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control start

echo "✅ Agent restarted."

# Step 5: Wait and check status
echo "⏳ Waiting for agent to initialize..."
sleep 10

# Check if syscheck is running
echo "🔍 Checking syscheck status..."
docker exec "$CONTAINER_NAME" /var/ossec/bin/agent_control -i | grep -i syscheck

# Show recent logs
echo "📋 Recent agent logs:"
docker exec "$CONTAINER_NAME" tail -20 /var/ossec/logs/ossec.log

echo ""
echo "🎉 FIM configuration applied!"
echo ""
echo "⏰ Please wait 5-10 minutes for the changes to appear in the dashboard."
echo "The agent needs time to:"
echo "  1. Perform initial file scan"
echo "  2. Send configuration to manager" 
echo "  3. Update dashboard status"
echo ""
echo "If the issue persists, try restarting the agent from the Wazuh dashboard."

