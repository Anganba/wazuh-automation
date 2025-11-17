#!/bin/bash

# Production-Safe Wazuh Docker Installation
# This version includes additional safeguards for servers with Imunify360

# --- Configuration ---
WAZUH_MANAGER_IP="206.162.244.158"
IMAGE_NAME="wazuh-agent-production"
CONTAINER_NAME="wazuh-agent-prod"
DOCKER_DIR="/opt/wazuh-agent-docker"

set -e

echo "🏭 Production-Safe Wazuh Agent Deployment"
echo "========================================"
echo ""

# Pre-flight checks
echo "🔍 Running pre-flight checks..."

# Check available resources
AVAILABLE_RAM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
AVAILABLE_DISK=$(df /opt --output=avail -m | tail -n1)
CPU_COUNT=$(nproc)

echo "  - Available RAM: ${AVAILABLE_RAM}MB"
echo "  - Available Disk: ${AVAILABLE_DISK}MB"
echo "  - CPU Cores: ${CPU_COUNT}"

if [ "$AVAILABLE_RAM" -lt 512 ]; then
    echo "⚠️  Warning: Low available RAM. Consider monitoring resource usage."
fi

if [ "$AVAILABLE_DISK" -lt 1024 ]; then
    echo "❌ Error: Insufficient disk space. Need at least 1GB free."
    exit 1
fi

# Check for Imunify360
echo "  - Checking for Imunify360..."
if command -v imunify360-agent >/dev/null 2>&1; then
    echo "  ✅ Imunify360 detected - using compatible configuration"
    IMUNIFY_PRESENT=true
else
    echo "  ℹ️  Imunify360 not detected"
    IMUNIFY_PRESENT=false
fi

# Check for other security software
echo "  - Checking for other security software..."
SECURITY_SOFTWARE=()
command -v clamd >/dev/null 2>&1 && SECURITY_SOFTWARE+=("ClamAV")
command -v rkhunter >/dev/null 2>&1 && SECURITY_SOFTWARE+=("RKHunter")
command -v chkrootkit >/dev/null 2>&1 && SECURITY_SOFTWARE+=("chkrootkit")

if [ ${#SECURITY_SOFTWARE[@]} -gt 0 ]; then
    echo "  ℹ️  Detected security software: ${SECURITY_SOFTWARE[*]}"
fi

echo "✅ Pre-flight checks completed."
echo ""

# Get agent name
read -p "Enter agent name for this production server: " AGENT_NAME
if [ -z "$AGENT_NAME" ]; then
    echo "❌ Error: Agent name cannot be empty."
    exit 1
fi

# Create production-optimized Dockerfile
echo "📁 Creating production-optimized Docker configuration..."
mkdir -p "$DOCKER_DIR"
cd "$DOCKER_DIR"

cat > Dockerfile << EOF
FROM ubuntu:22.04

ARG WAZUH_AGENT_NAME="production-agent"

ENV WAZUH_MANAGER="${WAZUH_MANAGER_IP}" \\
    WAZUH_AGENT_NAME="\${WAZUH_AGENT_NAME}" \\
    DEBIAN_FRONTEND=noninteractive

# Install with minimal footprint
RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl \\
    gnupg2 \\
    apt-transport-https \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/* \\
    && apt-get clean

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \\
    chmod 644 /usr/share/keyrings/wazuh.gpg && \\
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && \\
    apt-get update && \\
    apt-get install -y --no-install-recommends wazuh-agent && \\
    rm -rf /var/lib/apt/lists/* && \\
    apt-get clean

# Production-safe configuration
RUN sed -i "s/<address>MANAGER_IP<\/address>/<address>\${WAZUH_MANAGER}<\/address>/" /var/ossec/etc/ossec.conf

# Conservative monitoring configuration (avoids conflicts with Imunify360)
RUN sed -i '/<\/ossec_config>/i \\
  <syscheck>\\
    <disabled>no</disabled>\\
    <frequency>3600</frequency>\\
    <scan_on_start>yes</scan_on_start>\\
    <directories check_all="yes">/host/root/etc/passwd,/host/root/etc/shadow,/host/root/etc/group</directories>\\
    <directories check_all="yes">/host/root/etc/ssh</directories>\\
    <directories check_all="yes">/host/root/root/.ssh</directories>\\
    <directories check_all="yes">/host/root/home/*/.ssh</directories>\\
    <directories check_all="yes">/host/root/etc/crontab,/host/root/etc/cron.d</directories>\\
    <ignore>/host/root/var/log</ignore>\\
    <ignore>/host/root/var/cache</ignore>\\
    <ignore>/host/root/tmp</ignore>\\
    <ignore>/host/root/proc</ignore>\\
    <ignore>/host/root/sys</ignore>\\
    <ignore>/host/root/dev</ignore>\\
    <ignore>/host/root/var/lib/docker</ignore>\\
    <ignore>/host/root/usr/local/maldetect</ignore>\\
    <auto_ignore frequency="10" timeframe="3600">yes</auto_ignore>\\
  </syscheck>' /var/ossec/etc/ossec.conf

# Resource-conscious startup
RUN echo '#!/bin/bash' > /start.sh && \\
    echo 'nice -n 10 /var/ossec/bin/wazuh-control start' >> /start.sh && \\
    echo 'tail -f /var/ossec/logs/ossec.log' >> /start.sh && \\
    chmod +x /start.sh

CMD ["/start.sh"]
EOF

echo "✅ Production configuration created."

# Build with resource limits awareness
echo "🛠️  Building production Docker image..."
docker build --build-arg WAZUH_AGENT_NAME="$AGENT_NAME" -t "$IMAGE_NAME" .

# Stop existing container if present
if [ "$(docker ps -a -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "🔄 Updating existing container..."
    docker stop "$CONTAINER_NAME"
    docker rm "$CONTAINER_NAME"
fi

# Run with production-safe settings
echo "🚀 Deploying production container..."
docker run -d \\
  --name="$CONTAINER_NAME" \\
  --restart=unless-stopped \\
  --memory="256m" \\
  --memory-swap="512m" \\
  --cpus="0.5" \\
  --security-opt=no-new-privileges:true \\
  --read-only \\
  --tmpfs /tmp \\
  --tmpfs /var/ossec/queue \\
  -v /:/host/root:ro \\
  -v /var/run/docker.sock:/var/run/docker.sock:ro \\
  "$IMAGE_NAME"

echo ""
echo "🎉 Production deployment complete!"
echo ""
echo "📊 Container resource limits:"
echo "  - Memory: 256MB (512MB with swap)"
echo "  - CPU: 0.5 cores maximum"
echo "  - Priority: Lower than system processes"
echo ""
echo "🔒 Security features enabled:"
echo "  - Read-only container filesystem"
echo "  - No privilege escalation"
echo "  - Host filesystem mounted read-only"
echo ""

if [ "$IMUNIFY_PRESENT" = true ]; then
    echo "🛡️  Imunify360 compatibility notes:"
    echo "  - Conservative file monitoring to avoid overlap"
    echo "  - Resource limits to prevent interference"
    echo "  - Lower process priority"
    echo ""
fi

echo "⏰ The agent will appear in your dashboard within 5-10 minutes."
