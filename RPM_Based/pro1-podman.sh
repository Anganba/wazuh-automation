#!/bin/bash

# --- Configuration ---
WAZUH_MANAGER_IP="206.162.244.158"
IMAGE_NAME="wazuh-agent-custom"
CONTAINER_NAME="wazuh-agent-host"
PODMAN_DIR="/opt/wazuh-agent-podman"

set -e

echo "🚀 Starting Wazuh Agent Podman Deployment..."

# Prompt for agent name
read -p "Please enter a name for this Wazuh agent (e.g., 'almalinux-production'): " AGENT_NAME

if [ -z "$AGENT_NAME" ]; then
    echo "❌ Error: Agent name cannot be empty. Aborting."
    exit 1
fi

# Remove spaces
if [[ "$AGENT_NAME" != "${AGENT_NAME// /}" ]]; then
   echo "⚠️  Spaces are not allowed in agent names. They have been removed."
   AGENT_NAME="${AGENT_NAME// /}"
   echo "The agent will be registered as: $AGENT_NAME"
fi
echo "✅ Agent will be named '$AGENT_NAME'."

# 1. Check for Podman
if ! command -v podman &> /dev/null; then
    echo "❌ Error: Podman is not installed. Please install Podman and try again."
    exit 1
fi
echo "✅ Podman installation found."

# 2. Create Directory and Containerfile
echo "📁 Creating directory and Containerfile at $PODMAN_DIR..."
mkdir -p "$PODMAN_DIR"
cd "$PODMAN_DIR"

cat > Containerfile << EOF
FROM almalinux:9

ARG WAZUH_AGENT_NAME="podman-agent"
ARG WAZUH_MANAGER_IP="127.0.0.1"

ENV WAZUH_AGENT_NAME="\${WAZUH_AGENT_NAME}" \
    WAZUH_MANAGER_IP="\${WAZUH_MANAGER_IP}"

# Fix curl-minimal conflict by swapping it out
RUN dnf -y update && \
    dnf -y swap curl-minimal curl && \
    dnf -y install gnupg2 procps systemd && \
    dnf clean all

# Install Wazuh repository
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /etc/pki/rpm-gpg/GPG-KEY-WAZUH && \
    rpm --import /etc/pki/rpm-gpg/GPG-KEY-WAZUH && \
    cat <<EOT > /etc/yum.repos.d/wazuh.repo
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/GPG-KEY-WAZUH
enabled=1
EOT

# Install Wazuh agent
RUN dnf -y install wazuh-agent && dnf clean all

# Configure the agent's manager IP
RUN sed -i "s|<address>MANAGER_IP</address>|<address>\${WAZUH_MANAGER_IP}</address>|" /var/ossec/etc/ossec.conf

# Add basic host monitoring configuration
RUN sed -i '/<\/ossec_config>/i \
  <syscheck>\
    <directories check_all="yes">/host/root/etc,/host/root/usr/bin,/host/root/usr/sbin</directories>\
    <directories check_all="yes">/host/root/home,/host/root/root</directories>\
  </syscheck>' /var/ossec/etc/ossec.conf

# Start script to handle container lifecycle
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/var/ossec/bin/wazuh-control start' >> /start.sh && \
    echo 'tail -f /var/ossec/logs/ossec.log' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]
EOF
echo "✅ Containerfile created successfully."

# 3. Build the Podman Image with Manager IP + Agent Name
echo "🛠️  Building Podman image: $IMAGE_NAME..."
podman build \
    --build-arg WAZUH_AGENT_NAME="$AGENT_NAME" \
    --build-arg WAZUH_MANAGER_IP="$WAZUH_MANAGER_IP" \
    -t "$IMAGE_NAME" -f Containerfile .
echo "✅ Podman image built successfully."

# 4. Stop and Remove Existing Container (if exists)
if [ "$(podman ps -a -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "🔍 Found existing container '$CONTAINER_NAME'. Stopping and removing it..."
    podman stop "$CONTAINER_NAME"
    podman rm "$CONTAINER_NAME"
    echo "✅ Old container removed."
fi

# 5. Run the New Container
echo "▶️  Running new Podman container: $CONTAINER_NAME..."
podman run -d \
  --name="$CONTAINER_NAME" \
  --restart=always \
  --pid=host \
  --net=host \
  --privileged \
  -v /:/host/root:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -e HOST_HOSTNAME="$(hostname)" \
  "$IMAGE_NAME"

# 6. Generate and enable systemd service
echo "⚙️  Generating systemd service for Podman container..."
podman generate systemd --name "$CONTAINER_NAME" --files --new

sudo mv "container-${CONTAINER_NAME}.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now "container-${CONTAINER_NAME}.service"

# --- Finished ---
echo ""
echo "🎉 Deployment complete!"
echo "Your Wazuh agent named '$AGENT_NAME' is now running in a Podman container."
echo "It is also registered as a systemd service:"
echo "  systemctl status container-${CONTAINER_NAME}.service"
echo ""
echo "The agent is configured to monitor your AlmaLinux host system."
echo ""
echo "To check container logs, run:"
echo "  podman logs $CONTAINER_NAME"
echo ""
echo "To check service logs, run:"
echo "  journalctl -u container-${CONTAINER_NAME}.service -f"
echo ""
echo "The new agent should appear on your Wazuh dashboard shortly. ✨"

