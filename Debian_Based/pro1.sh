#!/bin/bash

# --- Configuration ---
# Set the IP address of your Wazuh Manager here
WAZUH_MANAGER_IP="206.162.244.158"

# Set the desired names for your Docker image and container
IMAGE_NAME="wazuh-agent-custom"
CONTAINER_NAME="wazuh-agent-host"
DOCKER_DIR="/opt/wazuh-agent-docker"

# This command ensures that the script will exit immediately if a command fails.
set -e

# --- Script Start ---
echo "🚀 Starting Wazuh Agent Docker Deployment..."

# --- NEW: Prompt for Agent Name ---
read -p "Please enter a name for this Wazuh agent (e.g., 'kali-production'): " AGENT_NAME

# --- NEW: Validate the input ---
if [ -z "$AGENT_NAME" ]; then
    echo "❌ Error: Agent name cannot be empty. Aborting."
    exit 1
fi
# Remove spaces from the name, as they are not allowed
if [[ "$AGENT_NAME" != "${AGENT_NAME// /}" ]]; then
   echo "⚠️  Spaces are not allowed in agent names. They have been removed."
   AGENT_NAME="${AGENT_NAME// /}"
   echo "The agent will be registered as: $AGENT_NAME"
fi
echo "✅ Agent will be named '$AGENT_NAME'."

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed. Please install Docker and try again."
    exit 1
fi
echo "✅ Docker installation found."

# 2. Create Directory and Dockerfile
echo "📁 Creating directory and Dockerfile at $DOCKER_DIR..."
mkdir -p "$DOCKER_DIR"
cd "$DOCKER_DIR"

# Create the corrected Dockerfile using a heredoc
cat > Dockerfile << EOF
FROM ubuntu:22.04

# --- MODIFIED: Accept agent name as an argument ---
ARG WAZUH_AGENT_NAME="docker-agent"

# Set environment variables for non-interactive installation
ENV WAZUH_MANAGER="${WAZUH_MANAGER_IP}" \\
    WAZUH_AGENT_NAME="\${WAZUH_AGENT_NAME}" \\
    DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    gnupg2 \\
    apt-transport-https \\
    software-properties-common \\
    lsb-release \\
    procps \\
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \\
    chmod 644 /usr/share/keyrings/wazuh.gpg && \\
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && \\
    apt-get update && \\
    apt-get install -y wazuh-agent && \\
    rm -rf /var/lib/apt/lists/*

# Configure the agent's manager IP
RUN sed -i "s/<address>MANAGER_IP<\/address>/<address>\${WAZUH_MANAGER}<\/address>/" /var/ossec/etc/ossec.conf

# Add basic host monitoring configuration
RUN sed -i '/<\/ossec_config>/i \\
  <syscheck>\\
    <directories check_all="yes">/host/root/etc,/host/root/usr/bin,/host/root/usr/sbin</directories>\\
    <directories check_all="yes">/host/root/home,/host/root/root</directories>\\
  </syscheck>' /var/ossec/etc/ossec.conf

# Start script to handle container lifecycle
RUN echo '#!/bin/bash' > /start.sh && \\
    echo '/var/ossec/bin/wazuh-control start' >> /start.sh && \\
    echo 'tail -f /var/ossec/logs/ossec.log' >> /start.sh && \\
    chmod +x /start.sh

CMD ["/start.sh"]
EOF
echo "✅ Dockerfile created successfully."

# 3. Build the Docker Image
echo "🛠️  Building Docker image: $IMAGE_NAME..."
docker build --build-arg WAZUH_AGENT_NAME="$AGENT_NAME" -t "$IMAGE_NAME" .
echo "✅ Docker image built successfully."

# 4. Stop and Remove Existing Container (if it exists)
if [ "$(docker ps -a -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "🔍 Found existing container '$CONTAINER_NAME'. Stopping and removing it..."
    docker stop "$CONTAINER_NAME"
    docker rm "$CONTAINER_NAME"
    echo "✅ Old container removed."
fi

# 5. Run the New Container with proper host monitoring
echo "▶️  Running new Docker container: $CONTAINER_NAME..."
docker run -d \
  --name="$CONTAINER_NAME" \
  --restart=always \
  --pid=host \
  --net=host \
  --privileged \
  -v /:/host/root:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -e HOST_HOSTNAME="$(hostname)" \
  "$IMAGE_NAME"

# --- Finished ---
echo ""
echo "🎉 Deployment complete!"
echo "Your Wazuh agent named '$AGENT_NAME' is now running in a Docker container."
echo "The agent is configured to monitor your Kali host system."
echo ""
echo "To check the agent logs, run this command:"
echo "  docker logs $CONTAINER_NAME"
echo ""
echo "To configure monitoring options, use the Docker monitoring script."
echo "The new agent should appear on your Wazuh dashboard shortly. ✨"
