#!/bin/bash

# Fix for Wazuh Docker Installation on AlmaLinux 9
# This script addresses cgroup and systemd integration issues

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo "🔧 Fixing Docker Configuration for AlmaLinux 9"
echo "=============================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root. Please use sudo."
   exit 1
fi

# Step 1: Check Docker installation
print_info "Step 1: Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    print_warning "Docker not found. Installing Docker..."
    
    # Install Docker on AlmaLinux 9
    dnf update -y
    dnf install -y dnf-utils
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    print_success "Docker installed"
else
    print_success "Docker is already installed"
fi

# Step 2: Fix Docker daemon configuration for AlmaLinux 9
print_info "Step 2: Configuring Docker daemon for AlmaLinux 9..."

# Create docker daemon configuration
mkdir -p /etc/docker

cat > /etc/docker/daemon.json << 'EOF'
{
    "exec-opts": ["native.cgroupdriver=systemd"],
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "storage-opts": [
        "overlay2.override_kernel_check=true"
    ],
    "live-restore": true,
    "group": "docker"
}
EOF

print_success "Docker daemon configuration created"

# Step 3: Configure systemd for Docker
print_info "Step 3: Configuring systemd integration..."

# Create systemd drop-in directory
mkdir -p /etc/systemd/system/docker.service.d

# Create override configuration
cat > /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --host=fd:// --add-runtime=nvidia=/usr/bin/nvidia-container-runtime
EOF

print_success "Systemd configuration updated"

# Step 4: Fix cgroup configuration
print_info "Step 4: Fixing cgroup configuration..."

# Ensure cgroup v2 is properly configured
if [ -f /etc/default/grub ]; then
    if ! grep -q "systemd.unified_cgroup_hierarchy=1" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1 /' /etc/default/grub
        print_warning "GRUB configuration updated. You may need to run 'grub2-mkconfig -o /boot/grub2/grub.cfg' and reboot"
    fi
fi

print_success "Cgroup configuration checked"

# Step 5: Restart Docker services
print_info "Step 5: Restarting Docker services..."

systemctl daemon-reload
systemctl restart docker

# Wait for Docker to be ready
sleep 5

if systemctl is-active --quiet docker; then
    print_success "Docker service restarted successfully"
else
    print_error "Docker service failed to start"
    systemctl status docker
    exit 1
fi

# Step 6: Test Docker
print_info "Step 6: Testing Docker installation..."

if docker info > /dev/null 2>&1; then
    print_success "Docker is working correctly"
else
    print_error "Docker test failed"
    docker info
    exit 1
fi

# Step 7: Create AlmaLinux-optimized Wazuh installation script
print_info "Step 7: Creating AlmaLinux-optimized Wazuh installation..."

cat > wazuh_install_almalinux.sh << 'EOF'
#!/bin/bash

# AlmaLinux 9 Optimized Wazuh Agent Docker Installation
# This version addresses AlmaLinux-specific issues

# --- Configuration ---
WAZUH_MANAGER_IP="206.162.244.158"
IMAGE_NAME="wazuh-agent-almalinux"
CONTAINER_NAME="wazuh-agent-host"
DOCKER_DIR="/opt/wazuh-agent-docker"

set -e

echo "🚀 Starting Wazuh Agent Docker Deployment for AlmaLinux 9..."

# Get agent name
read -p "Please enter a name for this Wazuh agent (e.g., 'almalinux-server'): " AGENT_NAME

if [ -z "$AGENT_NAME" ]; then
    echo "❌ Error: Agent name cannot be empty. Aborting."
    exit 1
fi

# Remove spaces
AGENT_NAME="${AGENT_NAME// /}"
echo "✅ Agent will be named '$AGENT_NAME'."

# Create directory
echo "📁 Creating directory and Dockerfile at $DOCKER_DIR..."
mkdir -p "$DOCKER_DIR"
cd "$DOCKER_DIR"

# Create AlmaLinux-compatible Dockerfile
cat > Dockerfile << 'DOCKERFILE_EOF'
FROM almalinux:9

ARG WAZUH_AGENT_NAME="almalinux-agent"

ENV WAZUH_MANAGER="206.162.244.158" \
    WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" \
    container=docker

# Install dependencies
RUN dnf update -y && \
    dnf install -y \
        curl \
        gnupg2 \
        systemd \
        procps-ng \
        which \
        findutils \
        && dnf clean all

# Install Wazuh agent
RUN rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && \
    echo -e '[wazuh]\n\
gpgcheck=1\n\
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\n\
enabled=1\n\
name=EL-$releasever - Wazuh\n\
baseurl=https://packages.wazuh.com/4.x/yum/\n\
protect=1' | tee /etc/yum.repos.d/wazuh.repo && \
    dnf install -y wazuh-agent && \
    dnf clean all

# Configure the agent
RUN sed -i "s/<address>MANAGER_IP<\/address>/<address>${WAZUH_MANAGER}<\/address>/" /var/ossec/etc/ossec.conf

# Add basic monitoring configuration
RUN sed -i '/<\/ossec_config>/i \
  <syscheck>\
    <directories check_all="yes">/host/root/etc,/host/root/usr/bin,/host/root/usr/sbin</directories>\
    <directories check_all="yes">/host/root/home,/host/root/root</directories>\
    <directories check_all="yes">/host/root/var/www,/host/root/opt</directories>\
  </syscheck>' /var/ossec/etc/ossec.conf

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'export container=docker' >> /start.sh && \
    echo '/var/ossec/bin/wazuh-control start' >> /start.sh && \
    echo 'tail -f /var/ossec/logs/ossec.log' >> /start.sh && \
    chmod +x /start.sh

# Use init system
CMD ["/start.sh"]
DOCKERFILE_EOF

echo "✅ AlmaLinux-compatible Dockerfile created."

# Build the image
echo "🛠️  Building Docker image: $IMAGE_NAME..."
docker build --build-arg WAZUH_AGENT_NAME="$AGENT_NAME" -t "$IMAGE_NAME" . || {
    echo "❌ Docker build failed. Checking for issues..."
    docker system df
    docker system prune -f
    echo "Retrying build..."
    docker build --build-arg WAZUH_AGENT_NAME="$AGENT_NAME" -t "$IMAGE_NAME" .
}

echo "✅ Docker image built successfully."

# Stop existing container
if [ "$(docker ps -a -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "🔍 Stopping existing container..."
    docker stop "$CONTAINER_NAME" || true
    docker rm "$CONTAINER_NAME" || true
fi

# Run the container with AlmaLinux-specific settings
echo "▶️  Running new Docker container: $CONTAINER_NAME..."
docker run -d \
  --name="$CONTAINER_NAME" \
  --restart=unless-stopped \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --cap-add SYS_ADMIN \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /:/host/root:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  --cgroupns=host \
  "$IMAGE_NAME"

# Check if container started
sleep 5
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo ""
    echo "🎉 Deployment successful!"
    echo "Agent '$AGENT_NAME' is running on AlmaLinux 9."
    echo ""
    echo "To check logs: docker logs $CONTAINER_NAME"
    echo "To check status: docker exec $CONTAINER_NAME /var/ossec/bin/wazuh-control status"
else
    echo "❌ Container failed to start. Checking logs..."
    docker logs "$CONTAINER_NAME"
fi
EOF

chmod +x wazuh_install_almalinux.sh
print_success "AlmaLinux-optimized installation script created"

echo ""
echo "🎉 AlmaLinux 9 Docker Fix Completed!"
echo "===================================="
echo ""
print_info "What was fixed:"
echo "  • Docker daemon configuration for systemd"
echo "  • Cgroup driver set to systemd"
echo "  • Storage driver optimized for AlmaLinux"
echo "  • Container runtime properly configured"
echo "  • AlmaLinux-specific Wazuh installation created"
echo ""
print_warning "Next Steps:"
echo "  1. Run the AlmaLinux-optimized script:"
echo "     sudo ./wazuh_install_almalinux.sh"
echo ""
echo "  2. If you still get cgroup warnings, you may need to:"
echo "     - Run: grub2-mkconfig -o /boot/grub2/grub.cfg"
echo "     - Reboot the system"
echo "     - Then run the installation script"
echo ""
print_info "The new script uses AlmaLinux base image and proper systemd integration."
