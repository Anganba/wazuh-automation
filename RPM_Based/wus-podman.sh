#!/bin/bash
# Uninstall script for Wazuh Agent Podman deployment

CONTAINER_NAME="wazuh-agent-host"
IMAGE_NAME="wazuh-agent-custom"
PODMAN_DIR="/opt/wazuh-agent-podman"
SERVICE_NAME="container-${CONTAINER_NAME}.service"

echo "🧹 Starting Wazuh Agent cleanup..."

# 1. Stop and remove container
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}\$"; then
    echo "🛑 Stopping container: $CONTAINER_NAME"
    podman stop "$CONTAINER_NAME" || true
    echo "🗑 Removing container: $CONTAINER_NAME"
    podman rm "$CONTAINER_NAME" || true
else
    echo "ℹ️ No container named $CONTAINER_NAME found."
fi

# 2. Remove image
if podman images --format "{{.Repository}}" | grep -q "^${IMAGE_NAME}\$"; then
    echo "🗑 Removing image: $IMAGE_NAME"
    podman rmi -f "$IMAGE_NAME" || true
else
    echo "ℹ️ No image named $IMAGE_NAME found."
fi

# 3. Remove systemd unit
if [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
    echo "🗑 Removing systemd service: $SERVICE_NAME"
    sudo systemctl disable --now "$SERVICE_NAME" || true
    sudo rm -f "/etc/systemd/system/$SERVICE_NAME"
    sudo systemctl daemon-reload
else
    echo "ℹ️ No systemd service $SERVICE_NAME found."
fi

# 4. Remove build directory
if [ -d "$PODMAN_DIR" ]; then
    echo "🗑 Removing build directory: $PODMAN_DIR"
    rm -rf "$PODMAN_DIR"
else
    echo "ℹ️ No build directory $PODMAN_DIR found."
fi

echo "✅ Wazuh Agent Podman cleanup complete!"

