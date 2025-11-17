#!/bin/bash

# Complete Wazuh Docker Agent Cleanup Script
# This script removes ALL traces of the Wazuh Docker deployment

# --- Configuration ---
CONTAINER_NAME="wazuh-agent-host"
IMAGE_NAME="wazuh-agent-custom"
DOCKER_DIR="/opt/wazuh-agent-docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Functions ---
print_header() {
    echo -e "${YELLOW}================================================================${NC}"
    echo -e "${YELLOW}           Wazuh Docker Agent Complete Cleanup${NC}"
    echo -e "${YELLOW}================================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# --- Script Start ---
clear
print_header
echo ""
echo -e "${RED}🛑 DANGER ZONE 🛑${NC}"
echo "This script will PERMANENTLY remove:"
echo "  • Docker container: $CONTAINER_NAME"
echo "  • Docker image: $IMAGE_NAME"
echo "  • Directory: $DOCKER_DIR"
echo "  • All associated volumes and data"
echo "  • All created scripts in current directory"
echo ""
print_warning "The agent will also need to be manually removed from Wazuh Manager!"
echo ""

# Confirmation
read -p "Are you absolutely sure you want to proceed? (type 'DELETE' to confirm): " CONFIRM
if [[ "$CONFIRM" != "DELETE" ]]; then
    echo "Operation cancelled. No changes made."
    exit 0
fi

echo ""
echo "🚀 Starting complete cleanup process..."
echo ""

# Step 1: Stop and remove Docker container
echo "🔍 Step 1: Checking for Docker container '$CONTAINER_NAME'..."
if [ "$(docker ps -a -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "  Container found. Stopping and removing..."
    if docker stop "$CONTAINER_NAME" >/dev/null 2>&1; then
        print_success "Container stopped"
    else
        print_warning "Container was already stopped or failed to stop"
    fi
    
    if docker rm "$CONTAINER_NAME" >/dev/null 2>&1; then
        print_success "Container removed"
    else
        print_error "Failed to remove container"
    fi
else
    print_warning "Container not found (already removed or never existed)"
fi

# Step 2: Remove Docker image
echo ""
echo "🔍 Step 2: Checking for Docker image '$IMAGE_NAME'..."
if [ "$(docker images -q ${IMAGE_NAME} 2>/dev/null)" ]; then
    echo "  Image found. Removing..."
    if docker rmi "$IMAGE_NAME" >/dev/null 2>&1; then
        print_success "Docker image removed"
    else
        print_error "Failed to remove Docker image (may be in use by other containers)"
    fi
else
    print_warning "Docker image not found (already removed or never existed)"
fi

# Step 3: Clean up Docker volumes (if any orphaned)
echo ""
echo "🔍 Step 3: Cleaning up orphaned Docker volumes..."
ORPHANED_VOLUMES=$(docker volume ls -qf dangling=true)
if [ ! -z "$ORPHANED_VOLUMES" ]; then
    echo "$ORPHANED_VOLUMES" | xargs docker volume rm >/dev/null 2>&1
    print_success "Orphaned volumes cleaned"
else
    print_warning "No orphaned volumes found"
fi

# Step 4: Remove Docker directory
echo ""
echo "🔍 Step 4: Checking for directory '$DOCKER_DIR'..."
if [ -d "$DOCKER_DIR" ]; then
    echo "  Directory found. Removing..."
    if rm -rf "$DOCKER_DIR"; then
        print_success "Directory removed"
    else
        print_error "Failed to remove directory (check permissions)"
    fi
else
    print_warning "Directory not found (already removed or never existed)"
fi

# Step 5: Remove created scripts in current directory
echo ""
echo "🔍 Step 5: Cleaning up created scripts in current directory..."
SCRIPT_FILES=(
    "wazuh_install_docker.sh"
    "wazuh_install_docker_fixed.sh"
    "wazuh_docker_monitoring_script.sh"
    "wazuh_monitoring_script.sh"
    "wazuh_uninstall_docker.sh"
    "wazuh_fim_fix.sh"
    "wazuh_force_sync.sh"
    "wazuh_complete_cleanup.sh"
)

for script in "${SCRIPT_FILES[@]}"; do
    if [ -f "$script" ] && [ "$script" != "wazuh_complete_cleanup.sh" ]; then
        echo "  Found: $script"
        read -p "    Remove $script? (y/n): " remove_script
        if [[ "$remove_script" == "y" || "$remove_script" == "Y" ]]; then
            rm -f "$script"
            print_success "Removed $script"
        else
            print_warning "Kept $script"
        fi
    fi
done

# Step 6: Clean Docker system (optional)
echo ""
echo "🔍 Step 6: Docker system cleanup (optional)..."
read -p "Run 'docker system prune' to clean unused Docker resources? (y/n): " cleanup_docker
if [[ "$cleanup_docker" == "y" || "$cleanup_docker" == "Y" ]]; then
    docker system prune -f >/dev/null 2>&1
    print_success "Docker system cleaned"
fi

# Step 7: Check for any remaining traces
echo ""
echo "🔍 Step 7: Scanning for any remaining traces..."

# Check for any remaining containers with wazuh in name
REMAINING_CONTAINERS=$(docker ps -a --format "table {{.Names}}" | grep -i wazuh 2>/dev/null || true)
if [ ! -z "$REMAINING_CONTAINERS" ]; then
    print_warning "Found other Wazuh-related containers:"
    echo "$REMAINING_CONTAINERS"
fi

# Check for any remaining images with wazuh in name
REMAINING_IMAGES=$(docker images --format "table {{.Repository}}:{{.Tag}}" | grep -i wazuh 2>/dev/null || true)
if [ ! -z "$REMAINING_IMAGES" ]; then
    print_warning "Found other Wazuh-related images:"
    echo "$REMAINING_IMAGES"
fi

# Check for any wazuh processes
WAZUH_PROCESSES=$(ps aux | grep -i wazuh | grep -v grep || true)
if [ ! -z "$WAZUH_PROCESSES" ]; then
    print_warning "Found Wazuh-related processes (native installation?):"
    echo "$WAZUH_PROCESSES"
fi

# Final summary
echo ""
echo "================================================================"
print_success "LOCAL CLEANUP COMPLETED!"
echo "================================================================"
echo ""
print_warning "IMPORTANT: Complete the cleanup by removing the agent from Wazuh Manager:"
echo ""
echo "1. 🌐 Log into your Wazuh Dashboard"
echo "2. 📊 Go to 'Endpoints Summary' or 'Agents' section"
echo "3. 🔍 Find the agent (will show as 'Disconnected' or 'Never connected')"
echo "4. ❌ Select the agent and click 'Remove agent'"
echo "5. ✅ Confirm the removal"
echo ""
print_warning "The agent will remain in the manager's database until manually removed!"
echo ""

# Self-destruct option
echo "================================================================"
read -p "Delete this cleanup script as well? (y/n): " delete_self
if [[ "$delete_self" == "y" || "$delete_self" == "Y" ]]; then
    echo "👋 Goodbye!"
    rm -- "$0"
else
    echo "✅ Cleanup script preserved."
fi
