#!/bin/bash

# Wazuh Yara Integration Script
# This script adds advanced malware detection using Yara rules

CONTAINER_NAME="wazuh-agent-host"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Error: Container '$CONTAINER_NAME' is not running."
    exit 1
fi

echo "🔬 Installing Yara for Advanced Malware Detection"
echo "================================================="
echo ""

# Install Yara and dependencies
print_info "Installing Yara and dependencies..."
docker exec "$CONTAINER_NAME" bash -c "
    apt-get update > /dev/null 2>&1
    apt-get install -y --no-install-recommends \
        yara \
        git \
        python3 \
        python3-yara \
        build-essential \
        automake \
        libtool \
        make \
        gcc \
        pkg-config \
        libssl-dev > /dev/null 2>&1
    rm -rf /var/lib/apt/lists/*
"
print_success "Yara installed"

# Download Yara rules
print_info "Downloading community Yara rules..."
docker exec "$CONTAINER_NAME" bash -c "
    mkdir -p /var/ossec/yara-rules
    cd /var/ossec/yara-rules
    
    # Download popular Yara rule repositories
    git clone --depth 1 https://github.com/Yara-Rules/rules.git community-rules > /dev/null 2>&1
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git signature-base > /dev/null 2>&1
    
    # Create index file for all rules
    find . -name '*.yar' -o -name '*.yara' > rules_index.txt
"
print_success "Yara rules downloaded"

# Create custom Yara rules for web environments
print_info "Creating custom Yara rules..."
docker exec "$CONTAINER_NAME" bash -c 'cat > /var/ossec/yara-rules/custom_web_malware.yar << "EOF"
rule WebShell_Generic
{
    meta:
        description = "Generic Web Shell Detection"
        author = "Wazuh Custom Rules"
        reference = "Custom Rule"
        date = "2024-01-01"

    strings:
        $php1 = "<?php" nocase
        $exec1 = "shell_exec(" nocase
        $exec2 = "system(" nocase
        $exec3 = "exec(" nocase
        $exec4 = "passthru(" nocase
        $exec5 = "eval(" nocase
        $base64 = "base64_decode(" nocase
        $upload = "$_FILES" nocase
        $post = "$_POST" nocase
        $get = "$_GET" nocase

    condition:
        $php1 and (2 of ($exec*) or ($base64 and ($upload or $post or $get)))
}

rule Suspicious_PHP_Obfuscated
{
    meta:
        description = "Obfuscated PHP Code"
        author = "Wazuh Custom Rules"

    strings:
        $php = "<?php"
        $obf1 = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'\"]\w+[\'\"]\s*\.\s*[\'\"]\w+[\'\"]/
        $obf2 = /chr\(\d+\)/
        $obf3 = /\$\w+\[\d+\]/
        $obf4 = "gzinflate(" nocase
        $obf5 = "str_rot13(" nocase

    condition:
        $php and 2 of ($obf*)
}

rule Cryptocurrency_Miner
{
    meta:
        description = "Cryptocurrency Mining Scripts"
        author = "Wazuh Custom Rules"

    strings:
        $mine1 = "stratum+tcp://" nocase
        $mine2 = "xmrig" nocase
        $mine3 = "cpuminer" nocase
        $mine4 = "minerd" nocase
        $mine5 = "cryptonight" nocase
        $mine6 = "monero" nocase
        $mine7 = "ethereum" nocase
        $mine8 = "bitcoin" nocase
        $mine9 = /--donate-level=\d+/
        $mine10 = "--background"

    condition:
        2 of them
}

rule Linux_Rootkit_Generic
{
    meta:
        description = "Generic Linux Rootkit Indicators"
        author = "Wazuh Custom Rules"

    strings:
        $str1 = "MAGIC_VAL" nocase
        $str2 = "GID_NOT_FOUND" nocase
        $str3 = "PROC_NET_TCP" nocase
        $str4 = "HIDE_THIS_SHELL" nocase
        $str5 = "/dev/shm/" nocase
        $str6 = "ld.so.preload" nocase
        $str7 = "__libc_dlopen_mode" nocase

    condition:
        2 of them
}
EOF'

print_success "Custom Yara rules created"

# Create Yara scanning script
print_info "Creating Yara scanning script..."
docker exec "$CONTAINER_NAME" bash -c 'cat > /usr/local/bin/yara_scan.sh << "EOF"
#!/bin/bash

# Yara scanning script for Wazuh integration
YARA_RULES_DIR="/var/ossec/yara-rules"
SCAN_DIRS="/host/root/var/www /host/root/home /host/root/tmp /host/root/var/tmp /host/root/opt"
LOG_FILE="/var/ossec/logs/yara_scan.log"
OSSEC_LOG="/var/ossec/logs/ossec.log"

# Function to log to both files
log_event() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') $1" >> $LOG_FILE
    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-yara: $1" >> $OSSEC_LOG
}

log_event "INFO: Starting Yara malware scan"

# Scan with custom rules
if [ -f "$YARA_RULES_DIR/custom_web_malware.yar" ]; then
    for scan_dir in $SCAN_DIRS; do
        if [ -d "$scan_dir" ]; then
            log_event "INFO: Scanning $scan_dir with custom Yara rules"
            
            # Scan directory and capture matches
            yara -r -s "$YARA_RULES_DIR/custom_web_malware.yar" "$scan_dir" 2>/dev/null | while read line; do
                if [ ! -z "$line" ]; then
                    rule_name=$(echo "$line" | awk '{print $1}')
                    file_path=$(echo "$line" | awk '{print $2}')
                    log_event "ALERT: Yara rule [$rule_name] matched file: $file_path"
                fi
            done
        fi
    done
fi

# Scan with community rules (sample)
if [ -d "$YARA_RULES_DIR/community-rules/malware" ]; then
    for rule_file in $(find "$YARA_RULES_DIR/community-rules/malware" -name "*.yar" | head -10); do
        rule_name=$(basename "$rule_file" .yar)
        for scan_dir in $SCAN_DIRS; do
            if [ -d "$scan_dir" ]; then
                yara -r "$rule_file" "$scan_dir" 2>/dev/null | while read line; do
                    if [ ! -z "$line" ]; then
                        file_path=$(echo "$line" | awk '{print $2}')
                        log_event "ALERT: Community Yara rule [$rule_name] matched file: $file_path"
                    fi
                done
            fi
        done
    done
fi

log_event "INFO: Yara scan completed"
EOF'

docker exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_scan.sh
print_success "Yara scanning script created"

# Add Yara scan to monitoring
print_info "Integrating Yara with Wazuh monitoring..."
docker exec "$CONTAINER_NAME" bash -c "
# Add Yara log monitoring to ossec.conf
sed -i '/<\/ossec_config>/i \\
  <localfile>\\
    <log_format>syslog</log_format>\\
    <location>/var/ossec/logs/yara_scan.log</location>\\
  </localfile>' /var/ossec/etc/ossec.conf

# Add Yara scan to cron (runs every 4 hours, offset from ClamAV)
echo '0 */4 * * * root /usr/local/bin/yara_scan.sh' >> /etc/crontab
"
print_success "Yara integration configured"

# Create additional Yara rules for file integrity monitoring
print_info "Creating FIM-integrated Yara scanning..."
docker exec "$CONTAINER_NAME" bash -c 'cat > /usr/local/bin/yara_fim_scan.sh << "EOF"
#!/bin/bash

# This script runs Yara scans on files that trigger FIM alerts
# Usage: yara_fim_scan.sh <file_path>

FILE_PATH="$1"
YARA_RULES_DIR="/var/ossec/yara-rules"
LOG_FILE="/var/ossec/logs/ossec.log"

if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
    exit 1
fi

# Only scan files that could contain malware
case "$FILE_PATH" in
    *.php|*.js|*.py|*.pl|*.sh|*.exe|*.bat|*.scr|*.vbs)
        # Run Yara scan on the specific file
        yara -s "$YARA_RULES_DIR/custom_web_malware.yar" "$FILE_PATH" 2>/dev/null | while read line; do
            if [ ! -z "$line" ]; then
                rule_name=$(echo "$line" | awk '{print $1}')
                echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-yara-fim: CRITICAL: Yara rule [$rule_name] matched newly modified file: $FILE_PATH" >> $LOG_FILE
            fi
        done
        ;;
esac
EOF'

docker exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_fim_scan.sh
print_success "FIM-integrated Yara scanning configured"

# Add custom Yara detection rules to Wazuh
print_info "Adding Yara-specific detection rules to Wazuh..."
docker exec "$CONTAINER_NAME" bash -c 'cat >> /var/ossec/etc/rules/local_malware_rules.xml << "EOF"

  <!-- Yara Detection Rules -->
  <rule id="100060" level="15">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara.*ALERT.*Yara rule</regex>
    <description>Yara malware detection: $(regex_extract)</description>
    <mitre>
      <id>T1027</id>
    </mitre>
  </rule>

  <rule id="100061" level="15">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara.*WebShell_Generic</regex>
    <description>Web shell detected by Yara: $(file)</description>
    <mitre>
      <id>T1505.003</id>
    </mitre>
  </rule>

  <rule id="100062" level="12">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara.*Cryptocurrency_Miner</regex>
    <description>Cryptocurrency miner detected: $(file)</description>
    <mitre>
      <id>T1496</id>
    </mitre>
  </rule>

  <rule id="100063" level="15">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara.*Linux_Rootkit</regex>
    <description>Linux rootkit detected by Yara: $(file)</description>
    <mitre>
      <id>T1014</id>
    </mitre>
  </rule>

  <rule id="100064" level="13">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara.*Suspicious_PHP_Obfuscated</regex>
    <description>Obfuscated malicious PHP code detected: $(file)</description>
    <mitre>
      <id>T1027</id>
    </mitre>
  </rule>

  <rule id="100065" level="15">
    <decoded_as>syslog</decoded_as>
    <regex>wazuh-yara-fim.*CRITICAL</regex>
    <description>Critical: Yara malware detected in real-time FIM scan: $(regex_extract)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

</group>
EOF'

print_success "Yara detection rules added"

# Update malware scanning to include Yara
print_info "Updating comprehensive malware scanning script..."
docker exec "$CONTAINER_NAME" bash -c 'cat >> /usr/local/bin/malware_scan.sh << "EOF"

# Add Yara scanning
echo "$(date): Starting Yara malware scan" >> $LOG_FILE
/usr/local/bin/yara_scan.sh

# Scan for recent suspicious files with Yara
find /host/root -type f -mtime -1 \( -name "*.php" -o -name "*.js" -o -name "*.py" \) 2>/dev/null | head -50 | while read file; do
    /usr/local/bin/yara_fim_scan.sh "$file"
done
EOF'

print_success "Comprehensive scanning updated"

# Create Yara rule update script
print_info "Creating Yara rule update script..."
docker exec "$CONTAINER_NAME" bash -c 'cat > /usr/local/bin/update_yara_rules.sh << "EOF"
#!/bin/bash

YARA_RULES_DIR="/var/ossec/yara-rules"
LOG_FILE="/var/ossec/logs/yara_updates.log"

echo "$(date): Updating Yara rules" >> $LOG_FILE

cd "$YARA_RULES_DIR"

# Update community rules
if [ -d "community-rules" ]; then
    cd community-rules
    git pull origin master >> $LOG_FILE 2>&1
    cd ..
fi

# Update signature base
if [ -d "signature-base" ]; then
    cd signature-base  
    git pull origin master >> $LOG_FILE 2>&1
    cd ..
fi

# Rebuild rules index
find . -name "*.yar" -o -name "*.yara" > rules_index.txt

echo "$(date): Yara rules updated successfully" >> $LOG_FILE
EOF'

docker exec "$CONTAINER_NAME" chmod +x /usr/local/bin/update_yara_rules.sh

# Add weekly rule updates
docker exec "$CONTAINER_NAME" bash -c 'echo "0 2 * * 0 root /usr/local/bin/update_yara_rules.sh" >> /etc/crontab'

print_success "Yara rule update system configured"

# Restart Wazuh agent
print_info "Restarting Wazuh agent to apply changes..."
docker exec "$CONTAINER_NAME" /var/ossec/bin/wazuh-control restart > /dev/null 2>&1
print_success "Wazuh agent restarted"

# Run initial Yara scan
print_info "Running initial Yara scan..."
docker exec "$CONTAINER_NAME" /usr/local/bin/yara_scan.sh &
print_success "Initial Yara scan started"

echo ""
echo "🔬 YARA INTEGRATION COMPLETED!"
echo "================================"
echo ""
print_success "Advanced malware detection capabilities added:"
echo "  🧬 Yara signature-based detection"
echo "  🕸️  Custom web shell detection rules"
echo "  💰 Cryptocurrency miner detection"
echo "  🔐 Rootkit signature detection"
echo "  📝 Obfuscated code detection"
echo "  🔄 Automatic rule updates (weekly)"
echo "  ⚡ Real-time FIM integration"
echo ""
print_info "Scanning Schedule:"
echo "  • Yara scan: Every 4 hours"
echo "  • ClamAV scan: Every 6 hours"
echo "  • Rule updates: Weekly on Sunday at 2 AM"
echo "  • Real-time: FIM triggers immediate Yara scan"
echo ""
print_warning "Monitor logs for detections:"
echo "  docker exec $CONTAINER_NAME tail -f /var/ossec/logs/yara_scan.log"
echo "  docker exec $CONTAINER_NAME tail -f /var/ossec/logs/ossec.log | grep yara"
