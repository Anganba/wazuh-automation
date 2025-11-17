#!/bin/bash
set -euo pipefail

CONTAINER_NAME="wazuh-agent-host"
YARA_SCAN_INTERVAL_H="4h"
YARA_UPDATE_ONCAL="Sun *-*-* 02:00:00"

die(){ echo "❌ $*" >&2; exit 1; }
info(){ echo "ℹ️  $*"; }
ok(){ echo "✅ $*"; }

require_running_container() {
  command -v podman >/dev/null 2>&1 || die "podman not found"
  podman ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME" || die "Container '$CONTAINER_NAME' is not running"
}

exec_c(){ podman exec "$CONTAINER_NAME" bash -c "$*"; }
exec_ci(){ podman exec -i "$CONTAINER_NAME" bash -c "$*"; }

# --- YARA setup ---
ensure_yara_in_container(){
  info "Installing YARA + git inside container (if missing)..."
  exec_c "dnf -y install yara git which >/dev/null 2>&1 || true"
  exec_c "mkdir -p /var/ossec/yara-rules /var/ossec/logs /usr/local/bin /var/ossec/etc/rules || true"
  exec_c "touch /var/ossec/logs/yara_scan.log /var/ossec/logs/yara_updates.log /var/ossec/logs/ossec.log || true"
  ok "YARA/tooling ensured."
}

install_yara_rules(){
  info "Fetching community YARA rules..."
  exec_c "cd /var/ossec/yara-rules && \
    [ -d community-rules ] || git clone --depth 1 https://github.com/Yara-Rules/rules.git community-rules >/dev/null 2>&1 || true && \
    [ -d signature-base ] || git clone --depth 1 https://github.com/Neo23x0/signature-base.git signature-base >/dev/null 2>&1 || true && \
    find . -type f \\( -name '*.yar' -o -name '*.yara' \\) > rules_index.txt || true"
  ok "Community YARA rules ready."
}

write_custom_yara(){
  exec_ci 'cat > /var/ossec/yara-rules/custom_web_malware.yar << "EOF"
rule WebShell_Generic {
  strings: $php="<?php" nocase $eval="eval(" nocase $exec="shell_exec(" nocase $b64="base64_decode(" nocase
  condition: $php and ( $eval or $exec or $b64 )
}
rule Obfuscated_PHP {
  strings: $o1=/gzinflate\(/ nocase $o2=/str_rot13\(/ nocase
  condition: 1 of them
}
EOF'
  ok "Custom YARA rules written."
}

write_yara_scanner_scripts(){
  exec_ci 'cat > /usr/local/bin/yara_scan.sh << "EOF"
#!/bin/bash
YARA_DIR="/var/ossec/yara-rules"
LOG="/var/ossec/logs/yara_scan.log"
OSSEC_LOG="/var/ossec/logs/ossec.log"
TARGETS="/host/root/var/www /host/root/home /host/root/opt"
log(){ echo "$(date "+%F %T") $*" | tee -a "$LOG"; echo "$(date "+%F %T") wazuh-yara: $*" >> "$OSSEC_LOG"; }
log "INFO: YARA scan started"
[ -f "$YARA_DIR/custom_web_malware.yar" ] && for d in $TARGETS; do [ -d "$d" ] && yara -r -s "$YARA_DIR/custom_web_malware.yar" "$d" 2>/dev/null | while read -r l; do rule=$(echo "$l"|awk "{print \$1}"); file=$(echo "$l"|awk "{print \$2}"); log "ALERT: YARA [$rule] matched $file"; done; done
log "INFO: YARA scan completed"
EOF
chmod +x /usr/local/bin/yara_scan.sh
'
  ok "YARA scanner installed."
}

# --- Wazuh config updates ---
update_ossec_localfiles(){
  info "Configuring Wazuh to ingest YARA + Imunify360 logs..."
  exec_c "sed -i '/yara_scan.log/d;/yara_updates.log/d;/imunify360/d' /var/ossec/etc/ossec.conf || true"
  exec_ci 'awk '\''/<\/ossec_config>/{
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>/var/ossec/logs/yara_scan.log</location>"
    print "  </localfile>"
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>/var/ossec/logs/yara_updates.log</location>"
    print "  </localfile>"
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>/host/root/var/log/imunify360/console.log</location>"
    print "  </localfile>"
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>/host/root/var/log/imunify360/agent.log</location>"
    print "  </localfile>"
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>/host/root/var/log/imunify360/ids.log</location>"
    print "  </localfile>"
  }
  { print }
  '\''' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf || true"
  ok "Localfiles updated."
}

# --- Custom Wazuh rules for YARA + Imunify360 ---
install_custom_rules(){
  info "Installing custom Wazuh rules with MITRE mappings..."
  exec_ci 'cat > /var/ossec/etc/rules/local_rules.xml << "EOF"
<group name="custom-yara-imunify360,">

  <!-- YARA detection -->
  <rule id="100700" level="10">
    <decoded_as>syslog</decoded_as>
    <description>YARA: Malware rule match</description>
    <match>wazuh-yara: ALERT:</match>
    <tag>malware,mitre:T1059,mitre:T1204</tag>
  </rule>

  <!-- YARA FIM triggered -->
  <rule id="100701" level="9">
    <decoded_as>syslog</decoded_as>
    <description>YARA FIM: Suspicious file change</description>
    <match>wazuh-yara-fim:</match>
    <tag>malware,persistence,mitre:T1548,mitre:T1059</tag>
  </rule>

  <!-- YARA info -->
  <rule id="100702" level="3">
    <decoded_as>syslog</decoded_as>
    <description>YARA: Scan info</description>
    <match>wazuh-yara: INFO:</match>
    <tag>scanner</tag>
  </rule>

  <!-- Imunify360 rules -->
  <rule id="100600" level="10">
    <decoded_as>syslog</decoded_as>
    <description>Imunify360: Malware detected</description>
    <match>Detected malware</match>
    <tag>malware,mitre:T1059,mitre:T1204</tag>
  </rule>

  <rule id="100601" level="8">
    <decoded_as>syslog</decoded_as>
    <description>Imunify360: IP blocked</description>
    <match>IP address .* is blocked</match>
    <tag>network,ids,mitre:T1046,mitre:T1040</tag>
  </rule>

  <rule id="100602" level="7">
    <decoded_as>syslog</decoded_as>
    <description>Imunify360: Brute force detected</description>
    <match>brute force</match>
    <tag>bruteforce,auth,mitre:T1110</tag>
  </rule>

</group>
EOF'
  ok "Custom YARA + Imunify360 rules with MITRE tags installed."
}

restart_agent(){
  info "Restarting Wazuh agent..."
  exec_c "/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start || true"
  ok "Agent restarted."
}

# --- Timers for YARA scans ---
host_systemd_units(){
  sudo bash -c "cat > /etc/systemd/system/wazuh-yara-scan.service <<'EOF'
[Unit]
Description=Run YARA malware scan inside ${CONTAINER_NAME}
[Service]
Type=oneshot
ExecStart=/usr/bin/podman exec ${CONTAINER_NAME} /usr/local/bin/yara_scan.sh
EOF"

  sudo bash -c "cat > /etc/systemd/system/wazuh-yara-scan.timer <<'EOF'
[Unit]
Description=Schedule YARA malware scan
[Timer]
OnUnitActiveSec=${YARA_SCAN_INTERVAL_H}
Persistent=true
[Install]
WantedBy=timers.target
EOF"

  sudo bash -c "cat > /etc/systemd/system/wazuh-yara-update.service <<'EOF'
[Unit]
Description=Update YARA rules inside ${CONTAINER_NAME}
[Service]
Type=oneshot
ExecStart=/usr/bin/podman exec ${CONTAINER_NAME} bash -c '
  cd /var/ossec/yara-rules || exit 0
  [ -d community-rules ] && (cd community-rules && git pull -q || true)
  [ -d signature-base ] && (cd signature-base && git pull -q || true)
  find . -type f \\( -name "*.yar" -o -name "*.yara" \\) > rules_index.txt
  echo "$(date): YARA rules updated" >> /var/ossec/logs/yara_updates.log
'
EOF"

  sudo bash -c "cat > /etc/systemd/system/wazuh-yara-update.timer <<'EOF'
[Unit]
Description=Weekly update of YARA rules
[Timer]
OnCalendar=${YARA_UPDATE_ONCAL}
Persistent=true
[Install]
WantedBy=timers.target
EOF"

  sudo systemctl daemon-reload
  sudo systemctl enable --now wazuh-yara-scan.timer wazuh-yara-update.timer
  ok "Systemd timers enabled."
}

# --- Main flow ---
require_running_container
ensure_yara_in_container
install_yara_rules
write_custom_yara
write_yara_scanner_scripts
update_ossec_localfiles
install_custom_rules
restart_agent
host_systemd_units

ok "🎉 Wazuh YARA + Imunify360 with MITRE rules is fully deployed!"
echo "Check logs: podman exec $CONTAINER_NAME tail -f /var/ossec/logs/ossec.log"
