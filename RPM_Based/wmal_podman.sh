#!/bin/bash
set -euo pipefail

CONTAINER_NAME="wazuh-agent-host"

die(){ echo "❌ $*" >&2; exit 1; }
info(){ echo "ℹ️  $*"; }
ok(){ echo "✅ $*"; }

require_running_container() {
  command -v podman >/dev/null 2>&1 || die "podman not found"
  podman ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME" || die "Container '$CONTAINER_NAME' is not running"
}

exec_c(){ podman exec "$CONTAINER_NAME" bash -c "$*"; }

# --- YARA setup ---
ensure_yara_in_container(){
  info "Installing YARA + git inside container (if missing)..."
  exec_c "dnf -y install yara git which coreutils >/dev/null 2>&1 || true"
  exec_c "mkdir -p /var/ossec/yara-rules /var/ossec/logs /usr/local/bin /var/ossec/etc/rules /var/ossec/malware || true"
  exec_c "touch /var/ossec/logs/yara_scan.log /var/ossec/logs/yara_updates.log /var/ossec/logs/ossec.log /var/ossec/malware/allowlist.sha256 || true"
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
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /var/ossec/yara-rules/custom_web_malware.yar >/dev/null
rule WebShell_Generic {
  strings:
    $php = "<?php" nocase
    $eval = "eval(" nocase
    $exec = "shell_exec(" nocase
    $b64 = "base64_decode(" nocase
  condition:
    $php and ( $eval or $exec or $b64 )
}
rule Obfuscated_PHP {
  strings:
    $o1 = "gzinflate(" nocase
    $o2 = "str_rot13(" nocase
  condition:
    1 of them
}
EOF
  ok "Custom YARA rules written."
}

write_yara_scanner_scripts(){
  # Scheduled scan
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /usr/local/bin/yara_scan.sh >/dev/null
#!/bin/bash
YARA_DIR="/var/ossec/yara-rules"
LOG="/var/ossec/logs/yara_scan.log"
OSSEC_LOG="/var/ossec/logs/ossec.log"
TARGETS="/host/root/var/www /host/root/home /host/root/opt"
log(){ echo "$(date "+%F %T") $*" | tee -a "$LOG"; echo "$(date "+%F %T") wazuh-yara: $*" >> "$OSSEC_LOG"; }
log "INFO: YARA scan started"
[ -f "$YARA_DIR/custom_web_malware.yar" ] && for d in $TARGETS; do [ -d "$d" ] && yara -r -s "$YARA_DIR/custom_web_malware.yar" "$d" 2>/dev/null | while read -r l; do rule=$(echo "$l"|awk '{print $1}'); file=$(echo "$l"|awk '{print $2}'); log "ALERT: YARA [$rule] matched $file"; done; done
log "INFO: YARA scan completed"
EOF
  podman exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_scan.sh

  # FIM scan
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /usr/local/bin/yara_fim_scan.sh >/dev/null
#!/bin/bash
FILE="${1:-}"
YARA_DIR="/var/ossec/yara-rules"
OSSEC_LOG="/var/ossec/logs/ossec.log"
[ -n "$FILE" ] && [ -f "$FILE" ] || exit 0
case "$FILE" in
  *.php|*.js|*.py|*.pl|*.sh|*.exe|*.bat|*.scr|*.vbs)
    yara -s "$YARA_DIR/custom_web_malware.yar" "$FILE" 2>/dev/null | while read -r l; do
      rule=$(echo "$l" | awk '{print $1}')
      echo "$(date "+%Y/%m/%d %H:%M:%S") wazuh-yara-fim: ALERT: [$rule] matched: $FILE" >> "$OSSEC_LOG"
    done
  ;;
esac
EOF
  podman exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_fim_scan.sh

  # ProcMon
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /usr/local/bin/yara_procmon.sh >/dev/null
#!/bin/bash
AUDIT_LOG="/host/root/var/log/audit/audit.log"
YARA_DIR="/var/ossec/yara-rules"
OSSEC_LOG="/var/ossec/logs/ossec.log"
ALLOWLIST="/var/ossec/malware/allowlist.sha256"

touch "$OSSEC_LOG" "$ALLOWLIST"

case_paths="/usr/local/ /usr/bin/ /usr/sbin/ /bin/ /sbin/ /var/www/ /home/ /opt/"

in_allowed_path(){
  exe="$1"
  for p in $case_paths; do
    expr "$exe" : "$p" >/dev/null && return 0
  done
  return 1
}

is_safelisted(){
  file="$1"
  [ -f "$file" ] || return 1
  h=$(sha256sum "$file" | awk '{print $1}') || return 1
  grep -qx "$h" "$ALLOWLIST" && return 0
  return 1
}

[ -r "$AUDIT_LOG" ] || { echo "$(date "+%F %T") wazuh-yara-proc: INFO: audit log not readable: $AUDIT_LOG" >> "$OSSEC_LOG"; exit 0; }

tail -Fn0 "$AUDIT_LOG" | \
awk -F "exe=" '/type=SYSCALL/ && /exe="/ { gsub(/"/,"",$2); split($2,a," "); print a[1] }' | \
while read -r exe; do
  host_exe="/host/root${exe}"
  in_allowed_path "$exe" || continue
  is_safelisted "$host_exe" && continue
  [ -f "$host_exe" ] || continue
  yara -s "$YARA_DIR/custom_web_malware.yar" "$host_exe" 2>/dev/null | while read -r l; do
    rule=$(echo "$l" | awk '{print $1}')
    echo "$(date "+%Y/%m/%d %H:%M:%S") wazuh-yara-proc: ALERT: [$rule] matched: $exe" >> "$OSSEC_LOG"
  done
done
EOF
  podman exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_procmon.sh

  # Safelist helper
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /usr/local/bin/yara_allow.sh >/dev/null
#!/bin/bash
FILE="${1:-}"
ALLOWLIST="/var/ossec/malware/allowlist.sha256"
OSSEC_LOG="/var/ossec/logs/ossec.log"
HOST_PREFIX="/host/root"

[ -n "$FILE" ] || { echo "Usage: $0 /absolute/path"; exit 1; }
HOST_FILE="$HOST_PREFIX$FILE"
[ -f "$HOST_FILE" ] || exit 1

hash=$(sha256sum "$HOST_FILE" | awk '{print $1}')
grep -qx "$hash" "$ALLOWLIST" || echo "$hash" >> "$ALLOWLIST"
echo "$(date "+%F %T") wazuh-yara-allow: Added safelist for $FILE ($hash)" >> "$OSSEC_LOG"
EOF
  podman exec "$CONTAINER_NAME" chmod +x /usr/local/bin/yara_allow.sh

  ok "Scanner + ProcMon + allowlist helper installed."
}

# --- Wazuh config updates ---
update_ossec_localfiles(){
  exec_c "sed -i '/yara_scan.log/d;/yara_updates.log/d;/imunify360/d' /var/ossec/etc/ossec.conf || true"
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /tmp/ossec_patch.awk >/dev/null
/<\/ossec_config>/{
  print "  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/yara_scan.log</location></localfile>"
  print "  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/yara_updates.log</location></localfile>"
  print "  <localfile><log_format>syslog</log_format><location>/host/root/var/log/imunify360/console.log</location></localfile>"
  print "  <localfile><log_format>syslog</log_format><location>/host/root/var/log/imunify360/agent.log</location></localfile>"
  print "  <localfile><log_format>syslog</log_format><location>/host/root/var/log/imunify360/ids.log</location></localfile>"
}
{print}
EOF
  podman exec "$CONTAINER_NAME" bash -c "awk -f /tmp/ossec_patch.awk /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf"
}

# --- Custom rules ---
install_custom_rules(){
  cat <<'EOF' | podman exec -i "$CONTAINER_NAME" tee /var/ossec/etc/rules/local_rules.xml >/dev/null
<group name="custom-yara-imunify360,">
  <rule id="100700" level="10"><decoded_as>syslog</decoded_as><description>YARA Malware</description><match>wazuh-yara: ALERT:</match></rule>
  <rule id="100701" level="9"><decoded_as>syslog</decoded_as><description>YARA FIM Suspicious</description><match>wazuh-yara-fim:</match></rule>
  <rule id="100703" level="10"><decoded_as>syslog</decoded_as><description>YARA ProcMon Match</description><match>wazuh-yara-proc: ALERT:</match></rule>
  <rule id="100702" level="3"><decoded_as>syslog</decoded_as><description>YARA Info</description><match>wazuh-yara: INFO:</match></rule>
  <rule id="100600" level="10"><decoded_as>syslog</decoded_as><description>Imunify360 Malware</description><match>Detected malware</match></rule>
  <rule id="100601" level="8"><decoded_as>syslog</decoded_as><description>Imunify360 IP Block</description><match>IP address .* is blocked</match></rule>
  <rule id="100602" level="7"><decoded_as>syslog</decoded_as><description>Imunify360 Brute force</description><match>brute force</match></rule>
</group>
EOF
}

restart_agent(){
  exec_c "/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start"
}

# --- Host systemd ---
host_systemd_units(){
  sudo bash -c "cat > /etc/systemd/system/wazuh-yara-procmon.service <<'EOF'
[Unit]
Description=YARA ProcMon
After=auditd.service

[Service]
Type=simple
ExecStart=/usr/bin/podman exec ${CONTAINER_NAME} /usr/local/bin/yara_procmon.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF"
  sudo systemctl daemon-reload
  sudo systemctl enable --now wazuh-yara-procmon.service
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

ok "🎉 Wazuh + YARA + Imunify360 + ProcMon ready!"

