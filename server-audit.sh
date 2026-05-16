#!/usr/bin/env bash
# server-audit - local Linux server security audit
set -o pipefail

BOLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'
GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; CYN='\033[0;36m'; WHT='\033[1;37m'
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
    BOLD=''; DIM=''; RST=''; GRN=''; RED=''; YLW=''; CYN=''; WHT=''
fi

PASS=0; FAIL=0; WARN=0; SKIP=0
SYSTEMCTL_OK=false
IS_ROOT=false; HAS_SUDO=false
if [ "$EUID" -eq 0 ]; then IS_ROOT=true
elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then HAS_SUDO=true; fi

# Output helpers
p() { PASS=$((PASS+1)); printf " ${GRN}[PASS]${RST} %s\n" "$1"; }
f() { FAIL=$((FAIL+1)); printf " ${RED}[FAIL]${RST} %-40s ${RED}%s${RST}\n" "$1" "${2:-}"; }
w() { WARN=$((WARN+1)); printf " ${YLW}[WARN]${RST} %s\n" "$1"; [ -n "${2:-}" ] && printf "        ${DIM}%s${RST}\n" "$2"; }
i() { printf " ${DIM}[INFO]${RST} %s\n" "$1"; [ -n "${2:-}" ] && printf "        ${DIM}%s${RST}\n" "$2"; }
s() { SKIP=$((SKIP+1)); printf " ${DIM}[SKIP]${RST} %s  ${DIM}(%s)${RST}\n" "$1" "${2:-}"; }
sec() {
    local label="$1" width=32 pad=1
    [ "${#label}" -lt "$width" ] && pad=$((width-${#label}))
    printf "\n${BOLD}${CYN}%s${RST} ${DIM}%s${RST}\n" "$label" "$(printf '%*s' "$pad" '' | tr ' ' '-')"
}

# Utility: count lines from a command (pipefail-safe via subshell)
_lcount() { local n; n=$( (set +o pipefail; "$@" 2>/dev/null | wc -l) ); echo "${n//[[:space:]]/}"; }

run_root() {
    if [ "$IS_ROOT" = true ]; then
        "$@"
    elif [ "$HAS_SUDO" = true ]; then
        sudo "$@"
    else
        "$@"
    fi
}

has_priv() { [ "$IS_ROOT" = true ] || [ "$HAS_SUDO" = true ]; }
svc_active() { [ "$SYSTEMCTL_OK" = true ] && systemctl is-active "$1" &>/dev/null; }
svc_enabled() { command -v systemctl &>/dev/null && systemctl is-enabled "$1" &>/dev/null; }

join_csv() {
    local item out=""
    for item in "$@"; do out="${out:+$out, }$item"; done
    printf "%s" "$out"
}

# Utility: read sshd config value (sshd -T preferred, then file parsing including drop-ins)
_sshd_val() {
    local key="$1" val=""
    if has_priv; then
        val=$(run_root sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}')
    fi
    if [ -z "$val" ]; then
        for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
            [ -f "$f" ] && [ -r "$f" ] || continue
            val=$(grep -i "^[[:space:]]*${key}[[:space:]]" "$f" 2>/dev/null | tail -1 | awk '{print $2}')
            [ -n "$val" ] && break
        done
    fi
    echo "${val}"
}

_sshd_can_read() {
    local f
    has_priv && return 0
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] && [ -r "$f" ] && return 0
    done
    return 1
}

# ==================================================================
printf "\n${BOLD}${WHT}server audit${RST} - %s - %s\n\n" "$(hostname 2>/dev/null || echo unknown)" "$(date '+%Y-%m-%d %H:%M:%S')"

if [ "$IS_ROOT" = true ]; then
    i "Privilege root"
elif [ "$HAS_SUDO" = true ]; then
    i "Privilege passwordless sudo"
else
    w "Privilege limited" "run as root or configure passwordless sudo for complete results"
fi
if command -v systemctl &>/dev/null && systemctl list-units --type=service --state=running --no-legend &>/dev/null; then
    SYSTEMCTL_OK=true
fi

# --- System Overview ---
i "OS       $(awk -F= '/^PRETTY_NAME=/ {gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null || echo unknown)"
i "Kernel   $(uname -r)"
i "Uptime   $(uptime -p 2>/dev/null | sed 's/^up //')"
if [ -f /proc/cpuinfo ]; then
    _c=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "?")
    _m=$(awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
    i "CPU      ${_c} vCPU${_m:+ ($_m)}"
fi
_mt=$(awk '/MemTotal/  {printf "%.1f", $2/1024/1024}' /proc/meminfo 2>/dev/null)
_ma=$(awk '/MemAvailable/ {printf "%.1f", $2/1024/1024}' /proc/meminfo 2>/dev/null)
if [ -n "$_mt" ] && [ -n "$_ma" ]; then
    _mu=$(awk "BEGIN {printf \"%.1f\", ${_mt}-${_ma}}")
    _mp=$(awk "BEGIN {printf \"%.0f\", 100-((${_ma}/${_mt})*100)}")
    i "Memory   ${_mu}/${_mt}G (${_mp}%)"
fi
i "Disk     $(df -h / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
if command -v dpkg &>/dev/null; then
    i "Pkgs     $( (set +o pipefail; dpkg -l 2>/dev/null | grep -c '^ii' || true) ) (dpkg)"
elif command -v rpm &>/dev/null; then
    i "Pkgs     $(_lcount rpm -qa) (rpm)"
fi
[ -f /var/run/reboot-required ] && w "Reboot required" || i "Reboot   no"

# --- SSH ---
sec "SSH"
_chk_ssh() {
    local label="$1" key="$2" expect="$3" fix="${4:-}"
    local val; val=$(_sshd_val "$key")
    if [ -z "$val" ]; then s "$label" "cannot read sshd config"
    elif [ "$val" = "$expect" ]; then p "$label"
    else f "$label" "is '$val', expect '$expect'${fix:+ — $fix}"; fi
}
_chk_ssh "PermitRootLogin no"          permitrootlogin        no  "edit /etc/ssh/sshd_config"
_chk_ssh "PasswordAuthentication no"   passwordauthentication no  "edit /etc/ssh/sshd_config"
_chk_ssh "PubkeyAuthentication yes"    pubkeyauthentication   yes "edit /etc/ssh/sshd_config"

if _sshd_can_read; then
    _val=$(_sshd_val protocol)
    if [ -z "$_val" ]; then
        s "Protocol 2 only" "option absent; modern OpenSSH is protocol 2 only"
    elif [ "$_val" = "2" ]; then
        p "Protocol 2 only"
    else
        f "Protocol 2 only" "is '$_val'"
    fi
    _port=$(_sshd_val port)
    i "Port ${_port:-22}"
    _alive=$(_sshd_val clientaliveinterval)
    [ -n "$_alive" ] && [ "$_alive" -gt 0 ] 2>/dev/null && p "ClientAliveInterval ${_alive}s" \
        || f "ClientAliveInterval" "not configured — /etc/ssh/sshd_config"
    _auth=$(_sshd_val maxauthtries)
    if [ -n "$_auth" ] && [ "$_auth" -le 4 ] 2>/dev/null; then p "MaxAuthTries $_auth"
    elif [ -n "$_auth" ]; then f "MaxAuthTries $_auth" "set to $_auth (>4) — /etc/ssh/sshd_config"
    else w "MaxAuthTries" "(default, likely 6)"; fi
else
    s "Protocol 2 only" "cannot read sshd config"
    s "Port" "cannot read sshd config"
    s "ClientAliveInterval" "cannot read sshd config"
    s "MaxAuthTries" "cannot read sshd config"
fi

# --- Firewall ---
sec "FW"
if command -v ufw &>/dev/null; then
    if run_root ufw status 2>/dev/null | grep -q "Status: active"; then
        p "UFW active"
        svc_enabled ufw && p "UFW at boot" || w "UFW at boot" "(not verified)"
    else f "UFW active" "inactive — ufw enable"; fi
elif command -v firewall-cmd &>/dev/null; then
    if run_root firewall-cmd --state 2>/dev/null | grep -q "running"; then
        p "firewalld active"
        svc_enabled firewalld && p "firewalld at boot" || w "firewalld at boot" "(not enabled)"
    else f "firewalld active" "not running — systemctl start firewalld"; fi
elif command -v iptables &>/dev/null; then
    if run_root iptables -L -n 2>/dev/null | grep -q "DROP\|REJECT\|ACCEPT"; then
        w "iptables rules present" "(UFW or firewalld recommended)"
    else f "No firewall" "no rules found"; fi
else f "No firewall" "no firewall tool detected"; fi

_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
[ "$_fwd" = "0" ] && p "IP forwarding disabled"
[ "$_fwd" = "1" ] && f "IP forwarding disabled" "enabled — sysctl -w net.ipv4.ip_forward=0"
[ -z "$_fwd" ] && s "IP forwarding" "cannot read"

if command -v ss &>/dev/null; then
    _ports=$(run_root ss -tlnp 2>/dev/null | awk 'NR>1 {addr=$4; sub(/.*:/, "", addr); print addr}' | sort -n | uniq | tr '\n' ' ')
    i "TCP ports" "${_ports:-none}"
    _pubports=$(run_root ss -tlnp 2>/dev/null | awk 'NR>1 && $4 ~ /^(0\.0\.0\.0|\[::\]|\*|:::):/ {addr=$4; sub(/.*:/, "", addr); print addr}' | sort -n | uniq | tr '\n' ' ')
    _pubc=$(printf "%s\n" "$_pubports" | awk 'NF {c++} END {print c+0}')
    if [ "${_pubc:-0}" -eq 0 ]; then p "No wildcard-bound services"
    else
        w "Wildcard-bound services" "$_pubc port(s): $_pubports"
    fi
elif command -v netstat &>/dev/null; then
    _ports=$(run_root netstat -tlnp 2>/dev/null | awk 'NR>2 {addr=$4; sub(/.*:/, "", addr); print addr}' | sort -n | uniq | tr '\n' ' ')
    i "TCP ports" "${_ports:-none}"
    _pubports=$(run_root netstat -tlnp 2>/dev/null | awk 'NR>2 && $4 ~ /^(0\.0\.0\.0|\*|::|:::):/ {addr=$4; sub(/.*:/, "", addr); print addr}' | sort -n | uniq | tr '\n' ' ')
    _pubc=$(printf "%s\n" "$_pubports" | awk 'NF {c++} END {print c+0}')
    [ "${_pubc:-0}" -eq 0 ] && p "No wildcard-bound services" || w "Wildcard-bound services" "$_pubc port(s): $_pubports"
else s "Open ports" "ss/netstat missing"; fi

# --- File Permissions ---
sec "Permissions"
_chk_perm() {
    local path="$1" exp="$2" label="$3" fix="${4:-}"
    local mode
    mode=$(run_root stat -c "%a" "$path" 2>/dev/null) || { s "$label" "not found or unreadable"; return; }
    if [ "$mode" = "$exp" ]; then p "$label"
    else f "$label" "${mode} -> ${exp}${fix:+ — $fix}"; fi
}

_chk_perm_max() {
    local path="$1" max="$2" label="$3" fix="${4:-}"
    local mode mode_num max_num
    mode=$(run_root stat -c "%a" "$path" 2>/dev/null) || { s "$label" "not found or unreadable"; return; }
    mode_num=$((8#$mode)); max_num=$((8#$max))
    if (( (mode_num & ~max_num) == 0 )); then p "$label"
    else f "$label" "${mode} exceeds ${max}${fix:+ — $fix}"; fi
}

_chk_perm_max "/etc/shadow"          "640" "/etc/shadow <= 640"    "chmod 640 /etc/shadow"
_chk_perm "/etc/passwd"              "644" "/etc/passwd"           "chmod 644 /etc/passwd"
_chk_perm_max "/etc/sudoers"         "440" "/etc/sudoers <= 440"   "chmod 440 /etc/sudoers"
_chk_perm_max "/etc/ssh/sshd_config" "600" "/etc/ssh/sshd_config <= 600"
_chk_perm_max "/root/.ssh"           "700" "/root/.ssh <= 700"     "chmod 700 /root/.ssh"
_chk_perm_max "/root/.ssh/authorized_keys" "600" "/root/.ssh/authorized_keys <= 600"

_sp=$(run_root stat -c "%a" /etc/shadow 2>/dev/null)
if [ -n "$_sp" ]; then
    case "${_sp: -1}" in
        [4-9]) f "shadow world-readable" "${_sp} — chmod 640 /etc/shadow" ;;
        *)     p "shadow not world-readable" ;;
    esac
fi

# --- Sudo ---
sec "Sudo"
if ! has_priv; then
    s "Syntax" "requires root/passwordless sudo"
elif command -v visudo &>/dev/null; then
    run_root visudo -c 2>/dev/null | grep -q "parsed OK" && p "Syntax valid" || f "Syntax valid" "check: visudo -c"
else
    s "Syntax" "visudo missing"
fi

_sudoers_matches() {
    local pattern="$1"
    run_root grep -RInE "$pattern" /etc/sudoers /etc/sudoers.d 2>/dev/null |
        awk '{raw=$0; line=$0; sub(/^[^:]+:[0-9]+:/, "", line); sub(/^[[:space:]]*/, "", line); if (line !~ /^#/) print raw}'
}

if ! has_priv; then
    s "Logging" "requires root/passwordless sudo"
    s "NOPASSWD entries" "requires root/passwordless sudo"
else
    if [ -n "$(_sudoers_matches "log_host|log_year|logfile|Defaults.*log")" ]; then
        p "Logging enabled"
    else w "Logging" "missing — add: Defaults logfile=/var/log/sudo.log"; fi

    _np=$(_sudoers_matches "NOPASSWD" | wc -l)
    _np=${_np##* }
    if [ "${_np:-0}" -eq 0 ]; then p "No NOPASSWD entries"
    else
        w "NOPASSWD entries" "$_np line(s) — review with visudo"
        _sudoers_matches "NOPASSWD" | while read -r l; do i "  $l"; done
    fi
fi

# --- Packages ---
sec "Packages"
_pm=""
for _p in apt dnf yum zypper pacman; do command -v "$_p" &>/dev/null && { _pm="$_p"; break; }; done

if [ "$_pm" = "apt" ]; then
    _sec=$( (set +o pipefail; apt list --upgradable 2>/dev/null | grep -ci security || true) )
    _sec=${_sec##* }
    [ "${_sec:-0}" -eq 0 ] && p "Security updates none" || f "Security updates" "${_sec} pending — apt upgrade"
else s "Security updates" "$([ -n "$_pm" ] && echo "not implemented for $_pm" || echo "no pkg mgr")"; fi

if [ "$_pm" = "apt" ] && [ -f /var/lib/apt/periodic/update-success-stamp ]; then
    _d=$(( ($(date +%s) - $(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo 0)) / 86400 ))
    [ "$_d" -le 7 ] && p "Last update ${_d}d" || { [ "$_d" -le 30 ] && w "Last update ${_d}d" || f "Last update ${_d}d" "run: apt update"; }
elif [ "$_pm" = "dnf" ] && [ -d /var/cache/dnf ]; then
    _d=$(( ($(date +%s) - $(stat -c %Y /var/cache/dnf 2>/dev/null || echo 0)) / 86400 ))
    [ "$_d" -le 7 ] && p "Last update ${_d}d" || w "Last update ${_d}d"
else s "Last update" "unknown"; fi

if [ "$_pm" = "apt" ]; then
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        if grep -qs 'APT::Periodic::Update-Package-Lists "1"' /etc/apt/apt.conf.d/20auto-upgrades && \
           grep -qs 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
            p "Auto-updates enabled"
        else w "Auto-updates" "installed but may not be configured"; fi
    else f "Auto-updates" "not installed — apt install unattended-upgrades"; fi
elif [ "$_pm" = "dnf" ] || [ "$_pm" = "yum" ]; then
    if [ "$SYSTEMCTL_OK" != true ]; then
        s "Auto-updates" "systemctl unavailable"
    elif svc_active dnf-automatic.timer || svc_enabled dnf-automatic.timer || svc_active dnf-automatic; then
        p "Auto-updates enabled"
    else
        w "Auto-updates" "dnf-automatic off"
    fi
else s "Auto-updates" "${_pm:+not implemented for $_pm}"; fi

# --- Services ---
sec "Services"
if [ "$SYSTEMCTL_OK" = true ]; then
    _found=false
    for _s in sshd ssh; do
        svc_active "$_s" && {
            _found=true; p "SSH running ($_s)"
            svc_enabled "$_s" && p "SSH at boot" || w "SSH at boot" "systemctl enable $_s"
            break
        }
    done
    [ "$_found" = false ] && f "SSH" "not active — install openssh-server"
else
    s "SSH service" "systemctl unavailable"
fi

[ -n "${_pm:-}" ] || _pm="unknown"
if [ "$SYSTEMCTL_OK" = true ]; then
    _svcc=$(_lcount run_root systemctl list-units --type=service --state=running --no-legend)
    i "Running services" "$_svcc"
else
    s "Running services" "systemctl unavailable"
fi

_unnecessary=(avahi-daemon cups cups-browsed rpcbind nfs-server nfs-kernel-server telnet telnetd vsftpd proftpd xinetd smbd bluetooth)
_found_un=()
if [ "$SYSTEMCTL_OK" = true ]; then
    for _s in "${_unnecessary[@]}"; do svc_active "$_s" && _found_un+=("$_s"); done
    if [ ${#_found_un[@]} -eq 0 ]; then p "Unnecessary services none"
    else f "Unnecessary services" "$(join_csv "${_found_un[@]}") — review: systemctl disable"; fi
else
    s "Unnecessary services" "systemctl unavailable"
fi

# --- Logging ---
sec "Logging"
_log_ok=false
if [ "$SYSTEMCTL_OK" = true ]; then
    svc_active rsyslog           && { _log_ok=true; p "rsyslog active"; }
    svc_active syslog-ng         && { _log_ok=true; p "syslog-ng active"; }
    svc_active systemd-journald  && { _log_ok=true; p "journald active"; }
    [ "$_log_ok" = false ] && f "System logging" "none active"
else
    s "System logging" "systemctl unavailable"
fi

_failed=0
if command -v journalctl &>/dev/null; then
    _failed=$( (set +o pipefail; run_root journalctl --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || true) )
    _failed=${_failed##* }
elif [ -f /var/log/auth.log ]; then
    _failed=$( (set +o pipefail; grep -c "Failed password" /var/log/auth.log 2>/dev/null || true) )
elif [ -f /var/log/secure ]; then
    _failed=$( (set +o pipefail; grep -c "Failed password" /var/log/secure 2>/dev/null || true) )
else s "Failed SSH logins" "no log source"; fi

[ -n "$_failed" ] && i "Failed SSH logins" "${_failed} (24h)"

_failed=${_failed:-0}
if [ "$_failed" -eq 0 ] 2>/dev/null; then p "Brute force clean"
elif [ "$_failed" -le 10 ] 2>/dev/null; then p "Brute force ${_failed} (normal)"
elif [ "$_failed" -le 50 ] 2>/dev/null; then w "Brute force ${_failed}" "elevated — monitor"
else f "Brute force ${_failed}" "possible attack — check logs, install fail2ban"; fi

# --- Summary ---
printf "\n${BOLD}${WHT}%s${RST}  ${GRN}PASS %s${RST}  ${RED}FAIL %s${RST}  ${YLW}WARN %s${RST}  ${DIM}SKIP %s${RST}\n\n" \
    "$(printf '%*s' 20 '' | tr ' ' '-')" "$PASS" "$FAIL" "$WARN" "$SKIP"
