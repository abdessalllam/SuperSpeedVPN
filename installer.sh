#!/usr/bin/env bash
# Dual-Hop VLESS+REALITY <-> WireGuard setup script 
# The speed is insane for Dual-Hop with VPN over TCP.
# Dual-Hop: VLESS+REALITY (edge) -> WireGuard (inter-hop) -> Internet (egress)
# Author: https://github.com/abdessalllam
# Author: https://abdessal.am
#
#       ░███    ░██               ░██                                             ░██ ░██ ░██                            
#      ░██░██   ░██               ░██                                             ░██ ░██ ░██                            
#     ░██  ░██  ░████████   ░████████  ░███████   ░███████   ░███████   ░██████   ░██ ░██ ░██  ░██████   ░█████████████  
#    ░█████████ ░██    ░██ ░██    ░██ ░██    ░██ ░██        ░██              ░██  ░██ ░██ ░██       ░██  ░██   ░██   ░██ 
#    ░██    ░██ ░██    ░██ ░██    ░██ ░█████████  ░███████   ░███████   ░███████  ░██ ░██ ░██  ░███████  ░██   ░██   ░██ 
#    ░██    ░██ ░███   ░██ ░██   ░███ ░██               ░██        ░██ ░██   ░██  ░██ ░██ ░██ ░██   ░██  ░██   ░██   ░██ 
#    ░██    ░██ ░██░█████   ░█████░██  ░███████   ░███████   ░███████   ░█████░██ ░██ ░██ ░██  ░█████░██ ░██   ░██   ░██
#                                                                                            
# Ubuntu 22.04/24.04. Idempotent. IPv4+IPv6 aware. Robust error handling.
# Roles:
#   --role 1st  (edge/entry: VLESS+REALITY server + WG client, binds outbound to wg0)
#   --role 2nd  (egress/exit: WG server + NAT) Backend server
#
# Example:
#   # On hop-2 (egress):
#   bash installer.sh --role 2nd --wg-port 51820
#   # Copy bundle to hop-1:
#   scp /root/wg-link-bundle.tar.gz root@hop1:/root/
#   # On hop-1 (edge):
#   bash installer.sh --role 1st --reality-port 443 --sni addons.mozilla.org \
#       --handshake www.cloudflare.com --wg-port 51820
# Notes:
# - Uses official sing-box installer.
# - Assumes a fresh Ubuntu 22.04/24.04 install (or compatible).
# - Installs sing-box, WireGuard, iptables-persistent.
# - Creates a self-signed TLS cert for REALITY (replaceable).
# - Generates a persistent X25519 keypair for REALITY (replaceable).
# - Generates a persistent UUID for VLESS (replaceable).
# - Generates a persistent short_id for REALITY (replaceable).
# - Creates a WireGuard interface (wg0) and service.
# - Allows adding new users (UUIDs) and SID & replacing URLS.
# - Read links below for details on how to use.

set -Eeuo pipefail
shopt -s inherit_errexit
umask 027
rp_ok()   { printf '\033[32mOK:\033[0m %s\n'   "$*"; }
rp_warn() { printf '\033[33mWARN:\033[0m %s\n' "$*"; }
rp_fail() { printf '\033[31mFAIL:\033[0m %s\n' "$*"; }
LOGFILE="/var/log/dualhop-vlessreality-wg.log"
mkdir -p "$(dirname "$LOGFILE")"; touch "$LOGFILE"; chmod 640 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
# Defaults (override via flags or env)
SILENT="${SILENT:-0}"                   # 0=interactive, 1=noninteractive (fail/skip on missing inputs)
ROLE="${ROLE:-}"                        # "1st" or "2nd"
REALITY_PORT="${REALITY_PORT:-443}"
WG_PORT="${WG_PORT:-51820}"
SNI="${SNI:-addons.mozilla.org}"
HANDSHAKE_HOST="${HANDSHAKE_HOST:-}" 
HANDSHAKE_FROM_ARG=0
HANDSHAKE_PORT="${HANDSHAKE_PORT:-443}" # REALITY 'dest' port
WG_IF="${WG_IF:-auto}" # WireGuard interface name
WG_TABLE="${WG_TABLE:-}" # WireGuard routing table (auto-derived from interface if empty)
REALITY_FLOW="${REALITY_FLOW:-}"   # set to xtls-rprx-vision to enable Vision
REQUIRE_X25519="${REQUIRE_X25519:-1}"
UTLS_FP="${UTLS_FP:-chrome}"
# DNS options
DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"   # cloudflare|google|quad9|adguard|opendns|nextdns|custom
DNS_USE_V6="${DNS_USE_V6:-auto}"             # auto|1|0  (auto enables v6 if IPV6_MODE != v4only)
DNS_NEXTDNS_ID="${DNS_NEXTDNS_ID:-}"         # required when DNS_PROVIDER=nextdns
# For custom DoH (optional):
DNS_CUSTOM_URL="${DNS_CUSTOM_URL:-}"         # e.g. https://doh.example.com/dns-query  (or https://dns.nextdns.io/ABCDE)
DNS_CUSTOM_SNI="${DNS_CUSTOM_SNI:-}"         # e.g. doh.example.com
DNS_CUSTOM_IP4="${DNS_CUSTOM_IP4:-}"         # pin to v4 IP (optional but recommended)
DNS_CUSTOM_IP6="${DNS_CUSTOM_IP6:-}"         # pin to v6 IP (optional)
# Use a pool that avoids Docker/K8s defaults (K3s Service CIDR defaults to 10.43.0.0/16)
H1_V4_POOL="${H1_V4_POOL:-100.88.0.0/24}"
H1_V6_POOL="${H1_V6_POOL:-fd00:88::/64}"
WG_H1_V4="${WG_H1_V4:-100.88.0.1/32}"
WG_H2_V4="${WG_H2_V4:-100.88.0.2/32}"
WG_H1_V6="${WG_H1_V6:-fd00:88::1/128}"
WG_H2_V6="${WG_H2_V6:-fd00:88::2/128}"
# IPv6 mode
IPV6_MODE="${IPV6_MODE:-dual}"         # dual | v4only | v6only
# TLS knobs (REALITY lives under the inbound's TLS object)
TLS_MIN="${TLS_MIN:-1.3}"               # "1.0" | "1.1" | "1.2" | "1.3"
TLS_MAX="${TLS_MAX:-1.3}"               # "1.0" | "1.1" | "1.2" | "1.3"
# DNS_LOCKDOWN=off|mark53|drop53  (default: off)
DNS_LOCKDOWN="${DNS_LOCKDOWN:-off}"
# Advanced user management (edge only)
FRESH_URL_MODE=""   # ""|replace|add
ADD_LINK=0
NEW_SID=0
ROTATE_KEYS=0
REVOKE_UUID=""
REVOKE_SID=""
LIST_LINKS=0 
PROBE_ONLY=0
ADVANCED_MODE="${ADVANCED_MODE:-auto}"   # auto | 1 | 0
ACTION_PURGE_SINGBOX=${ACTION_PURGE_SINGBOX:-0} # set to 1 to uninstall sing-box (keep config files)
REVOKE_ALL=0
FORCE=0
REALITY_TAG="${REALITY_TAG:-vless-reality-in}"
# CLI parsing
### TAG CATALOGS & HELP
ROLE_TAGS=(
  "1st" "Edge: VLESS+REALITY server + WG client (bind to wg0)"
  "2nd" "Egress: WG server + NAT"
)

IPV6_MODE_TAGS=(
  "dual"   "IPv4 + IPv6"
  "v4only" "IPv4 only"
  "v6only" "IPv6 only"
)

DNS_PROVIDER_TAGS=(
  "cloudflare" "Cloudflare DoH"
  "google"     "Google DoH"
  "quad9"      "Quad9 DoH"
  "adguard"    "AdGuard DoH"
  "opendns"    "OpenDNS DoH"
  "nextdns"    "NextDNS (needs ID)"
  "custom"     "Custom URL/SNI"
)

DNS_USE_V6_TAGS=(
  "auto" "Follow --ipv6-mode"
  "1"    "Yes (enable DoH over IPv6)"
  "0"    "No (force DoH over IPv4)"
)

UTLS_FP_TAGS=(
  "chrome"     "Chrome"
  "firefox"    "Firefox"
  "safari"     "Safari"
  "edge"       "Edge"
  "ios"        "Mobile Safari (iOS)"
  "android"    "Android"
  "randomized" "Randomized"
)

DNS_LOCKDOWN_TAGS=(
  "off"    "Disabled (default)"
  "mark53" "Policy-route only :53 via wg table"
  "drop53" "Allow lo/wg0 :53, drop others"
)
declare -A HELP_FLAGS=(
  [--role]="1st|2nd — Node role (edge or egress)"
  [--wg-port]="UDP port for WireGuard (default: 51820)"
  [--wg-if]="WireGuard interface name (default: wg0)"

  [--reality-port]="TCP port for VLESS+REALITY inbound (edge) (default: 443)"
  [--sni]="REALITY SNI presented in ClientHello (edge)"
  [--handshake]="REALITY decoy/handshake host or IP (edge)"
  [--handshake-port]="REALITY decoy TLS port (edge, default: 443)"

  [--ipv6-mode]="dual|v4only|v6only — IP family behavior (affects WG/sing-box & DNS)"
  [--utls-fp]="chrome|firefox|safari|edge|ios|android|randomized — client hint in share URL (edge)"
  [--reality-flow]="Optional: xtls-rprx-vision to enable Vision (edge)"
  [--require-x25519]="1|0 — Require X25519 on decoy probe (default: 1, edge)"
  [--preflight-only-ipv4]="1|0 — Probe decoy only over IPv4 (default: 0, edge)"

  [--dns]="cloudflare|google|quad9|adguard|opendns|nextdns|custom — DoH upstream"
  [--dns-use-v6]="auto|1|0 — Allow DoH over IPv6"
  [--dns-nextdns-id]="NextDNS profile ID (when provider=nextdns)"
  [--dns-custom-url]="Custom DoH URL (when provider=custom)"
  [--dns-custom-sni]="Custom DoH SNI to verify (when provider=custom)"
  [--dns-custom-ip4]="Optional IPv4 pin for custom DoH"
  [--dns-custom-ip6]="Optional IPv6 pin for custom DoH"

  [--dns-lockdown]="off|mark53|drop53 — host DNS egress policy (default: off) DNS_LOCKDOWN=mark53 ./script-wg.sh --role 1st ..."
  [--silent]="Enable noninteractive mode (same as --silent=1)"

  # Advanced network pools (usually leave defaults)
  [--h1-v4-pool]="CIDR for hop-1 WG IPv4 pool (default: 100.88.0.0/24)"
  [--h1-v6-pool]="CIDR for hop-1 WG IPv6 pool (default: fd00:88::/64)"
  [--wg-h1-v4]="WG IPv4 address for hop-1 (default: 100.88.0.1/32)"
  [--wg-h2-v4]="WG IPv4 address for hop-2 (default: 100.88.0.2/32)"
  [--wg-h1-v6]="WG IPv6 address for hop-1 (default: fd00:88::1/128)"
  [--wg-h2-v6]="WG IPv6 address for hop-2 (default: fd00:88::2/128)"
  [--new]="Create a fresh link (default mode: replace). Use --new=add to append a new user; combine with --new-sid to also mint a new short_id"
  [--new-user]="Append a new user (UUID); combine with --new-sid for a fresh short_id"
  [--new-sid]="When used with --new or --new-user, also generate a new short_id (sid)"
  [--rotate]="Rotate REALITY keypair (regenerates /etc/sing-box/reality.key)"
  [--revoke-uuid]="Remove a specific UUID from the link store"
  [--revoke-sid]="Remove a specific short_id (sid) from the link store"
  [--list-users]="List current users (UUIDs) and SIDs"
  [--advanced]="Force advanced menu on interactive runs (for tuning defaults)"
  [--wizard]="Alias for --advanced"
  [--tune]="Alias for --advanced"
  [--probe]="Just run the REALITY decoy probe and exit (requires --sni; optional --handshake/--handshake-port)"


)

# Print order for help output
HELP_ORDER=(
  --role --wg-port --wg-if --probe
  --reality-port --sni --handshake --handshake-port
  --ipv6-mode --utls-fp --reality-flow --require-x25519 --preflight-only-ipv4
  --dns --dns-use-v6 --dns-nextdns-id --dns-custom-url --dns-custom-sni --dns-custom-ip4 --dns-custom-ip6
  --dns-lockdown --silent --new --new-user --new-sid --rotate --revoke-uuid --revoke-sid --list-users
  --h1-v4-pool --h1-v6-pool --wg-h1-v4 --wg-h2-v4 --wg-h1-v6 --wg-h2-v6 --advanced --wizard --tune 
)

# Usage text (terminal) + Help dialog (whiptail) from the same source
_usage_body() {
  echo "Usage: $0 [flags]"
  echo
  echo "Examples:"
  echo "  # Hop-2 (egress):"
  echo "  $0 --role 2nd --wg-port 51820"
  echo "  # Hop-1 (edge):"
  echo "  $0 --role 1st --reality-port 443 --sni addons.mozilla.org --handshake www.cloudflare.com --wg-port 51820"
  echo "  Tip: run hop-2 (egress) first, then hop-1 (edge). Defaults are sane for headless runs."
  echo
  echo "Flags:"
  local k pad=28
  for k in "${HELP_ORDER[@]}"; do
    printf "  %-*s %s\n" "$pad" "$k" "${HELP_FLAGS[$k]}"
  done
  echo
  echo "Notes:"
  echo "  • Values can also be set via environment vars of the same UPPERCASE names."
  echo "  • Interactive menus appear when required values are missing (unless --silent=1 or not present)."
}

usage() {
  if command -v whiptail >/dev/null 2>&1 && [[ -t 1 ]]; then
    local tmp; tmp="$(mktemp)"
    _usage_body >"$tmp"
    whiptail --title "Dual-Hop (VLESS REALITY ↔ WireGuard) — Help" --scrolltext --textbox "$tmp" 25 92
    rm -f "$tmp"
  else
    _usage_body
  fi
}
# Quick helper to show “Help” from a menu (tag = help)
help_tag() { usage; }
### END TAG CATALOGS & HELP
# Bool parsing for flags/env
is_true()  { case "${1,,}" in 1|true|yes|on)  return 0;; *) return 1;; esac; }
is_false() { case "${1,,}" in 0|false|no|off) return 0;; *) return 1;; esac; }
norm_bool(){ is_true "$1" && echo 1 || echo 0; }

# simple argv parser
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2;;
    --role=*) ROLE="${1#*=}"; shift;;
    --wg-port)           WG_PORT="${2:-}"; ARG_WG_PORT=1; shift 2;;
    --wg-port=*)         WG_PORT="${1#*=}"; ARG_WG_PORT=1; shift;;
    --reality-port)      REALITY_PORT="${2:-}"; ARG_REALITY_PORT=1; shift 2;;
    --reality-port=*)    REALITY_PORT="${1#*=}"; ARG_REALITY_PORT=1; shift;;
    --sni)               SNI="${2:-}"; ARG_SNI=1; shift 2;;
    --sni=*)             SNI="${1#*=}"; ARG_SNI=1; shift;;
    --handshake)         HANDSHAKE_HOST="${2:-}"; HANDSHAKE_FROM_ARG=1; ARG_HANDSHAKE=1; shift 2;;
    --handshake=*)       HANDSHAKE_HOST="${1#*=}"; HANDSHAKE_FROM_ARG=1; ARG_HANDSHAKE=1; shift;;
    --handshake-port)    HANDSHAKE_PORT="${2:-}"; ARG_HANDSHAKE_PORT=1; shift 2;;
    --handshake-port=*)  HANDSHAKE_PORT="${1#*=}"; ARG_HANDSHAKE_PORT=1; shift;;
    --ipv6-mode)         IPV6_MODE="${2:-}"; ARG_IPV6_MODE=1; shift 2;;
    --ipv6-mode=*)       IPV6_MODE="${1#*=}"; ARG_IPV6_MODE=1; shift;;
    --dns)               DNS_PROVIDER="${2:-}"; ARG_DNS_PROVIDER=1; shift 2;;
    --dns=*)             DNS_PROVIDER="${1#*=}"; ARG_DNS_PROVIDER=1; shift;;
    --dns-use-v6)        DNS_USE_V6="${2:-}"; ARG_DNS_USE_V6=1; shift 2;;
    --dns-use-v6=*)      DNS_USE_V6="${1#*=}"; ARG_DNS_USE_V6=1; shift;;
    --dns-nextdns-id)    DNS_NEXTDNS_ID="${2:-}"; ARG_DNS_NEXTDNS_ID=1; shift 2;;
    --dns-nextdns-id=*)  DNS_NEXTDNS_ID="${1#*=}"; ARG_DNS_NEXTDNS_ID=1; shift;;
    --dns-custom-url)    DNS_CUSTOM_URL="${2:-}"; ARG_DNS_CUSTOM_URL=1; shift 2;;
    --dns-custom-url=*)  DNS_CUSTOM_URL="${1#*=}"; ARG_DNS_CUSTOM_URL=1; shift;;
    --dns-custom-sni)    DNS_CUSTOM_SNI="${2:-}"; ARG_DNS_CUSTOM_SNI=1; shift 2;;
    --dns-custom-sni=*)  DNS_CUSTOM_SNI="${1#*=}"; ARG_DNS_CUSTOM_SNI=1; shift;;
    --dns-custom-ip4)    DNS_CUSTOM_IP4="${2:-}"; ARG_DNS_CUSTOM_IP4=1; shift 2;;
    --dns-custom-ip4=*)  DNS_CUSTOM_IP4="${1#*=}"; ARG_DNS_CUSTOM_IP4=1; shift;;
    --dns-custom-ip6)    DNS_CUSTOM_IP6="${2:-}"; ARG_DNS_CUSTOM_IP6=1; shift 2;;
    --dns-custom-ip6=*)  DNS_CUSTOM_IP6="${1#*=}"; ARG_DNS_CUSTOM_IP6=1; shift;;
    --utls-fp)           UTLS_FP="${2:-}"; ARG_UTLS_FP=1; shift 2;;
    --utls-fp=*)         UTLS_FP="${1#*=}"; ARG_UTLS_FP=1; shift;;
    --reality-flow)      REALITY_FLOW="${2:-}"; shift 2;;
    --reality-flow=*)    REALITY_FLOW="${1#*=}"; shift;;
    --require-x25519)    REQUIRE_X25519="${2:-}"; shift 2;;
    --require-x25519=*)  REQUIRE_X25519="${1#*=}"; shift;;
    --preflight-only-ipv4)PREFLIGHT_ONLY_IPV4="${2:-}"; shift 2;;
    --preflight-only-ipv4=*)PREFLIGHT_ONLY_IPV4="${1#*=}"; shift;;
    --dns-lockdown)      DNS_LOCKDOWN="${2:-}"; shift 2;;
    --dns-lockdown=*)    DNS_LOCKDOWN="${1#*=}"; shift;;
    --h1-v4-pool)        H1_V4_POOL="${2:-}"; shift 2;;
    --h1-v4-pool=*)      H1_V4_POOL="${1#*=}"; shift;;
    --h1-v6-pool)        H1_V6_POOL="${2:-}"; shift 2;;
    --h1-v6-pool=*)      H1_V6_POOL="${1#*=}"; shift;;
    --wg-h1-v4)          WG_H1_V4="${2:-}"; shift 2;;
    --wg-h1-v4=*)        WG_H1_V4="${1#*=}"; shift;;
    --wg-h2-v4)          WG_H2_V4="${2:-}"; shift 2;;
    --wg-h2-v4=*)        WG_H2_V4="${1#*=}"; shift;;
    --wg-h1-v6)          WG_H1_V6="${2:-}"; shift 2;;
    --wg-h1-v6=*)        WG_H1_V6="${1#*=}"; shift;;
    --wg-h2-v6)          WG_H2_V6="${2:-}"; shift 2;;
    --wg-h2-v6=*)        WG_H2_V6="${1#*=}"; shift;;
    --probe)             PROBE_ONLY=1; shift ;;
    --probe=*)           PROBE_ONLY=1; shift ;;
    --purge-singbox)     ACTION_PURGE_SINGBOX=1; shift;;
    --purge-singbox=*)   ACTION_PURGE_SINGBOX="${1#*=}"; shift;;
    --wizard|--tune|--advanced) FORCE_ADVANCED=1; shift ;;
    --new)
      FRESH_URL_MODE="replace"; shift ;;
    --new=*)
      _val="${1#*=}"
      case "${_val}" in
        replace|add) FRESH_URL_MODE="${_val}" ;;
        *) echo "Invalid --new value: '${_val}' (use: replace|add)"; usage; exit 2;;
      esac
      shift ;;
    --new-user|--add-link)
      ADD_LINK=1; shift ;;
    --new-sid)
      NEW_SID=1; shift ;;
    --rotate|--rotate-pbk)
      ROTATE_KEYS=1; shift ;;
    --revoke-uuid=*) REVOKE_UUID="${1#*=}"; shift ;;
    --revoke-sid=*)  REVOKE_SID="${1#*=}"; shift ;;
    --revoke-uuid)   REVOKE_UUID="$2"; shift ;;
    --revoke-sid)    REVOKE_SID="$2"; shift ;;
    --revoke-all)    REVOKE_ALL=1; shift;;
    --yes|-y|--force) FORCE=1; shift;;
    --list-users|--list-links) LIST_LINKS=1; shift ;;
    --list-users=all|--list-links=all) LIST_LINKS=all; shift ;;
    -h|--help) usage; exit 0;;
    --silent)
      SILENT=1; shift
      ;;
    --silent=*)
      SILENT="$(norm_bool "${1#*=}")"; shift
      ;;
    --no-silent|--interactive)
      SILENT=0; shift
      ;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done
# After parsing, only hard-fail immediately if running in --silent mode.
if is_true "${SILENT:-0}"; then
  [[ "$ROLE" == "1st" || "$ROLE" == "2nd" ]] || { usage; exit 2; }
fi

# Pretty + traps
msg(){ echo -e "\n\033[32m=>\033[0m \033[1m$*\033[0m"; }
warn(){ echo -e "\n\033[33mWARN:\033[0m $*"; }
fatal(){ printf "\n\033[31mFATAL:\033[0m %s\n" "$*" >&2; exit 1; }
on_err(){
  local code=$? line=${BASH_LINENO[0]} cmd="${BASH_COMMAND}"
  echo -e "\n\033[41;97m --- SCRIPT ERROR --- \033[0m"
  echo -e "\033[31m[FATAL] line ${line}, exit ${code}\033[0m"
  echo -e "\033[31m[FATAL] cmd: '${cmd}'\033[0m"
  echo -e "\033[31mSee log: ${LOGFILE}\033[0m"
  echo -e "\n--- recent svc logs ---"
  journalctl -u "wg-quick@${WG_IF}.service" -u sing-box -n 80 --no-pager --output=cat 2>/dev/null || true
  exit $code
}
trap on_err ERR
trap 'echo "Interrupted."; exit 130' INT TERM
trap 'echo -e "\n--- Done. Log: ${LOGFILE}"' EXIT
is_dns_name() { [[ "$1" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$ ]]; }

# Helpers
require_root(){ [[ $EUID -eq 0 ]] || fatal "Run as root."; }
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }
detect_wan_if4(){ ip -4 route show default | awk '/default/ {print $5; exit}'; }
detect_wan_if6(){ ip -6 route show default | awk '/default/ {print $5; exit}'; }
# Pick or validate a WireGuard interface name.
pick_free_wg_if() {
  local want="${1:-auto}"    # "auto" or explicit (e.g., wg3)

  # If explicit, just echo it back (we don't create here).
  if [[ "$want" != "auto" ]]; then
    printf '%s\n' "$want"
    return 0
  fi

  # Auto-pick the first free wgN (no link, no conf file).
  local n
  for n in {0..63}; do
    if ! ip link show "wg${n}" &>/dev/null && [[ ! -e "/etc/wireguard/wg${n}.conf" ]]; then
      printf 'wg%s\n' "$n"
      return 0
    fi
  done

  # Nothing free
  return 2
}
derive_wg_table() {
  # If WG_TABLE is empty, derive it from interface numeric suffix to avoid conflicts
  [[ -n "${WG_TABLE}" ]] && return 0
  local num=0
  if [[ "${WG_IF}" =~ ^wg([0-9]+)$ ]]; then
    num="${BASH_REMATCH[1]}"
  fi
  # Base 51820 + suffix (e.g., wg0->51820, wg1->51821, …)
  WG_TABLE=$((51820 + num))
}

ensure_udp_port_free_for_wg() {
  # For hop-2 (server): if WG_PORT is busy, bump until free
  local p="${WG_PORT}"
  while ss -H -lun | awk '{print $5}' | grep -q ":${p}$"; do
    p=$((p+1))
  done
  if [[ "${p}" != "${WG_PORT}" ]]; then
    echo "WARN: UDP ${WG_PORT} in use; switching to ${p}"
    WG_PORT="${p}"
  fi
}
# Interactive prompting helpers (tag-based menus)
_has_tty(){ [[ -t 0 ]]; }
_has_whiptail(){ return 1; } # Whiptail disable cause I don't like it, Feel free to enable it below
# _has_whiptail(){ [[ "${USE_WHIPTAIL:-0}" == 1 ]] && command -v whiptail >/dev/null 2>&1; }
_abort_or_fail(){ fatal "$1"; }
_prompt_input(){
  # _prompt_input VAR "Title" "Prompt" "default"
  local __var="$1" __title="$2" __msg="$3" __def="${4:-}"
  local __val
  if _has_tty && _has_whiptail; then
    __val="$(whiptail --title "$__title" --inputbox "$__msg" 10 70 "$__def" 3>&1 1>&2 2>&3)" || _abort_or_fail "Cancelled."
  else
    read -rp "$__msg [${__def}]: " __val || true
    [[ -z "$__val" ]] && __val="$__def"
  fi
  printf -v "$__var" "%s" "$__val"
}

_prompt_menu_tags(){
  # _prompt_menu_tags VAR "Title" "Text" default_tag  "tag1" "desc1"  "tag2" "desc2" ...
  local __var="$1"; shift
  local __title="$1"; shift
  local __text="$1"; shift
  local __def="$1"; shift
  local __args=("$@")
  local __sel=""
  if _has_tty && _has_whiptail; then
    local whi=()
    local i=0
    while (( i < ${#__args[@]} )); do
      local tag="${__args[i]}"; local desc="${__args[i+1]}"; i=$((i+2))
      local on="OFF"; [[ "$tag" == "$__def" ]] && on="ON"
      whi+=("$tag" "$desc" "$on")
    done
    __sel="$(whiptail --title "$__title" --radiolist "$__text" 18 72 9 "${whi[@]}" 3>&1 1>&2 2>&3)" || _abort_or_fail "Cancelled."
  else
    echo -e "\n$__title — $__text"
    local idx=1 opts=() map=()
    local i=0
    while (( i < ${#__args[@]} )); do
      local tag="${__args[i]}"; local desc="${__args[i+1]}"; i=$((i+2))
      printf "  %d) %s  — %s\n" "$idx" "$tag" "$desc"
      opts+=("$tag"); map[$idx]="$tag"; idx=$((idx+1))
    done
    local choice
    while :; do
      read -rp "Choose [${__def} or 1-${#opts[@]}]: " choice || true
      [[ -z "$choice" ]] && { __sel="$__def"; break; }
      if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=${#opts[@]} )); then
        __sel="${map[$choice]}"; break
      fi
      # also accept exact tag
      for t in "${opts[@]}"; do [[ "$choice" == "$t" ]] && { __sel="$t"; break 2; }; done
      echo "Invalid choice."
    done
  fi
  printf -v "$__var" "%s" "$__sel"
}

_validate_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }
_validate_host_like(){
  local v="$1"
  [[ "$v" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$ || "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$v" == *:* ]]
}
_prompt_port(){
  local __tmp
  while :; do
    _prompt_input __tmp "$1" "$2" "$3"
    _validate_port "$__tmp" && { printf -v "$4" "%s" "$__tmp"; return 0; }
    echo "Invalid port."
  done
}
# Flow 1 — only the baseline knobs
_prompt_key_settings(){
  # Common
  [[ "${ARG_WG_PORT:-0}" == "1" ]] || _prompt_port "WireGuard Port" "UDP port for WG" "${WG_PORT}" WG_PORT

  [[ "${ARG_IPV6_MODE:-0}" == "1" ]] || _prompt_menu_tags IPV6_MODE "IPv6 Mode" "Choose IPv6 behaviour:" "${IPV6_MODE}" \
    "dual" "IPv4 + IPv6" "v4only" "IPv4 only" "v6only" "IPv6 only"

  [[ "${ARG_DNS_PROVIDER:-0}" == "1" ]] || _prompt_menu_tags DNS_PROVIDER "DNS Provider" "Pick DoH resolver:" "${DNS_PROVIDER}" \
    "cloudflare" "Cloudflare DoH" "google" "Google DoH" "quad9" "Quad9 DoH" \
    "adguard" "AdGuard DoH" "opendns" "OpenDNS DoH" "nextdns" "NextDNS (needs ID)" "custom" "Custom URL/SNI"

  [[ "${ARG_DNS_USE_V6:-0}" == "1" ]] || _prompt_menu_tags DNS_USE_V6 "DNS v6" "Allow DoH over IPv6?" "${DNS_USE_V6}" \
    "auto" "Follow --ipv6-mode" "1" "Yes" "0" "No"

  # Provider-specific
  if [[ "$DNS_PROVIDER" == "nextdns" && "${ARG_DNS_NEXTDNS_ID:-0}" != "1" ]]; then
    _prompt_input DNS_NEXTDNS_ID "NextDNS ID" "Enter your profile ID" "${DNS_NEXTDNS_ID}"
  elif [[ "$DNS_PROVIDER" == "custom" ]]; then
    [[ "${ARG_DNS_CUSTOM_URL:-0}" == "1" ]] || _prompt_input DNS_CUSTOM_URL "Custom DoH URL" "e.g. https://doh.example.com/dns-query" "${DNS_CUSTOM_URL}"
    [[ "${ARG_DNS_CUSTOM_SNI:-0}" == "1" ]] || _prompt_input DNS_CUSTOM_SNI "Custom DoH SNI" "Hostname to verify in TLS" "${DNS_CUSTOM_SNI}"
    [[ "${ARG_DNS_CUSTOM_IP4:-0}" == "1" ]] || _prompt_input DNS_CUSTOM_IP4 "Custom DoH IPv4 (pin)" "Optional IPv4 address to pin" "${DNS_CUSTOM_IP4}"
    if [[ "$IPV6_MODE" != "v4only" ]]; then
      [[ "${ARG_DNS_CUSTOM_IP6:-0}" == "1" ]] || _prompt_input DNS_CUSTOM_IP6 "Custom DoH IPv6 (pin)" "Optional IPv6 address to pin" "${DNS_CUSTOM_IP6}"
    fi
  fi

  if [[ "$ROLE" == "1st" ]]; then
    # Only show if not passed on CLI
    [[ "${ARG_REALITY_PORT:-0}" == "1" ]] || \
      _prompt_port "REALITY Port" "TCP port for VLESS+REALITY inbound" "${REALITY_PORT}" REALITY_PORT

    [[ "${ARG_SNI:-0}" == "1" ]] || {
      _prompt_input SNI "REALITY SNI" "Hostname in ClientHello (must be on cert SAN)" "${SNI}"
      is_dns_name "$SNI" || fatal "SNI must be a DNS hostname."
    }

    # Handshake host: show only if user passed it OR it’s non-default (i.e., not empty and != SNI)
    if [[ "${ARG_HANDSHAKE:-0}" == "1" || ( -n "${HANDSHAKE_HOST:-}" && "${HANDSHAKE_HOST}" != "$SNI" ) ]]; then
      _prompt_input HANDSHAKE_HOST "REALITY Handshake Host" "Decoy endpoint host or IP" "${HANDSHAKE_HOST:-$SNI}"
      _validate_host_like "$HANDSHAKE_HOST" || fatal "HANDSHAKE_HOST looks invalid."
    fi

    # Handshake port: show only if user passed it OR it’s non-default (not 443)
    if [[ "${ARG_HANDSHAKE_PORT:-0}" == "1" || "${HANDSHAKE_PORT:-443}" != "443" ]]; then
      _prompt_port "REALITY Handshake Port" "Decoy TLS port" "${HANDSHAKE_PORT:-443}" HANDSHAKE_PORT
    fi

    [[ "${ARG_UTLS_FP:-0}" == "1" ]] || \
      _prompt_menu_tags UTLS_FP "TLS Fingerprint" "Browser-like fingerprint for clients" "${UTLS_FP}" \
        "chrome" "Chrome" \
        "firefox" "Firefox" \
        "safari" "Safari" \
        "edge" "Edge" \
        "ios" "Mobile Safari (iOS)" \
        "android" "Android" \
        "randomized" "Randomized"
  fi
}
_is_default_handshake() {
  [[ -z "${HANDSHAKE_HOST:-}" || "${HANDSHAKE_HOST}" == "${SNI}" ]] \
  && [[ -z "${HANDSHAKE_PORT:-}" || "${HANDSHAKE_PORT}" == "443" ]]
}
_compute_needs_key_review(){
  NEEDS_KEY_REVIEW=0

  # Core
  [[ "${ARG_WG_PORT:-0}" == "1"       ]] || NEEDS_KEY_REVIEW=1
  [[ "${ARG_IPV6_MODE:-0}" == "1"     ]] || NEEDS_KEY_REVIEW=1
  [[ "${ARG_DNS_PROVIDER:-0}" == "1"  ]] || NEEDS_KEY_REVIEW=1
  [[ "${ARG_DNS_USE_V6:-0}" == "1"    ]] || NEEDS_KEY_REVIEW=1

  # Provider extras
  if [[ "$DNS_PROVIDER" == "nextdns" && "${ARG_DNS_NEXTDNS_ID:-0}" != "1" ]]; then NEEDS_KEY_REVIEW=1; fi
  if [[ "$DNS_PROVIDER" == "custom" ]]; then
    if [[ "${ARG_DNS_CUSTOM_URL:-0}" != "1" || "${ARG_DNS_CUSTOM_SNI:-0}" != "1" ]]; then NEEDS_KEY_REVIEW=1; fi
  fi
  if [[ "$ROLE" == "1st" ]]; then
    [[ "${ARG_REALITY_PORT:-0}" == "1" ]] || NEEDS_KEY_REVIEW=1
    [[ "${ARG_SNI:-0}"         == "1" ]] || NEEDS_KEY_REVIEW=1

    # Only consider handshake knobs if not passed AND they deviate from defaults
    if [[ "${ARG_HANDSHAKE:-0}" != "1" && "${HANDSHAKE_HOST:-$SNI}" != "$SNI" ]]; then
      NEEDS_KEY_REVIEW=1
    fi
    if [[ "${ARG_HANDSHAKE_PORT:-0}" != "1" && "${HANDSHAKE_PORT:-443}" != "443" ]]; then
      NEEDS_KEY_REVIEW=1
    fi

    [[ "${ARG_UTLS_FP:-0}"     == "1" ]] || NEEDS_KEY_REVIEW=1
  fi
}
# Yes/No prompt (TTY + whiptail friendly)
_ask_yes_no(){
  local __outvar="$1"; shift
  local prompt="$1"; shift
  local default="${1:-1}"  # 1 = default YES, 0 = default NO

  # Validate output var name: [A-Za-z_][A-Za-z0-9_]*
  case "$__outvar" in ''|*[!A-Za-z0-9_]*|[0-9]*)
    printf 'BUG: invalid output var name: %q\n' "$__outvar" >&2; return 2;;
  esac

  local def_str; [[ $default -eq 1 ]] && def_str="Y/n" || def_str="y/N"
  local ans
  while :; do
    read -r -p "$prompt [$def_str] " ans
    [[ -z $ans ]] && { [[ $default -eq 1 ]] && ans=yes || ans=no; }
    case "$ans" in
      y|Y|yes|YES) printf -v "$__outvar" yes; return 0;;
      n|N|no|NO)  printf -v "$__outvar" no;  return 0;;
      *) printf 'Please answer yes or no.\n' ;;
    esac
  done
}
# Call this early to ensure all required inputs exist
prompt_missing_inputs(){
  # Respect SILENT mode: hard-fail if required inputs missing
  if is_true "$SILENT"; then
    [[ -z "$ROLE" ]]     && fatal "ROLE is required (1st|2nd)"
    [[ -z "$WG_PORT" ]]  && fatal "WG_PORT is required"
    if [[ "$ROLE" == "1st" ]]; then
      [[ -z "$REALITY_PORT" ]] && fatal "REALITY_PORT is required"
      [[ -z "$SNI" ]]          && fatal "SNI is required"
      # Default HANDSHAKE to SNI:443 if not provided
      [[ -z "$HANDSHAKE_HOST" ]] && HANDSHAKE_HOST="$SNI"
      [[ -z "$HANDSHAKE_PORT" ]] && HANDSHAKE_PORT=443
    fi
  fi
  # ROLE menu if missing
  if [[ -z "$ROLE" ]]; then
    _prompt_menu_tags ROLE "Role" "Select the node role:" "1st" \
      "1st" "Edge: VLESS+REALITY server + WG client (bind to wg0)" \
      "2nd" "Egress: WG server + NAT"
  fi
  # One-line bool menu using tags "1/0"
  _prompt_bool(){
    # _prompt_bool VAR "Title" "Text" default(1|0)
    local __var="$1" __title="$2" __text="$3" __def="${4:-0}"
    _prompt_menu_tags "$__var" "$__title" "$__text" "$__def" \
      "1" "Yes" \
      "0" "No"
  }

  # Advanced settings wizard (runs only if user opts in)
# Flow 2 — advanced-only knobs (NOT asked in Flow 1)
  _prompt_advanced(){
    # Common advanced
    _prompt_input WG_IF "WG interface" "WireGuard interface name" "${WG_IF}"

    _prompt_menu_tags DNS_LOCKDOWN "DNS Lockdown" "Host DNS egress policy:" "${DNS_LOCKDOWN}" \
      "off"    "Disabled (default)" \
      "mark53" "Mark :53 -> WG table" \
      "drop53" "Allow lo/wg :53, drop others"

    # Edge-only advanced toggles
    if [[ "$ROLE" == "1st" ]]; then
      _prompt_input REALITY_FLOW "REALITY Flow" "Optional: xtls-rprx-vision to enable Vision (or blank)" "${REALITY_FLOW}"

      _prompt_bool REQUIRE_X25519 "Require X25519" "Reject decoys without X25519 during probe?" "$(norm_bool "$REQUIRE_X25519")"

      _prompt_bool PREFLIGHT_ONLY_IPV4 "Probe only over IPv4" "Force decoy probe to IPv4?" "$(norm_bool "$PREFLIGHT_ONLY_IPV4")"
    fi

    # Optional: advanced address pools (proper var name, not a string)
    local ADVANCED_POOLS
    _ask_yes_no ADVANCED_POOLS "Change WireGuard address pools / peer IPs?" 0
    if [[ "${ADVANCED_POOLS:-no}" == "yes" ]]; then
      _prompt_input H1_V4_POOL "Hop-1 WG IPv4 Pool" "CIDR" "${H1_V4_POOL}"
      if [[ "$IPV6_MODE" != "v4only" ]]; then
        _prompt_input H1_V6_POOL "Hop-1 WG IPv6 Pool" "CIDR" "${H1_V6_POOL}"
      fi
      _prompt_input WG_H1_V4 "WG IPv4 (hop-1)" "Address with prefix" "${WG_H1_V4}"
      _prompt_input WG_H2_V4 "WG IPv4 (hop-2)" "Address with prefix" "${WG_H2_V4}"
      if [[ "$IPV6_MODE" != "v4only" ]]; then
        _prompt_input WG_H1_V6 "WG IPv6 (hop-1)" "Address with prefix" "${WG_H1_V6}"
        _prompt_input WG_H2_V6 "WG IPv6 (hop-2)" "Address with prefix" "${WG_H2_V6}"
      fi
    fi
  }

  # Common ports if missing
  [[ -z "$WG_PORT" ]] && _prompt_port "WireGuard Port" "UDP port for WG" "${WG_PORT:-51820}" WG_PORT

  # IPv6 mode if missing
  if [[ -z "$IPV6_MODE" ]]; then
    _prompt_menu_tags IPV6_MODE "IPv6 Mode" "Choose IPv6 behaviour:" "dual" \
      "dual"   "IPv4 + IPv6" \
      "v4only" "IPv4 only" \
      "v6only" "IPv6 only"
  fi

  # DNS provider (only if DNS chooser exists; defaults ok)
  if [[ -z "$DNS_PROVIDER" ]]; then
    _prompt_menu_tags DNS_PROVIDER "DNS Provider" "Pick DoH resolver (tags are returned):" "cloudflare" \
      "cloudflare" "Cloudflare DoH" \
      "google"     "Google DoH" \
      "quad9"      "Quad9 DoH" \
      "adguard"    "AdGuard DoH" \
      "opendns"    "OpenDNS DoH" \
      "nextdns"    "NextDNS (needs ID)" \
      "custom"     "Custom URL/SNI"
  fi
  # DNS v6 preference (optional)
  if [[ -z "$DNS_USE_V6" ]]; then
    _prompt_menu_tags DNS_USE_V6 "DNS v6" "Allow DoH over IPv6?" "auto" \
      "auto" "Follow --ipv6-mode" \
      "1"    "Yes" \
      "0"    "No"
  fi

  # Role-specific
  if [[ "$ROLE" == "1st" ]]; then
    [[ -z "$REALITY_PORT" ]] && _prompt_port "REALITY Port" "TCP port for VLESS+REALITY inbound" "${REALITY_PORT:-443}" REALITY_PORT

    if [[ -z "$SNI" ]]; then
      _prompt_input SNI "REALITY SNI" "Hostname presented in ClientHello (must be on cert's SAN)" "${SNI:-addons.mozilla.org}"
      _validate_host_like "$SNI" || fatal "SNI looks invalid."
    fi

    if [[ -z "$HANDSHAKE_HOST" ]]; then
      _prompt_input HANDSHAKE_HOST "REALITY Handshake Host" "Decoy endpoint to actually connect to (host or IP)" "${HANDSHAKE_HOST:-$SNI}"
      _validate_host_like "$HANDSHAKE_HOST" || fatal "HANDSHAKE_HOST looks invalid."
    fi

    if [[ -z "$HANDSHAKE_PORT" ]]; then
      _prompt_port "REALITY Handshake Port" "Decoy TLS port" "${HANDSHAKE_PORT:-443}" HANDSHAKE_PORT
    fi
    # uTLS browser fingerprint (client-side hint; used in share URL)
    if [[ -z "$UTLS_FP" ]]; then
    _prompt_menu_tags UTLS_FP "TLS Fingerprint" "Pick a browser-like fingerprint (clients will use this):" "chrome" \
        "chrome"     "Chrome" \
        "firefox"    "Firefox" \
        "safari"     "Safari" \
        "edge"       "Edge" \
        "ios"        "Mobile Safari (iOS)" \
        "android"    "Android WebView/Chrome" \
        "randomized" "Randomized (rotate per conn)"
    fi
    _validate_in_list "$UTLS_FP" "${VALID_UTLS_FPS[@]}" || UTLS_FP="chrome"
    # DNS extras
    if [[ "$DNS_PROVIDER" == "nextdns" && -z "$DNS_NEXTDNS_ID" ]]; then
      _prompt_input DNS_NEXTDNS_ID "NextDNS ID" "Enter your profile ID (letters/numbers)" ""
    fi
    if [[ "$DNS_PROVIDER" == "custom" ]]; then
      [[ -z "$DNS_CUSTOM_URL" ]] && _prompt_input DNS_CUSTOM_URL "Custom DoH URL" "https://host/path (e.g. https://doh.example.com/dns-query)" ""
      [[ -z "$DNS_CUSTOM_SNI" ]] && _prompt_input DNS_CUSTOM_SNI "Custom DoH SNI" "SNI to verify (usually the URL host)" ""
      # Optional pins
      [[ -z "$DNS_CUSTOM_IP4" ]] && _prompt_input DNS_CUSTOM_IP4 "Custom DoH IPv4" "Optional: pin a v4 address" ""
      if [[ "$IPV6_MODE" != "v4only" && -z "$DNS_CUSTOM_IP6" ]]; then
        _prompt_input DNS_CUSTOM_IP6 "Custom DoH IPv6" "Optional: pin a v6 address" ""
      fi
    fi
  fi
  # Optional review step (only when interactive + TTY)
  if _has_tty && ! is_true "$SILENT"; then
    _compute_needs_key_review
    if (( NEEDS_KEY_REVIEW == 1 )); then
      local review
      review="$(read_choice "Review/edit key settings (only the ones you didn’t pass)? [y/N]: " "n")"
      [[ "$review" =~ ^y ]] && _prompt_key_settings
    fi
  fi
}
# End interactive helpers
VALID_UTLS_FPS=(chrome firefox safari edge ios android randomized)
_validate_in_list(){
  local val="$1"; shift
  local x
  for x in "$@"; do [[ "$val" == "$x" ]] && return 0; done
  return 1
}
WAN6=""
if [[ "$IPV6_MODE" != "v4only" ]]; then
  WAN6="$(detect_wan_if6 || true)"
fi
IPV6_FWD=""
# Enable IPv6 forwarding only if we have a default route
if [[ "$IPV6_MODE" != "v4only" ]] && WAN6=$(detect_wan_if6); then
  IPV6_FWD=$(cat <<EOF
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.${WAN6}.accept_ra=2
EOF
)
fi
enable_sysctl(){
  msg "Enabling forwarding + BBR + fq qdisc…"
  cat >/etc/sysctl.d/99-dualhop.conf <<EOF
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
${IPV6_FWD}
EOF
  sysctl -p /etc/sysctl.d/99-dualhop.conf >/dev/null
}

install_pkgs(){
  msg "Installing prerequisites…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -yq
  apt-get install -yq ca-certificates curl jq iproute2 iptables iptables-persistent wireguard resolvconf openssl ipcalc

}
dns_want_v6() {
  # returns 0 if we should emit v6 server, else 1
  case "${DNS_USE_V6}" in
    1|true|yes) return 0 ;;
    0|false|no) return 1 ;;
    auto)
      [[ "${IPV6_MODE:-dual}" != "v4only" ]] && return 0 || return 1
      ;;
    *) return 1 ;;
  esac
}
install_singbox(){
  [[ "${SKIP_SINGBOX_INSTALL:-0}" == "1" ]] && return 0
  if [[ "$ROLE" == "1st" ]]; then
    if ! cmd_exists sing-box; then
      msg "Installing sing-box via official installer…"
      curl -fsSL https://sing-box.app/install.sh | sh
      systemctl daemon-reload
    fi
  fi
}
port_owner() {
  local p="$1"
  local line
  line="$(ss -H -lntp "( sport = :$p )" 2>/dev/null | head -n1)" || return 1
  local name pid
  name="$(sed -n 's/.*users:(("\([^"]\+\)".*/\1/p' <<<"$line")"
  pid="$(sed -n 's/.*users:((".*pid=\([0-9]\+\).*/\1/p' <<<"$line")"
  [[ -n "$name" && -n "$pid" ]] || return 1
  echo "$name $pid"
}
port_is_free() {
  local p="$1"
  ss -H -lntp "( sport = :$p )" | grep -q . && return 1 || return 0
}
read_choice() {
  # read a single lowercased char with default
  local prompt="$1" default="${2:-}"
  local ans=""
  read -r -p "$prompt" ans || true
  ans="${ans,,}"
  [[ -z "$ans" && -n "$default" ]] && ans="$default"
  printf "%s" "$ans"
}

read_new_port() {
  local np=""
  while :; do
    read -r -p "Enter an alternative TCP port (1-65535): " np || true
    [[ "$np" =~ ^[0-9]+$ ]] && (( np>=1 && np<=65535 )) && { echo "$np"; return 0; }
    echo "Invalid port."
  done
}

ensure_port_free() {
  local -n _port_ref="$1"
  local allow_owner="${2:-}"

  while ! port_is_free "${_port_ref}"; do
    local info name pid
    info="$(port_owner "${_port_ref}")" || info=""
    name="${info%% *}"; pid="${info##* }"

    # If the port is owned by what we expect (sing-box), that's fine.
    if [[ -n "$allow_owner" && "$name" == "$allow_owner" ]]; then
      return 0
    fi
    if [[ -t 0 ]]; then
      echo
      echo "TCP port ${_port_ref} is in use by '${name:-unknown}' (pid ${pid:-?})."
      if [[ "$name" == "sing-box" ]]; then
        local c
        c="$(read_choice "Kill sing-box and free port ${_port_ref}? [y]yes / [n]no / [c]change port [y]: " "y")"
        case "$c" in
          y|yes)
            systemctl kill sing-box 2>/dev/null || true
            # fallback in case it's not a systemd-managed instance
            [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
            sleep 0.5
            continue
            ;;
          c|change)
            _port_ref="$(read_new_port)"
            continue
            ;;
          n|no)
            echo "Aborting."
            return 2
            ;;
          *) ;;
        esac
      else
        # Any other owner: busybox, nginx, whatever
        local c
        c="$(read_choice "Port ${_port_ref} is owned by '${name:-unknown}' (pid ${pid:-?}). [c]change port / [k]kill pid / [a]abort [c]: " "c")"
        case "$c" in
          k|kill)
            if [[ -n "$pid" ]]; then
              kill -TERM "$pid" 2>/dev/null || true
              sleep 0.5
              continue
            else
              echo "Don't know the PID; cannot kill. Choose another port."
              _port_ref="$(read_new_port)"
              continue
            fi
            ;;
          a|abort)
            echo "Aborting."
            exit 2
            ;;
          c|change|*)
            _port_ref="$(read_new_port)"
            continue
            ;;
        esac
      fi
    else
      # Non-interactive: fail fast with context
      fatal "TCP port ${_port_ref} is in use by '${name:-unknown}' (pid ${pid:-?}). Run interactively to resolve or pick a different port with --reality-port."
    fi
  done
}

preflight_route_conflict(){
  # Ensure H1_V4_POOL is set (e.g., 10.10.0.0/24)
  [[ -z "${H1_V4_POOL:-}" ]] && { warn "preflight_route_conflict: H1_V4_POOL is empty; skipping check."; return 0; }

  if command -v ipcalc >/dev/null 2>&1; then
    local net
    net="$(ipcalc -n "$H1_V4_POOL" | awk '/Network:/{print $2}')"
    if [[ -n "$net" ]]; then
      # Use an if-block so grep's non-match (exit 1) doesn't trigger -e/pipefail
      if ip -4 route | awk '{print $1}' | grep -Fxq -- "$net"; then
        fatal "Route conflict with $net"
      fi
    else
      warn "preflight_route_conflict: ipcalc returned empty network for '$H1_V4_POOL'; skipping."
    fi
  else
    # Fallback heuristic: look for same /24 base in routing table
    local base
    base="$(echo "$H1_V4_POOL" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3"."}')"
    if [[ -n "$base" ]]; then
      if ip -4 route | grep -Fq -- "$(echo "$base" | sed 's/\./\\./g')"; then
        fatal "Route conflict: $H1_V4_POOL overlaps."
      fi
    fi
  fi
}
# DNS lockdown options
lockdown_dns_to_wg() {
  # Only make sense on hop-1 (edge). On hop-2 it can break NATed clients.
  [[ "$ROLE" != "1st" ]] && { msg "DNS lockdown: skipped (ROLE=$ROLE)"; return 0; }

  local TBL="${WG_TABLE:-51820}"
  local TEST_HOST="${DNS_TEST_HOST:-cloudflare.com}"

  case "${DNS_LOCKDOWN:-off}" in
    off|'')
      msg "DNS lockdown: off"
      return 0
      ;;
    mark53)
      # Preflight: ensure wg table has a default route
      if ! ip -4 route show table "$TBL" | grep -q '^default'; then
        warn "DNS lockdown: table $TBL has no IPv4 default; skipping mark53."
        return 0
      fi
      # (IPv6 optional)
      # Ensure policy rules for fwmark exist
      ip -4 rule show | grep -q "fwmark 0x1 .* lookup $TBL" || ip -4 rule add fwmark 0x1 lookup "$TBL" priority 10001
      ip -6 rule show | grep -q "fwmark 0x1 .* lookup $TBL" || ip -6 rule add fwmark 0x1 lookup "$TBL" priority 10001

      # Mark all local DNS (idempotent)
      iptables  -t mangle -C OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1 2>/dev/null \
        || iptables  -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1
      iptables  -t mangle -C OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1 2>/dev/null \
        || iptables  -t mangle -A OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1
      ip6tables -t mangle -C OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1 2>/dev/null \
        || ip6tables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1
      ip6tables -t mangle -C OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1 2>/dev/null \
        || ip6tables -t mangle -A OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1
      ;;
    drop53)
      # Extremely strict: will break host DNS unless you’ve rehomed upstreams.
      [[ "${DNS_LOCKDOWN_FORCE:-0}" = 1 ]] || {
        warn "DNS lockdown: 'drop53' is dangerous; set DNS_LOCKDOWN_FORCE=1 to enable. \nExtremely strict: will break host DNS unless you’ve rehomed upstreams. Skipping."
        return 0
      }
      # allow loopback & wg, then reject everything else
      iptables  -C OUTPUT -o lo     -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables  -I OUTPUT 1 -o lo     -p udp --dport 53 -j ACCEPT
      iptables  -C OUTPUT -o lo     -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables  -I OUTPUT 2 -o lo     -p tcp --dport 53 -j ACCEPT
      iptables  -C OUTPUT -o "${WG_IF}" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables  -I OUTPUT 3 -o "${WG_IF}" -p udp --dport 53 -j ACCEPT
      iptables  -C OUTPUT -o "${WG_IF}" -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables  -I OUTPUT 4 -o "${WG_IF}" -p tcp --dport 53 -j ACCEPT
      iptables  -C OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || iptables  -A OUTPUT -p udp --dport 53 -j REJECT
      iptables  -C OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null || iptables  -A OUTPUT -p tcp --dport 53 -j REJECT

      ip6tables -C OUTPUT -o lo     -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o lo     -p udp --dport 53 -j ACCEPT
      ip6tables -C OUTPUT -o lo     -p tcp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 2 -o lo     -p tcp --dport 53 -j ACCEPT
      ip6tables -C OUTPUT -o "${WG_IF}" -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 3 -o "${WG_IF}" -p udp --dport 53 -j ACCEPT
      ip6tables -C OUTPUT -o "${WG_IF}" -p tcp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 4 -o "${WG_IF}" -p tcp --dport 53 -j ACCEPT
      ip6tables -C OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || ip6tables -A OUTPUT -p udp --dport 53 -j REJECT
      ip6tables -C OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null || ip6tables -A OUTPUT -p tcp --dport 53 -j REJECT
      ;;
    *)
      warn "DNS lockdown: unknown mode '${DNS_LOCKDOWN}'"
      return 0
      ;;
  esac

  # Sanity check: ensure host DNS still works. If not, rollback.
  if ! timeout 5 getent ahosts "$TEST_HOST" >/dev/null; then
    warn "DNS check failed after lockdown; rolling back rules."
    # rollback mark53 bits (idempotent)
    iptables  -t mangle -D OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1 2>/dev/null || true
    iptables  -t mangle -D OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1 2>/dev/null || true
    ip6tables -t mangle -D OUTPUT -p udp --dport 53 -j MARK --set-mark 0x1 2>/dev/null || true
    ip6tables -t mangle -D OUTPUT -p tcp --dport 53 -j MARK --set-mark 0x1 2>/dev/null || true
    ip -4 rule del fwmark 0x1 lookup "$TBL" priority 10001 2>/dev/null || true
    ip -6 rule del fwmark 0x1 lookup "$TBL" priority 10001 2>/dev/null || true

    # rollback drop53 bits (if any)
    for t in iptables ip6tables; do
      $t -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || true
      $t -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null || true
      $t -D OUTPUT -o "${WG_IF}" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
      $t -D OUTPUT -o "${WG_IF}" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
      $t -D OUTPUT -o lo       -p udp --dport 53 -j ACCEPT 2>/dev/null || true
      $t -D OUTPUT -o lo       -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    done
    return 1
  fi

  msg "DNS lockdown applied; resolution is OK."
}
save_iptables(){
  msg "Persisting iptables rules…"
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 || true
  systemctl enable --now netfilter-persistent >/dev/null 2>&1 || true
  systemctl restart netfilter-persistent >/dev/null 2>&1 || true
}
# Fills globals: DOH_SNI, DOH_PATH_V4, DOH_HOST_V4, DOH_PATH_V6, DOH_HOST_V6
dns_fill_preset() {
  DOH_SNI=""; DOH_PATH_V4="/dns-query"; DOH_HOST_V4=""; DOH_PATH_V6="/dns-query"; DOH_HOST_V6=""

  case "${DNS_PROVIDER}" in
    cloudflare)
      DOH_SNI="cloudflare-dns.com"
      DOH_HOST_V4="1.1.1.1"
      DOH_HOST_V6="2606:4700:4700::1111"
      ;;
    google)
      DOH_SNI="dns.google"
      DOH_HOST_V4="8.8.8.8"
      DOH_HOST_V6="2001:4860:4860::8888"
      ;;
    quad9)
      DOH_SNI="dns.quad9.net"
      DOH_HOST_V4="9.9.9.9"
      DOH_HOST_V6="2620:fe::fe"
      ;;
    adguard)
      DOH_SNI="dns.adguard.com"
      DOH_HOST_V4="94.140.14.14"
      DOH_HOST_V6="2a10:50c0::ad1:ff"
      ;;
    opendns)
      DOH_SNI="doh.opendns.com"
      DOH_HOST_V4="208.67.222.222"
      DOH_HOST_V6="2620:0:ccc::2"
      ;;
    nextdns)
      [[ -n "${DNS_NEXTDNS_ID}" ]] || fatal "NextDNS selected but --dns-nextdns-id not provided."
      DOH_SNI="dns.nextdns.io"
      DOH_PATH_V4="/${DNS_NEXTDNS_ID}"
      DOH_PATH_V6="/${DNS_NEXTDNS_ID}"
      DOH_HOST_V4=""  # let SNI resolve
      DOH_HOST_V6=""
      ;;
    custom)
      [[ -n "${DNS_CUSTOM_URL}" && -n "${DNS_CUSTOM_SNI}" ]] || \
        fatal "Custom DNS needs --dns-custom-url and --dns-custom-sni."
      # Extract path & host part from URL (very simple parser)
      local _rest="${DNS_CUSTOM_URL#*://}"
      local _host="${_rest%%/*}"
      local _path="/${_rest#*/}"
      [[ "$_rest" == "$_host" ]] && _path="/dns-query" 
      DOH_SNI="$DNS_CUSTOM_SNI"
      DOH_PATH_V4="$_path"; DOH_PATH_V6="$_path"
      DOH_HOST_V4="${DNS_CUSTOM_IP4:-$_host}"
      DOH_HOST_V6="${DNS_CUSTOM_IP6:-}"
      ;;
    *)
      fatal "Unknown DNS provider: ${DNS_PROVIDER}"
      ;;
  esac
}
DNS_STRATEGY="ipv4_only"
[[ "$IPV6_MODE" != "v4only" ]] && DNS_STRATEGY="prefer_ipv6"
render_dns_servers_json() {
  dns_fill_preset

  local servers=()

  # Primary v4 (tag dns-remote)
  if [[ -n "$DOH_HOST_V4" ]]; then
    servers+=("{
      \"type\": \"https\",
      \"tag\": \"dns-remote\",
      \"server\": \"${DOH_HOST_V4}\",
      \"server_port\": 443,
      \"path\": \"${DOH_PATH_V4}\",
      \"tls\": { \"enabled\": true, \"server_name\": \"${DOH_SNI}\" },
      \"detour\": \"direct-wg\",
      \"domain_resolver\": { \"server\": \"dns-local\", \"strategy\": \"${DNS_STRATEGY}\" }
    }")
  fi

  # Optional v6 (tag dns-remote-v6)
  if dns_want_v6 && [[ -n "$DOH_HOST_V6" ]]; then
    servers+=("{
      \"type\": \"https\",
      \"tag\": \"dns-remote-v6\",
      \"server\": \"${DOH_HOST_V6}\",
      \"server_port\": 443,
      \"path\": \"${DOH_PATH_V6}\",
      \"tls\": { \"enabled\": true, \"server_name\": \"${DOH_SNI}\" },
      \"detour\": \"direct-wg\",
      \"domain_resolver\": { \"server\": \"dns-local\", \"strategy\": \"${DNS_STRATEGY}\" }
    }")
  fi

  # Local resolver tag (used by domain_resolver refs above)
  servers+=("{ \"type\": \"local\", \"tag\": \"dns-local\" }")

  local IFS=$'\n'
  printf "[\n%s\n]" "$(printf '%s,\n' "${servers[@]}" | sed '$ s/,$//')"
}

# WireGuard (shared)
wg_gen_keys(){
  local d="$1"
  mkdir -p "$d"
  umask 077
  [[ -f "$d/privatekey" ]] || wg genkey | tee "$d/privatekey" | wg pubkey > "$d/publickey"
}

wg_setup_h2(){ # WG server on hop-2 (egress, NATs out)
  msg "Configuring WireGuard on hop-2 (server)…"
  ensure_udp_port_free_for_wg
  preflight_route_conflict
  local d_srv="/etc/wireguard/keys-server"
  local d_peer="/etc/wireguard/keys-peer"
  wg_gen_keys "$d_srv"
  wg_gen_keys "$d_peer"

  local srv_priv="$(cat "$d_srv/privatekey")"
  local srv_pub="$(cat "$d_srv/publickey")"
  local peer_priv="$(cat "$d_peer/privatekey")"
  local peer_pub="$(cat "$d_peer/publickey")"

  local WAN4="$(detect_wan_if4)"; [[ -n "$WAN4" ]] || fatal "Cannot detect WAN IPv4 interface."
  local H2_PUBLIC_IP
  H2_PUBLIC_IP="$(curl -fsS https://checkip.amazonaws.com || curl -fsS https://api.ipify.org || ip -4 addr show "$WAN4" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)" || true
  [[ -n "$H2_PUBLIC_IP" ]] || fatal "Could not detect hop-2 public IP."

v6_rules=""
v6_rules_down=""
if [[ "$IPV6_MODE" != "v4only" && -n "$WAN6" ]]; then
v6_rules_down="$(cat <<EOF
PostDown = ip6tables -D FORWARD -i ${WG_IF} -o ${WAN6} -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i ${WAN6} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -t nat -D POSTROUTING -s ${H1_V6_POOL} -o ${WAN6} -j MASQUERADE 2>/dev/null || true
PostDown = ip6tables -t mangle -D FORWARD -i ${WAN6} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = ip6tables -t mangle -D FORWARD -i ${WG_IF} -o ${WAN6} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
EOF
)"
fi
if [[ "$IPV6_MODE" != "v4only" && -n "$WAN6" ]]; then
v6_rules="$(cat <<EOF
# v6 forward + NAT66 + MSS clamp
PostUp = ip6tables -C FORWARD -i ${WG_IF} -o ${WAN6} -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i ${WG_IF} -o ${WAN6} -j ACCEPT
PostUp = ip6tables -C FORWARD -i ${WAN6} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i ${WAN6} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -t nat -C POSTROUTING -s ${H1_V6_POOL} -o ${WAN6} -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s ${H1_V6_POOL} -o ${WAN6} -j MASQUERADE
PostUp = ip6tables -t mangle -C FORWARD -i ${WAN6} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A FORWARD -i ${WAN6} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = ip6tables -t mangle -C FORWARD -i ${WG_IF} -o ${WAN6} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A FORWARD -i ${WG_IF} -o ${WAN6} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF
)"
fi

  local ADDR_V6_SUFFIX="" ALLOWED_V6_SUFFIX=""
  if [[ "$IPV6_MODE" != "v4only" ]]; then
    ADDR_V6_SUFFIX=", ${WG_H2_V6}"
    ALLOWED_V6_SUFFIX=", ${H1_V6_POOL}"
  fi

  if ss -H -lun | awk '{print $5}' | grep -q ":${WG_PORT}$"; then
    fatal "UDP port ${WG_PORT} is already in use."
  fi
local ipv6_preup_rules=""
if [[ "$IPV6_MODE" != "v4only" ]]; then
ipv6_preup_rules="$(cat <<EOF
PostUp = sysctl -w net.ipv6.conf.all.forwarding=1
PostUp = sysctl -w net.ipv6.conf.${WAN6}.accept_ra=2
PostUp = modprobe ip6table_nat 2>/dev/null || true
EOF
)"
fi
  cat >/etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
PrivateKey = ${srv_priv}
Address = ${WG_H2_V4}${ADDR_V6_SUFFIX}
ListenPort = ${WG_PORT}
# Optional but recommended for stability on double-hop + TLS
MTU = 1380
# IPv4 + IPv6 forwarding/NAT/MSS (${WAN4} is your WAN)
PostUp = sysctl -w net.ipv4.ip_forward=1
${ipv6_preup_rules}
# v4 forward + MASQUERADE
PostUp = iptables -C FORWARD -i ${WG_IF} -o ${WAN4} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${WG_IF} -o ${WAN4} -j ACCEPT
PostUp = iptables -C FORWARD -i ${WAN4} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${WAN4} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s ${H1_V4_POOL} -o ${WAN4} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${H1_V4_POOL} -o ${WAN4} -j MASQUERADE
PostUp = iptables -t mangle -C FORWARD -i ${WAN4} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -i ${WAN4} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -C FORWARD -i ${WG_IF} -o ${WAN4} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -i ${WG_IF} -o ${WAN4} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
${v6_rules}
# Cleanly remove on stop
PostDown = iptables -D FORWARD -i ${WG_IF} -o ${WAN4} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${WAN4} -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s ${H1_V4_POOL} -o ${WAN4} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -i ${WAN4} -o ${WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -i ${WG_IF} -o ${WAN4} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
${v6_rules_down}
PreUp = ip link del ${WG_IF} 2>/dev/null || true
PreUp = ip addr flush dev ${WG_IF} 2>/dev/null || true
PreDown = true
SaveConfig = false

[Peer]
# Hop-1 peer
PublicKey = ${peer_pub}
AllowedIPs = ${H1_V4_POOL}${ALLOWED_V6_SUFFIX}
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/${WG_IF}.conf

  # Bundle for hop-1 import
  local bundle="/root/wg-link-bundle.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  cp "$d_peer/privatekey" "$tmp/h1_privatekey"
  printf "%s" "$srv_pub" > "$tmp/h2_publickey"
  cat >"$tmp/vars" <<BUNDLE
WG_PORT=${WG_PORT}
WG_IF=${WG_IF}
WG_TABLE=${WG_TABLE}
WG_H1_V4=${WG_H1_V4}
WG_H1_V6=${WG_H1_V6}
WG_H2_V4=${WG_H2_V4}
WG_H2_V6=${WG_H2_V6}
H1_V4_POOL=${H1_V4_POOL}
H1_V6_POOL=${H1_V6_POOL}
IPV6_MODE=${IPV6_MODE}
H2_ENDPOINT=${H2_PUBLIC_IP}:${WG_PORT}
BUNDLE
  tar -C "$tmp" -czf "$bundle" h1_privatekey h2_publickey vars
  rm -rf "$tmp"
  msg "WG bundle created: ${bundle}"
  systemctl enable --now "wg-quick@${WG_IF}.service"
  lockdown_dns_to_wg
  save_iptables
}

wg_setup_h1(){ # WG client on hop-1 (edge)
  msg "Configuring WireGuard on hop-1 (client)…"
  local bundle="/root/wg-link-bundle.tar.gz"
  [[ -f "$bundle" ]] || fatal "Missing ${bundle}. Run the script on hop-2 first and scp the bundle here."
  local tmp; tmp="$(mktemp -d)"; tar -xzf "$bundle" -C "$tmp"
  # shellcheck disable=SC1090
  source "$tmp/vars"
  local cli_priv="$(cat "$tmp/h1_privatekey")"
  local srv_pub="$(cat "$tmp/h2_publickey")"
  rm -rf "$tmp"

  local ADDR_V6_SUFFIX="" ALLOW_V6_SUFFIX=""
  if [[ "$IPV6_MODE" != "v4only" ]]; then
    ADDR_V6_SUFFIX=", ${WG_H1_V6}"
    ALLOW_V6_SUFFIX=", ::/0"
  fi
local ipv6_h1_postup_rules=""
if [[ "$IPV6_MODE" != "v4only" ]]; then
ipv6_h1_postup_rules="$(cat <<EOF
PostUp = bash -lc 'ip -6 rule list priority 10000 | grep -q "oif ${WG_IF} lookup ${WG_TABLE}" || ip -6 rule add oif ${WG_IF} lookup ${WG_TABLE} priority 10000'
PostUp = ip -6 route replace default dev ${WG_IF} table ${WG_TABLE}
EOF
)"
fi
local ipv6_h1_postdown_rules=""
if [[ "$IPV6_MODE" != "v4only" ]]; then
ipv6_h1_postdown_rules="$(cat <<EOF
PostDown = ip -6 rule del oif ${WG_IF} lookup ${WG_TABLE} priority 10000 || true
PostDown = ip -6 route del default dev ${WG_IF} table ${WG_TABLE} || true
EOF
)"
fi
  cat >/etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
PrivateKey = ${cli_priv}
Address = ${WG_H1_V4}${ADDR_V6_SUFFIX}
# Keep main default route; sing-box will bind to ${WG_IF} explicitly.
Table = off
PreUp = ip link del ${WG_IF} 2>/dev/null || true
PreUp = ip addr flush dev ${WG_IF} 2>/dev/null || true
PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Make "sockets bound to ${WG_IF}" actually route via ${WG_IF} (without hijacking the main table)
PostUp = bash -lc 'ip -4 rule list priority 10000 | grep -q "oif ${WG_IF} lookup ${WG_TABLE}" || ip -4 rule add oif ${WG_IF} lookup ${WG_TABLE} priority 10000'
PostUp = ip -4 route replace default dev ${WG_IF} table ${WG_TABLE}
${ipv6_h1_postup_rules}
PreDown = true
PostDown = ip -4 rule del oif ${WG_IF} lookup ${WG_TABLE} priority 10000 || true
PostDown = ip -4 route del default dev ${WG_IF} table ${WG_TABLE} || true
${ipv6_h1_postdown_rules}
SaveConfig = false

[Peer]
PublicKey = ${srv_pub}
Endpoint = ${H2_ENDPOINT}
AllowedIPs = 0.0.0.0/0${ALLOW_V6_SUFFIX}
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/${WG_IF}.conf
  systemctl enable --now "wg-quick@${WG_IF}.service"
  lockdown_dns_to_wg
}

# sing-box (hop-1)
singbox_lockdown_execstart(){
  # Force a single config file: no -D merges -> no duplicate tags
  local sb_bin; sb_bin="$(command -v sing-box || echo /usr/bin/sing-box)"
  mkdir -p /etc/systemd/system/sing-box.service.d
  cat >/etc/systemd/system/sing-box.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=${sb_bin} run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2s
EOF

 cat >/etc/systemd/system/sing-box.service.d/hardening.conf <<EOF
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/etc/sing-box /var/log
EOF
  systemctl daemon-reload
}
# MULTI-LINK STORE
# We maintain two files (idempotent):
#   /etc/sing-box/uuids      -> one UUID per line
#   /etc/sing-box/short_ids  -> one short_id (8 hex) per line
# We keep original files as seeds: /etc/sing-box/uuid and /etc/sing-box/short_id
# Exact-line delete (already added earlier)
_delete_exact_line() {
  local file="$1" needle="$2" tmp
  tmp="$(mktemp)"
  if [[ -f "$file" ]]; then
    grep -Fxv -- "$needle" "$file" > "$tmp" || true
    mv "$tmp" "$file"
  else
    rm -f "$tmp"
  fi
}
# Normalize store files (dedupe, strip CRLF) — optional but recommended
normalize_store_files(){
  for f in /etc/sing-box/uuids /etc/sing-box/short_ids; do
    [[ -f "$f" ]] || continue
    sed -i 's/\r$//' "$f"
    awk 'NF{print $0}' "$f" | awk '!seen[$0]++' > "${f}.tmp" && mv "${f}.tmp" "$f"
    chmod 600 "$f"
  done
}
# Revoke one UUID or all (when val == '*')
revoke_uuid() {
  local val="$1" f="/etc/sing-box/uuids"
  [[ -z "$val" ]] && return 0
  [[ -f "$f" ]] || return 0
  if [[ "$val" == "*" ]]; then
    cp -a "$f" "${f}.bak.$(date +%s)" || true
    : > "$f"
  else
    _delete_exact_line "$f" "$val"
  fi
}
# Revoke one SID or all (when val == '*')
revoke_sid() {
  local val="$1" f="/etc/sing-box/short_ids"
  [[ -z "$val" ]] && return 0
  [[ -f "$f" ]] || return 0
  if [[ "$val" == "*" ]]; then
    cp -a "$f" "${f}.bak.$(date +%s)" || true
    : > "$f"
  else
    _delete_exact_line "$f" "$val"
  fi
}
# Revoke all links (UUIDs and SIDs)
revoke_all_links() {
  # Truncate (zero out) the stores in-place
  : > /etc/sing-box/uuids
  : > /etc/sing-box/short_ids
}
ensure_link_store() {
  mkdir -p /etc/sing-box
  # ensure base UUID list
  if [[ ! -f /etc/sing-box/uuids ]]; then
    if [[ -f /etc/sing-box/uuid ]]; then
      tr -d '\n' </etc/sing-box/uuid > /etc/sing-box/uuids
      echo >> /etc/sing-box/uuids
    else
      sing-box generate uuid | tr -d '\n' > /etc/sing-box/uuids
      echo >> /etc/sing-box/uuids
      tee /etc/sing-box/uuid </etc/sing-box/uuids >/dev/null
    fi
  fi
  # ensure base SID list
  if [[ ! -f /etc/sing-box/short_ids ]]; then
    if [[ -f /etc/sing-box/short_id ]]; then
      tr -d '\n' </etc/sing-box/short_id > /etc/sing-box/short_ids
      echo >> /etc/sing-box/short_ids
    else
      sing-box generate rand 8 --hex | awk 'NR==1{print tolower($0)}' > /etc/sing-box/short_ids
      tee /etc/sing-box/short_id </etc/sing-box/short_ids >/dev/null
    fi
  fi
  chmod 600 /etc/sing-box/uuids /etc/sing-box/short_ids
}

gen_uuid()   { sing-box generate uuid | tr -d '\n'; }
gen_sid8()   { sing-box generate rand 8 --hex | awk 'NR==1{print tolower($0)}'; }

append_uuid() { local u; u="$(gen_uuid)"; echo "$u" >> /etc/sing-box/uuids; echo "$u"; }
append_sid()  { local s; s="$(gen_sid8)";  echo "$s" >> /etc/sing-box/short_ids; echo "$s"; }

revoke_uuid() { [[ -z "$1" ]] && return 0; sed -i "/^${1//\//\\/}\$/d" /etc/sing-box/uuids; }
revoke_sid()  { [[ -z "$1" ]] && return 0; sed -i "/^${1//\//\\/}\$/d" /etc/sing-box/short_ids; }

list_uuids()  { awk 'NF' /etc/sing-box/uuids 2>/dev/null; }
list_sids()   { awk 'NF' /etc/sing-box/short_ids 2>/dev/null; }

new_link_pair() {
  # Returns "UUID SID" (SID may be existing or new depending on NEW_SID)
  ensure_link_store
  local u s
  u="$(append_uuid)"
  if [[ "$NEW_SID" == "1" ]]; then
    s="$(append_sid)"
  else
    s="$(tail -n1 /etc/sing-box/short_ids)"
  fi
  echo "$u $s"
}
gen_uuid4() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    # fallback via openssl
    openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
  fi
}

gen_sid() {
  # default short id length = 8 hex
  local len="${1:-8}"
  # ensure even length
  if (( len % 2 )); then len=$((len+1)); fi
  openssl rand -hex $((len/2)) | tr '[:upper:]' '[:lower:]'
}

normalize_store_files(){
  for f in /etc/sing-box/uuids /etc/sing-box/short_ids; do
    [[ -f "$f" ]] || continue
    sed -i 's/\r$//' "$f"
    awk 'NF{print $0}' "$f" | awk '!seen[$0]++' > "${f}.tmp" && mv "${f}.tmp" "$f"
    chmod 600 "$f"
  done
}
fresh_link() {
  
  # replace or add
  ensure_link_store
  local u s
  u="$(gen_uuid)"
  if [[ "$NEW_SID" == "1" ]]; then s="$(gen_sid8)"; else s="$(tail -n1 /etc/sing-box/short_ids)"; fi
  case "$FRESH_URL_MODE" in
    add)
      echo "$u" >> /etc/sing-box/uuids
      [[ "$NEW_SID" == "1" ]] && echo "$s" >> /etc/sing-box/short_ids
      ;;
    replace|*)
      printf "%s\n" "$u" > /etc/sing-box/uuids
      if [[ "$NEW_SID" == "1" ]]; then printf "%s\n" "$s" > /etc/sing-box/short_ids; fi
      # keep legacy singletons in sync (handy for backups)
      printf "%s\n" "$u" > /etc/sing-box/uuid
      [[ "$NEW_SID" == "1" ]] && printf "%s\n" "$s" > /etc/sing-box/short_id
      ;;
  esac
  echo "$u $s"
}
rotate_reality_keypair() {
  msg "Rotating REALITY keypair (this will invalidate ALL existing links)…"
  sing-box generate reality-keypair | tee /etc/sing-box/reality.key >/dev/null
  chmod 600 /etc/sing-box/reality.key
}
# Build JSON fragments from store
json_users_array() {
  local arr=() u
  while read -r u; do
    [[ -z "$u" ]] && continue
    if [[ -n "$REALITY_FLOW" ]]; then
      arr+=( "{ \"uuid\": \"${u}\", \"flow\": \"${REALITY_FLOW}\" }" )
    else
      arr+=( "{ \"uuid\": \"${u}\" }" )
    fi
  done < <(list_uuids)
  local IFS=$'\n'; printf "[%s]" "$(printf '%s,' "${arr[@]}" | sed 's/,$//')"
}

json_short_ids_array() {
  local arr=() s
  while read -r s; do
    [[ -z "$s" ]] && continue
    arr+=( "\"${s}\"" )
  done < <(list_sids)
  local IFS=$'\n'; printf "[%s]" "$(printf '%s,' "${arr[@]}" | sed 's/,$//')"
}

print_all_links() {
  local PUB_KEY="$(awk '/PublicKey:/ {print $2}' /etc/sing-box/reality.key)"
  local HOST; HOST="$(curl -fsS https://checkip.amazonaws.com || hostname -I | awk '{print $1}')"; HOST="${HOST//$'\n'/}"
  local sid
  while read -r U; do
    [[ -z "$U" ]] && continue
    while read -r sid; do
      [[ -z "$sid" ]] && continue
      local url="vless://${U}@${HOST}:${REALITY_PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB_KEY}&sid=${sid}&fp=${UTLS_FP}&type=tcp"
      [[ -n "$REALITY_FLOW" ]] && url+="&flow=${REALITY_FLOW}"
      url+="#dualhop-edge"
      echo "$url"
    done < <(tac /etc/sing-box/short_ids)  # newest first
  done < <(list_uuids)
}
print_all_links_all_sids(){
  local PUB_KEY HOST sid U
  PUB_KEY="$(awk '/PublicKey:/ {print $2}' /etc/sing-box/reality.key)"
  HOST="$(curl -fsS https://checkip.amazonaws.com || hostname -I | awk '{print $1}')"; HOST="${HOST//$'\n'/}"
  while read -r U; do
    [[ -z "$U" ]] && continue
    while read -r sid; do
      [[ -z "$sid" ]] && continue
      local url="vless://${U}@${HOST}:${REALITY_PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB_KEY}&sid=${sid}&fp=${UTLS_FP}&type=tcp"
      [[ -n "$REALITY_FLOW" ]] && url+="&flow=${REALITY_FLOW}"
      echo "${url}#dualhop-edge"
    done < <(tac /etc/sing-box/short_ids)
  done < <(list_uuids)
}
list_links_and_exit() {
  ensure_link_store_exists_or_die
  if [[ ! -s /etc/sing-box/uuids || ! -s /etc/sing-box/short_ids ]]; then
    echo "No users."
    exit 0
  fi
  print_all_links
  exit 0
}
_singbox_set_perms(){
  # Make it readable regardless of service User=/DynamicUser=
  chown -R root:root /etc/sing-box
  chmod 755 /etc/sing-box
  chmod 640 /etc/sing-box/config.json
}
_singbox_validate(){
  # Validate schema; (merge check unnecessary since we override ExecStart)
  sing-box check -c /etc/sing-box/config.json
}
singbox_write_config(){
  msg "Writing sing-box REALITY server config…"

  # Clean split configs to avoid duplicate inbounds
  rm -rf /etc/sing-box/conf.d 2>/dev/null || true
  mkdir -p /etc/sing-box

  # Generate creds if missing
  [[ -f /etc/sing-box/reality.key ]] || sing-box generate reality-keypair | tee /etc/sing-box/reality.key
  [[ -f /etc/sing-box/uuid ]] || sing-box generate uuid | tee /etc/sing-box/uuid
  [[ -f /etc/sing-box/short_id ]] || sing-box generate rand 8 --hex | tee /etc/sing-box/short_id

  local PRIV_KEY="$(awk '/PrivateKey:/ {print $2}' /etc/sing-box/reality.key)"
  local PUB_KEY="$(awk '/PublicKey:/ {print $2}'  /etc/sing-box/reality.key)"
  local UUID="$(tr -d '\n' </etc/sing-box/uuid)"
  local SHORTID="$(tr -d '\n' </etc/sing-box/short_id)"
  ensure_link_store
  dns_fill_preset
  local DNS_SERVERS_JSON
  DNS_SERVERS_JSON="$(render_dns_servers_json)"
  local RESOLVER_TAG="dns-remote"
  if dns_want_v6 && [[ -n "${DOH_HOST_V6:-}" ]]; then
      RESOLVER_TAG="dns-remote-v6"
  fi
  ensure_port_free REALITY_PORT "sing-box"
  local FLOW_JSON=""
  local USER_JSON="{ \"uuid\": \"${UUID}\" }"
  [[ -n "$REALITY_FLOW" ]] && USER_JSON="{ \"uuid\": \"${UUID}\", \"flow\": \"${REALITY_FLOW}\" }"
  # New DNS typed format (DoH) + default_domain_resolver; DNS dial detours to direct-wg
  local USERS_JSON SHORT_IDS_JSON
  USERS_JSON="$(json_users_array)"
  SHORT_IDS_JSON="$(json_short_ids_array)"
  cat >/etc/sing-box/config.json <<JSON
{
  "log": {
    "level": "warn"
  },
  "dns": {
    "servers": ${DNS_SERVERS_JSON}
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${REALITY_PORT},
      "users": ${USERS_JSON},
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "min_version": "${TLS_MIN}",
        "max_version": "${TLS_MAX}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${HS_EFF}",
            "server_port": ${HANDSHAKE_PORT}
          },
          "private_key": "${PRIV_KEY}",
          "short_id": ${SHORT_IDS_JSON}
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-wg",
      "bind_interface": "${WG_IF}",
      "fallback_delay": "300ms",
      "domain_resolver": {
        "server": "${RESOLVER_TAG}",
        "strategy": "${DNS_STRATEGY}"
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "final": "direct-wg",
    "default_domain_resolver": "${RESOLVER_TAG}"
  }
}
JSON

  singbox_lockdown_execstart
  _singbox_set_perms
  _singbox_validate

  systemctl enable sing-box >/dev/null 2>&1 || true
  if systemctl is-active --quiet sing-box; then
    systemctl restart sing-box
  else
    systemctl start sing-box
  fi
  sleep 1
  systemctl is-active --quiet sing-box || { journalctl -u sing-box --no-pager -n 200; fatal "sing-box failed to start."; }

# Shareable REALITY URL (pbk/sid per sharing convention)
# NOTE: this block is inside a function -> use 'return', not 'exit'
  case "${LIST_LINKS:-}" in
    1|true|yes)
      echo
      print_all_links
      echo
      return 0
      ;;
    all)
      ensure_link_store
      print_all_links_all_sids
      return 0
      ;;
  esac
  # Print just the newest UUID with newest SID
  local U SID HOST
  # tolerate empty files under -e/-u; fail with a clear error if missing
  U="$(tail -n 1 /etc/sing-box/uuids || true)"
  SID="$(tail -n 1 /etc/sing-box/short_ids || true)"
  [[ -z "${U:-}" || -z "${SID:-}" ]] && fatal "No users/SIDs found. Add one with --new-user [--new-sid]."

  # pbk might already be set upstream; compute if not
  PUB_KEY="${PUB_KEY:-$(awk '/PublicKey:/ {print $2}' /etc/sing-box/reality.key)}"
  [[ -z "${PUB_KEY:-}" ]] && fatal "Missing REALITY public key (/etc/sing-box/reality.key)."

  # public IP with sane fallbacks
  HOST="$(curl -fsS --max-time 2 https://checkip.amazonaws.com || hostname -I | awk '{print $1}')" || true
  HOST="${HOST//$'\n'/}"
  [[ -z "${HOST:-}" ]] && HOST="${SNI}"

  VLESS_URL="vless://${U}@${HOST}:${REALITY_PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB_KEY}&sid=${SID}&fp=${UTLS_FP}&type=tcp"
  [[ -n "${REALITY_FLOW:-}" ]] && VLESS_URL+="&flow=${REALITY_FLOW}"
  VLESS_URL+="#dualhop-edge"

  printf '\n \033[36mClient URL:\033[0m %s\n \n' "$VLESS_URL"
  return 0
}
# REALITY decoy preflight
resolve_single_ip() {
  # resolve_single_ip <host> [4|6] -> prints one IP or fails
  local host="$1" fam="${2:-4}" ip=""
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$host" == *:* ]]; then
    echo "$host"; return 0
  fi
  if [[ "$fam" == 4 ]]; then
    ip="$(getent ahostsv4 "$host" | awk 'NR==1{print $1}')" || true
  else
    ip="$(getent ahostsv6 "$host" | awk 'NR==1{print $1}')" || true
  fi
  [[ -n "$ip" ]] && echo "$ip" || return 1
}

PREFLIGHT_ONLY_IPV4="${PREFLIGHT_ONLY_IPV4:-0}"
# Start of Domain Checker
reality_probe() {
  local SNI="${1:-}"
  local HS="${2:-$1}"
  local PORT="${3:-443}"
  local IPVER="${4:-auto}"   # auto|4|6
  local TO="${5:-7}"
  local JSON="${6:-0}"
  local DEBUG="${7:-0}"
  local REQUIRE_X="${8:-1}"

  [[ -n "$SNI" ]] || { printf 'Usage: reality_probe <sni> [handshake] [port] [ipver] [timeout] [json] [debug]\n' >&2; return 6; }

  # Tiny helpers (no global function pollution)
  local _green=$'\033[32m' _yellow=$'\033[33m' _red=$'\033[31m' _reset=$'\033[0m'
  rp_ok()   { printf '%sOK:%s %s\n'   "$_green" "$_reset" "$*"; }
  rp_warn() { printf '%sWARN:%s %s\n' "$_yellow" "$_reset" "$*"; }
  rp_fail() { printf '%sFAIL:%s %s\n' "$_red" "$_reset" "$*"; }

  # Resolve handshake target to one IP if family is forced
  local CONNECT_HOST="$HS"
  if [[ "$IPVER" == "4" ]]; then
    if [[ "$HS" =~ ^[0-9.]+$ ]]; then :; else
      CONNECT_HOST="$(getent ahostsv4 "$HS" | awk 'NR==1{print $1}')"
      [[ -n "$CONNECT_HOST" ]] || { rp_fail "IPv4 resolve failed for $HS"; return 2; }
    fi
  elif [[ "$IPVER" == "6" ]]; then
    if [[ "$HS" =~ : ]]; then :; else
      CONNECT_HOST="$(getent ahostsv6 "$HS" | awk 'NR==1{print $1}')"
      [[ -n "$CONNECT_HOST" ]] || { rp_fail "IPv6 resolve failed for $HS"; return 2; }
    fi
  fi

  # Bracket IPv6 literal for -connect
  local CONNECT="${CONNECT_HOST}:${PORT}"
  if [[ "$CONNECT_HOST" == *:* && "$CONNECT_HOST" != *"]"* ]]; then
    CONNECT="[${CONNECT_HOST}]:${PORT}"
  fi

  # Detect -groups vs -curves for OpenSSL
  local GROUP_FLAG="-groups"
  openssl s_client -help 2>&1 | grep -q -- '-groups' || GROUP_FLAG="-curves"

  # 1) TLS 1.3 negotiation check
  local OPENSSL_OUT="" TLS13=0
  if command -v timeout >/dev/null 2>&1; then
    OPENSSL_OUT="$(timeout -k 1 "$TO" openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 </dev/null 2>&1)" || true
  else
    OPENSSL_OUT="$(openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 </dev/null 2>&1)" || true
  fi

  if grep -Eq 'Protocol *: *TLSv1\.3' <<<"$OPENSSL_OUT" \
     || grep -Eiq 'New, *TLSv1\.3' <<<"$OPENSSL_OUT" \
     || grep -Eq 'SSL-Session:.*Protocol *: *TLSv1\.3' <<<"$OPENSSL_OUT"; then
    TLS13=1
  fi

  if [[ $TLS13 -ne 1 && $(command -v curl || true) ]]; then
    # Fallback via curl to confirm TLS1.3
    local CURL_VER="" IP_LIT="" ; IP_LIT="${CONNECT_HOST#[}" ; IP_LIT="${IP_LIT%]}"
    local RESOLVE_OPT=()
    # Use --resolve when we forced an IP or family
    if [[ "$CONNECT_HOST" =~ ^\[?([0-9a-fA-F:.]+)\]?$ || "$IPVER" != "auto" ]]; then
      RESOLVE_OPT=(--resolve "${SNI}:${PORT}:${IP_LIT}")
    fi
    set +e
    if command -v timeout >/dev/null 2>&1; then
      CURL_VER="$(timeout -k 1 "$TO" curl -sS -o /dev/null -w '%{ssl_version}\n' --tlsv1.3 "https://${SNI}:${PORT}/" "${RESOLVE_OPT[@]}" 2>/dev/null)"
    else
      CURL_VER="$(curl -sS -o /dev/null -w '%{ssl_version}\n' --tlsv1.3 "https://${SNI}:${PORT}/" "${RESOLVE_OPT[@]}" 2>/dev/null)"
    fi
    set -e
    [[ "$CURL_VER" == TLSv1.3 ]] && TLS13=1
  fi

  if [[ $TLS13 -ne 1 ]]; then
    [[ $DEBUG -eq 1 ]] && { printf '\n----- openssl output snippet -----\n'; echo "$OPENSSL_OUT" | sed -n '1,80p'; printf '----------------------------------\n'; }
    rp_fail "Nope, no TLS 1.3 negotiated for SNI=${SNI} via ${CONNECT}, Try another domain. "
    [[ $JSON -eq 1 ]] && printf '{"ok":false,"reason":"no_tls13","sni":"%s","connect":"%s"}\n' "$SNI" "$CONNECT"
    return 3
  else
    rp_ok "TLS 1.3 negotiated"
  fi

  if (( REQUIRE_X )); then
    # 2) X25519 check
    local X25519_OK=0 MORE=""
    if command -v timeout >/dev/null 2>&1; then
      timeout -k 1 "$TO" openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 "$GROUP_FLAG" X25519 </dev/null >/dev/null 2>&1 && X25519_OK=1
    else
      openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 "$GROUP_FLAG" X25519 </dev/null >/dev/null 2>&1 && X25519_OK=1
    fi
    if [[ $X25519_OK -ne 1 ]]; then
      if grep -Eiq '(Group|Curve|Server Temp Key): *X25519' <<<"$OPENSSL_OUT"; then
        X25519_OK=1
      else
        if command -v timeout >/dev/null 2>&1; then
          MORE="$(timeout -k 1 "$TO" openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 </dev/null 2>&1 || true)"
        else
          MORE="$(openssl s_client -connect "$CONNECT" -servername "$SNI" -tls1_3 </dev/null 2>&1 || true)"
        fi
        grep -Eiq '(Group|Curve|Server Temp Key): *X25519' <<<"$MORE" && X25519_OK=1 || true
      fi
    fi
    if [[ $X25519_OK -ne 1 ]]; then
      if (( JSON )); then
        printf '{"ok":false,"reason":"no_x25519"}\n'
      else
        rp_fail "X25519 not present"
      fi
      return 4
    fi
  else
    (( JSON )) || rp_warn "Skipping X25519 check (per --require-x25519=0)"
  fi
  rp_ok "X25519 supported/negotiated"

  # 3) SAN contains SNI (exact match check)
  local CERT_SAN=""
  if command -v timeout >/dev/null 2>&1; then
    CERT_SAN="$(timeout -k 1 "$TO" openssl s_client -connect "$CONNECT" -servername "$SNI" -showcerts </dev/null 2>/dev/null \
      | awk 'BEGIN{p=0}/BEGIN CERTIFICATE/{p=1} p;/END CERTIFICATE/{exit}' \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)"
  else
    CERT_SAN="$(openssl s_client -connect "$CONNECT" -servername "$SNI" -showcerts </dev/null 2>/dev/null \
      | awk 'BEGIN{p=0}/BEGIN CERTIFICATE/{p=1} p;/END CERTIFICATE/{exit}' \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)"
  fi

  if grep -qi "DNS:${SNI}" <<<"$CERT_SAN"; then
    rp_ok "Certificate SAN contains ${SNI}"
  else
    [[ $DEBUG -eq 1 ]] && { printf '\n----- SAN block -----\n'; echo "$CERT_SAN"; printf '---------------------\n'; }
    rp_fail "Certificate SAN does NOT contain ${SNI}"
    if [[ $JSON -eq 1 ]]; then
      printf '{"ok":false,"reason":"san_mismatch","san_raw":%s}\n' "$(printf '%s' "$CERT_SAN" | sed 's/"/\\"/g; s/.*/"&"/')"
    fi
    return 5
  fi
  # Normalize the SNI to A-label for IDNs if idn2 exists.
  local SNI_A="$SNI"
  if command -v idn2 >/dev/null 2>&1; then
    SNI_A="$(idn2 --quiet --ace "$SNI" 2>/dev/null || echo "$SNI")"
  fi

  if san_has_name "$CERT_SAN" "$SNI" || san_has_name "$CERT_SAN" "$SNI_A"; then
    (( JSON )) || rp_ok "Certificate SAN matches ${SNI}"
  else
    (( DEBUG )) && { printf '\n----- SAN block -----\n'; echo "$CERT_SAN"; printf '---------------------\n'; }
    if (( JSON )); then
      printf '{"ok":false,"reason":"san_mismatch","san_raw":%s}\n' "$(printf '%s' "$CERT_SAN" | sed 's/"/\\"/g; s/.*/"&"/')"
    else
      rp_fail "Certificate SAN does NOT contain ${SNI}"
    fi
    return 5
  fi

  # Summaries (best-effort parse)
  local PROTO GROUP CIPHER ALPN
  PROTO="$( { grep -Eo 'Protocol *: *TLSv1\.3' <<<"$OPENSSL_OUT" || true; } | head -n1 )"
  GROUP="$( { grep -Eo '(Group|Curve|Server Temp Key): *[^ ]+' <<<"$OPENSSL_OUT" || true; } | head -n1 | sed 's/.*: *//' )"
  CIPHER="$( { grep -Eo 'Ciphersuite *: *.*' <<<"$OPENSSL_OUT" || true; } | head -n1 | sed 's/.*: *//' )"
  ALPN="$( { grep -Eo 'ALPN protocol *: *.*' <<<"$OPENSSL_OUT" || true; } | head -n1 | sed 's/.*: *//' )"
  [[ -z "$GROUP" ]] && GROUP="X25519 (parsed)"
  [[ -z "$ALPN" ]] && ALPN="(not advertised)"

  printf '\nSummary for SNI=%s  connect=%s\n' "$SNI" "$CONNECT"
  echo   "  TLS     : TLS 1.3"
  echo   "  Group   : ${GROUP}"
  echo   "  Cipher  : ${CIPHER:-unknown}"
  echo   "  ALPN    : ${ALPN}"

  if [[ $JSON -eq 1 ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq -n --arg sni "$SNI" --arg conn "$CONNECT" --arg group "$GROUP" --arg cipher "$CIPHER" --arg alpn "$ALPN" \
        '{ok:true,sni:$sni,connect:$conn,tls13:true,x25519:true,group:$group,cipher:$cipher,alpn:$alpn}'
    else
      printf '\n{"ok":true,"sni":"%s","connect":"%s","tls13":true,"x25519":true,"group":"%s","cipher":"%s","alpn":"%s"}\n' \
        "$SNI" "$CONNECT" "$GROUP" "$CIPHER" "$ALPN"
    fi
  fi

  return 0
}
# End of domain checker
# Case-insensitive SAN matcher with wildcard support (*.example.tld).
# Accepts only left-most-label wildcards (RFC 6125-ish); no bare-domain match.
san_has_name() {
  local san="$1" name="${2,,}" entry suf
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    entry="${entry#DNS:}"
    entry="${entry//[[:space:]]/}"
    entry="${entry,,}"
    # exact
    [[ "$entry" == "$name" ]] && return 0
    # wildcard on left-most label only (e.g., *.example.com)
    if [[ "$entry" == \*.* ]]; then
      suf="${entry#*.}"
      [[ "$name" == *".${suf}" ]] && return 0    # requires at least one label before suffix
    fi
  done < <(printf '%s' "$san" | tr ',' '\n' | sed -n 's/.*DNS:\s*//Ip')
  return 1
}
# Interactive preflight check
check_domain_tls() {
  local ipver="auto"
  case "${IPV6_MODE:-dual}" in v4only) ipver="4";; v6only) ipver="6";; esac
  [[ "$PREFLIGHT_ONLY_IPV4" == "1" ]] && ipver="4"
  msg "Preflight: validating REALITY decoy locally …"
  # Call the probe FUNCTION
  if reality_probe "$SNI" "$HS_EFF" "$HANDSHAKE_PORT" "$ipver" 7 0 0 "$REQUIRE_X25519"; then
    msg "Decoy OK: SNI=${SNI}, handshake=${HS_EFF}:${HANDSHAKE_PORT}, ipver=${ipver}"
    return 0    # ← important: stop here on success
  else
    rc=$?
    warn "Nope: Try another Domain (rc=${rc})"
  fi
  # Interactive fallback only when the probe failed
  [[ "${NONINTERACTIVE:-0}" == "1" ]] && fatal "Decoy check failed. Run interactively to change SNI/handshake or fix reachability."
  warn "Decoy FAILED. Codes: 2=connect, 3=no TLS1.3, 4=no X25519, 5=SAN mismatch."
  local tries=0 nsni nhs nport
  while (( tries < 4 )); do
    read -r -p "New SNI (hostname for ClientHello, or 'abort'): " nsni
    [[ "$nsni" == "abort" ]] && fatal "Aborted by user."
    [[ -z "$nsni" ]] && continue
    read -r -p "Handshake host [${nsni}]: " nhs;  nhs="${nhs:-$nsni}"
    read -r -p "Handshake port [443]: " nport;   nport="${nport:-443}"
    if reality_probe "$nsni" "$nhs" "$nport" "$ipver" 7 0 0 "$REQUIRE_X25519"; then
      SNI="$nsni"; HANDSHAKE_HOST="$nhs"; HANDSHAKE_PORT="$nport"
      msg "Decoy OK after update: SNI=${SNI}, handshake=${HANDSHAKE_HOST}:${HANDSHAKE_PORT}"
      return 0
    fi
    warn "Still failing; try again."
    tries=$((tries+1))
  done
  fatal "Exceeded attempts; pick a different decoy."
}
# read current REALITY params from live config (jq + grep fallback)
cfg="/etc/sing-box/config.json"
read_reality_params_from_config() {
  local cfg="/etc/sing-box/config.json"
  [[ -r "$cfg" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1

  # We parse JSONC: strip comments + trailing commas, then JSON-load and pick the inbound by tag.
  local out rc
  out="$(
    CFG="$cfg" TAG="$REALITY_TAG" python3 - <<'PY'
import os, re, json, sys
cfg = os.environ.get("CFG", "/etc/sing-box/config.json")
tag = os.environ.get("TAG", "reality-in")

try:
    s = open(cfg, "r", encoding="utf-8", errors="ignore").read()
except Exception:
    sys.exit(2)

# Strip /* ... */ and // comments
s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
s = re.sub(r"(?m)//.*$", "", s)
# Remove trailing commas before } or ]
s = re.sub(r",\s*([}\]])", r"\1", s)

try:
    j = json.loads(s)
except Exception:
    sys.exit(3)

ins = j.get("inbounds", [])
ib = None

# 1) Prefer exact tag match with reality enabled
for x in ins:
    try:
        if x.get("tag") != tag: continue
        tls = x.get("tls", {}) or {}
        rea = tls.get("reality", {}) or {}
        if tls.get("enabled") and rea.get("enabled"):
            ib = x; break
    except Exception:
        pass

# 2) Fallback: first vless inbound with reality enabled
if ib is None:
    for x in ins:
        try:
            if x.get("type") != "vless": continue
            tls = x.get("tls", {}) or {}
            rea = tls.get("reality", {}) or {}
            if tls.get("enabled") and rea.get("enabled"):
                ib = x; break
        except Exception:
            pass

if ib is None:
    sys.exit(4)

tls = ib.get("tls", {}) or {}
rea = tls.get("reality", {}) or {}
hs  = rea.get("handshake")
hhost = None
hport = None

def split_host_port(s: str):
    s = s.strip()
    # [IPv6]:port
    if s.startswith('[') and ']' in s:
        host = s[1:s.index(']')]
        rest = s[s.index(']')+1:]
        port = None
        if rest.startswith(':'):
            try: port = int(rest[1:])
            except: port = None
        return host, port
    # domain:port (single colon)
    if s.count(':') == 1:
        host, port = s.split(':', 1)
        try: port = int(port)
        except: port = None
        return host, port
    # bare host or IPv6 w/out port
    return s, None

if isinstance(hs, dict):
    hhost = hs.get("server")
    hport = hs.get("server_port")
elif isinstance(hs, str):
    hhost, hport = split_host_port(hs)

# SNI precedence: server_name > server_names[0] > handshake host
sni = tls.get("server_name")
if not sni:
    names = tls.get("server_names") or []
    if isinstance(names, list) and names:
        sni = names[0]
if not sni:
    sni = hhost or ""

# Port fallback: handshake port > listen_port > 443
if not hport:
    lp = ib.get("listen_port")
    if isinstance(lp, int):
        hport = lp
if not hport:
    hport = 443

print(f"{sni}\t{hhost or ''}\t{hport}")
PY
  )"
  rc=$?

  [[ $rc -eq 0 && -n "$out" ]] || return 1

  # TSV → vars
  IFS=$'\t' read -r _sni _hhost _hport <<<"$out"

  # Only set if non-empty (so CLI flags can override)
  [[ -n "${_sni:-}"  ]] && SNI="$_sni"
  [[ -n "${_hhost:-}" ]] && HANDSHAKE_HOST="$_hhost"
  [[ -n "${_hport:-}" ]] && HANDSHAKE_PORT="$_hport"

  # reasonable fallbacks if partial
  [[ -z "${HANDSHAKE_HOST:-}" && -n "${SNI:-}" ]] && HANDSHAKE_HOST="$SNI"
  [[ -z "${HANDSHAKE_PORT:-}" ]] && HANDSHAKE_PORT=443

  return 0
}
# PURGE SING-BOX (complete removal, idempotent)
purge_singbox() {
  require_root
  msg "Purging sing-box completely…"

  # Optional backup unless NO_BACKUP=1
  local bk=""
  if [[ "${NO_BACKUP:-0}" != "1" ]]; then
    bk="/root/singbox-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    msg "Creating backup at ${bk} (config/state/logrotate/logs)…"
    tar czf "$bk" \
      --ignore-failed-read \
      /etc/sing-box \
      /var/lib/sing-box \
      /etc/logrotate.d/sing-box \
      /var/log/sing-box* 2>/dev/null || true
  fi

  # Stop & disable service (best effort)
  systemctl disable --now sing-box 2>/dev/null || true
  pkill -TERM -x sing-box 2>/dev/null || true
  sleep 0.3
  pkill -KILL -x sing-box 2>/dev/null || true

  # Remove systemd unit & drop-ins wherever they might live
  rm -f  /etc/systemd/system/sing-box.service
  rm -rf /etc/systemd/system/sing-box.service.d
  rm -f  /lib/systemd/system/sing-box.service
  systemctl daemon-reload || true

  # Remove config/state/logrotate/logs
  rm -rf /etc/sing-box /var/lib/sing-box /etc/logrotate.d/sing-box /var/log/sing-box*

  # Remove binaries (manual installs and apt)
  rm -f /usr/local/bin/sing-box /usr/bin/sing-box /usr/sbin/sing-box
  if dpkg -s sing-box >/dev/null 2>&1; then
    apt-get purge -y sing-box || true
    apt-get autoremove -y --purge || true
  fi

  # Remove dedicated user/group if present (and unused)
  if id -u singbox >/dev/null 2>&1; then userdel -r singbox 2>/dev/null || true; fi
  if getent group singbox >/dev/null 2>&1; then groupdel singbox 2>/dev/null || true; fi

  # Best-effort firewall cleanup for REALITY port if we know it
  if [[ -n "${REALITY_PORT:-}" ]]; then
    iptables  -C INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT 2>/dev/null \
      && iptables  -D INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT || true
    ip6tables -C INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT 2>/dev/null \
      && ip6tables -D INPUT -p tcp --dport "$REALITY_PORT" -j ACCEPT || true
  fi

  # Clean persistent iptables rules if you ever wrote markers; keep harmless if not present
  sed -i.bak '/SB_MARK/d;/sing-box/d' /etc/iptables/rules.v4 2>/dev/null || true
  sed -i.bak '/SB_MARK/d;/sing-box/d' /etc/iptables/rules.v6 2>/dev/null || true
  iptables-restore  < /etc/iptables/rules.v4 2>/dev/null || true
  ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null || true

  ok "sing-box purged."
  [[ -n "$bk" ]] && msg "Backup: ${bk}"
  msg "You can rerun this installer to reinstall clean."
}
ensure_link_store_exists_or_die() {
  [[ -f /etc/sing-box/uuids && -f /etc/sing-box/short_ids ]] \
    || fatal "No link store to revoke from. Create users first with --new/--add."
}
confirm_revoke_all(){
  [[ "${FORCE}" == "1" ]] && return 0
  # no TTY? force required
  if ! [ -t 0 ] && ! [ -t 1 ]; then
    fatal "Non-interactive session. Use --yes with --revoke-all."
  fi
  local u=0 s=0 ans=""
  [[ -f /etc/sing-box/uuids     ]] && u=$(wc -l < /etc/sing-box/uuids || echo 0)
  [[ -f /etc/sing-box/short_ids ]] && s=$(wc -l < /etc/sing-box/short_ids || echo 0)
  printf "\nThis will DELETE ALL links (UUIDs=%s, SIDs=%s). Continue? [y/N]: " "$u" "$s" > /dev/tty
  if ! read -r -t 20 ans < /dev/tty; then
    printf "\nTimed out waiting for confirmation.\n" >&2
    return 1
  fi
  [[ "$ans" =~ ^([Yy]|[Yy][Ee][Ss])$ ]]
}
# fast path for `--probe` flag using the external helper
if [[ "${PROBE_ONLY:-0}" == "1" ]]; then
  [[ -n "${SNI:-}" ]] || { echo "--probe requires --sni <host>"; exit 2; }
  : "${HANDSHAKE_HOST:=$SNI}"
  : "${HANDSHAKE_PORT:=443}"

  fam="auto"
  case "${IPV6_MODE:-dual}" in
    v6only) fam="6" ;;
    v4only) fam="4" ;;
  esac
  [[ "${PREFLIGHT_ONLY_IPV4:-0}" == "1" ]] && fam="4"

  if reality_probe "$SNI" "$HANDSHAKE_HOST" "$HANDSHAKE_PORT" "$fam" 7 0 0 "$REQUIRE_X25519"; then
    echo "Probe OK: SNI=${SNI}, handshake=${HANDSHAKE_HOST}:${HANDSHAKE_PORT}, ipver=${fam}"
    exit 0
  else
    rc=$?; echo "Probe FAILED (rc=${rc})"; exit $rc
  fi
fi
# Run Advanced exactly once, honoring FORCE/DISABLE flags.
run_advanced_gate(){
  # idempotent: bail if we've already decided/handled advanced once
  if [[ "${__ADVANCED_ALREADY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  # forced on
  if [[ "${FORCE_ADVANCED:-0}" == "1" ]]; then
    _prompt_advanced
    __ADVANCED_ALREADY_RUN=1
    return 0
  fi
  # forced off
  if [[ "${DISABLE_ADVANCED:-0}" == "1" ]]; then
    __ADVANCED_ALREADY_RUN=1
    return 0
  fi
  # interactive gate (only on TTY and not SILENT)
  if _has_tty && ! is_true "$SILENT"; then
    local do_adv="no"
    _ask_yes_no do_adv "Review advanced settings?" 0  # default NO on Enter
    if [[ "${do_adv:-no}" == "yes" ]]; then
      _prompt_advanced
    fi
  fi
  __ADVANCED_ALREADY_RUN=1
  return 0
}
if ! WG_IF="$(pick_free_wg_if "${WG_IF:-auto}")"; then
  fatal "No free wg interface slots found."
fi
_show_branding() {
  _supports_hyperlinks() {
    [[ -t 2 ]] || return 1
    [[ "${FORCE_HYPERLINK:-}" == 1 ]] && return 0
    [[ -n "${WT_SESSION:-}" ]] && return 0                    
    [[ -n "${WEZTERM_EXECUTABLE:-}${WEZTERM_PANE:-}" ]] && return 0
    [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]] && return 0
    [[ -n "${KONSOLE_VERSION:-}" ]] && return 0
    [[ -n "${KITTY_WINDOW_ID:-}" ]] && return 0
    [[ -n "${VTE_VERSION:-}" ]] && (( VTE_VERSION >= 5000 )) && return 0 
    [[ "${TERM:-}" != "dumb" ]] || return 1
    return 1
  }

  _link() { 
    if _supports_hyperlinks; then
      printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$1" "$2" >&2
    else
      printf '%s' "$1" >&2
    fi
  }

  printf '\n\033[1;35m▞▚▞▚▞▚▞▚\033[0m \033[1mDouble-Hop VPN Installer by Abdessal.am\033[0m \033[1;35m▞▚▞▚▞▚▞▚\033[0m\n' >&2
  printf 'Looks like HTTPS. Moves like WireGuard.  Host: %s · %s UTC\n' \
    "$(hostname)" "$(date -u +'%Y-%m-%d %H:%M:%S')" >&2

  printf 'Docs: ' >&2;  _link 'https://abdessal.am' 'Guide'
  printf '  |  ' >&2;   _link 'https://github.com/abdessalllam?tab=repositories' 'Repo'
  printf '\n\n' >&2
}
[[ "${NO_BRANDING:-0}" == 1 ]] || _show_branding
# Post-parse validation
HS_EFF="$SNI"
[[ "$HANDSHAKE_FROM_ARG" == "1" ]] && HS_EFF="$HANDSHAKE_HOST"
if [[ -z "${HANDSHAKE_HOST:-}" ]]; then
  HANDSHAKE_HOST="$SNI"
  HS_EFF="$SNI"
fi
if [[ -n "$FRESH_URL_MODE" && "$ADD_LINK" == "1" ]]; then
  fatal "Use either --new/--new=add OR --new-user, not both."
fi
if [[ "$NEW_SID" == "1" && -z "$FRESH_URL_MODE" && "$ADD_LINK" != "1" ]]; then
  warn "--new-sid has no effect without --new or --new-user."
fi
if [[ -n "$FRESH_URL_MODE" && "$FRESH_URL_MODE" != "replace" && "$FRESH_URL_MODE" != "add" ]]; then
  fatal "Invalid --new value: '$FRESH_URL_MODE' (use replace|add)."
fi
if [[ "$LIST_LINKS" == "1" ]]; then
  list_links_and_exit
fi
if [[ "$SILENT" == "1" && -z "${ROLE:-}" ]]; then
  fatal "Missing --role (use 1st or 2nd)."
fi
update_users_sids_only() {
  local tag="${REALITY_TAG:-vless-reality-in}"
  local cfg="/etc/sing-box/config.json"
  [[ -r "$cfg" ]] || fatal "Missing $cfg. Run initial install first."

  local tmp users sids
  users="$(json_users_array)"      || fatal "users JSON build failed"
  sids="$(json_short_ids_array)"   || fatal "short_ids JSON build failed"
  tmp="$(mktemp)"

  jq --arg tag "$tag" \
     --argjson users "$users" \
     --argjson sids  "$sids" \
     '(.inbounds[] | select(.tag==$tag).users)                          = $users
      | (.inbounds[] | select(.tag==$tag).tls.reality.short_id)         = $sids' \
     "$cfg" > "$tmp" \
    || fatal "jq update failed (will NOT rewrite config)."

  mv "$tmp" "$cfg"
}

# Non-destructive: when rotating PBK, write only the private_key field
update_reality_privkey_only() {
  local tag="${REALITY_TAG:-vless-reality-in}"
  local cfg="/etc/sing-box/config.json"
  [[ -r "$cfg" ]] || fatal "Missing $cfg. Run initial install first."

  local tmp pk
  pk="$(awk '/PrivateKey:/ {print $2}' /etc/sing-box/reality.key)"
  [[ -n "$pk" ]] || fatal "No private key in /etc/sing-box/reality.key"

  tmp="$(mktemp)"
  jq --arg tag "$tag" --arg pk "$pk" \
     '(.inbounds[] | select(.tag==$tag).tls.reality.private_key) = $pk' \
     "$cfg" > "$tmp" \
    || fatal "jq key update failed."
  mv "$tmp" "$cfg"
}

safe_reload_singbox() {
  timeout 12s systemctl reload-or-restart sing-box 2>/dev/null \
    || timeout 12s systemctl restart sing-box 2>/dev/null \
    || true
}
if [[ "${ROTATE_KEYS:-0}" == "1" ]]; then
  rotate_reality_keypair
  update_reality_privkey_only
  safe_reload_singbox
fi
# Admin fast path (no wizard, no ROLE needed)
if [[ "${LIST_LINKS:-0}" == "1" || -n "${FRESH_URL_MODE:-}" || "${ADD_LINK:-0}" == "1" || \
      "${ROTATE_KEYS:-0}" == "1" || -n "${REVOKE_UUID:-}" || -n "${REVOKE_SID:-}" ]]; then
  require_root
  ensure_link_store

  [[ -n "$REVOKE_UUID" ]] && revoke_uuid "$REVOKE_UUID"
  [[ -n "$REVOKE_SID"  ]] && revoke_sid  "$REVOKE_SID"
  [[ "${ROTATE_KEYS:-0}" == "1" ]] && rotate_reality_keypair

  if [[ -n "$FRESH_URL_MODE" ]]; then
    read -r NEWU NEWSID < <(fresh_link "$FRESH_URL_MODE" "$NEW_SID")
    msg "Fresh link ready (mode=${FRESH_URL_MODE})."
  elif [[ "${ADD_LINK:-0}" == "1" ]]; then
    read -r NEWU NEWSID < <(new_link_pair "$NEW_SID")
    msg "Added new link."
  fi

  # If an edge config already exists, apply changes without touching the wizard
  if [[ -f /etc/sing-box/config.json ]]; then
    normalize_store_files || true
    update_users_sids_only
  else
    fatal "No /etc/sing-box/config.json found. Run initial install first; no destructive rewrites here."
  fi

  safe_reload_singbox
  # Re-read live params only for printing, not for rewriting
  read_reality_params_from_config || true
  # If we just created a link, print that exact one (no DNS/SNI changes)
  if [[ -n "${NEWU:-}" && -n "${NEWSID:-}" ]]; then
    PUB_KEY="${PUB_KEY:-$(awk '/PublicKey:/ {print $2}' /etc/sing-box/reality.key)}"
    HOST="$(curl -fsS --max-time 2 https://checkip.amazonaws.com || hostname -I | awk '{print $1}')" || true
    HOST="${HOST//$'\n'/}"; [[ -z "${HOST:-}" ]] && HOST="${SNI}"

    VLESS_URL="vless://${NEWU}@${HOST}:${REALITY_PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB_KEY}&sid=${NEWSID}&fp=${UTLS_FP}&type=tcp"
    [[ -n "${REALITY_FLOW:-}" ]] && VLESS_URL+="&flow=${REALITY_FLOW}"
    VLESS_URL+="#dualhop-edge"

    echo
    echo "Client URL: $VLESS_URL"
    echo
  fi

  # Print or quit
  [[ "${LIST_LINKS:-0}" == "1" ]] && { list_links_and_exit; } || exit 0
fi
if [[ "${ACTION_PURGE_SINGBOX:-0}" == "1" || "${ACTION_PURGE_SINGBOX,,}" == "true" || "${ACTION_PURGE_SINGBOX,,}" == "yes" ]]; then
  purge_singbox
  exit 0
fi
# === Main ===
#_show_branding
require_root
# Revocation fast path (no wizard, no ROLE needed)
# Revocation fast path (no wizard, no ROLE needed)
if [[ "${REVOKE_ALL:-0}" == "1" ]]; then
  require_root

  # 1) Wipe stores and mint exactly ONE new link
  install -d -m 0750 /etc/sing-box
  : > /etc/sing-box/uuids
  : > /etc/sing-box/short_ids
  NEW_UUID="$(gen_uuid4)"; NEW_SID="$(gen_sid "${SID_LEN:-8}")"
  printf '%s\n' "$NEW_UUID" >> /etc/sing-box/uuids
  printf '%s\n' "$NEW_SID"  >> /etc/sing-box/short_ids
  normalize_store_files || true

  # 2) Non-destructive config update (arrays only)
  update_users_sids_only
  safe_reload_singbox

  # 3) Print info (read-only)
  read_reality_params_from_config || true
  msg "Revocation complete. SNI/handshake/DNS preserved."

  # Optional: print the exact fresh link
  PUB_KEY="${PUB_KEY:-$(awk '/PublicKey:/ {print $2}' /etc/sing-box/reality.key)}"
  HOST="$(curl -fsS --max-time 2 https://checkip.amazonaws.com || hostname -I | awk '{print $1}')" || true
  HOST="${HOST//$'\n'/}"; [[ -z "${HOST:-}" ]] && HOST="${SNI}"
  VLESS_URL="vless://${NEW_UUID}@${HOST}:${REALITY_PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB_KEY}&sid=${NEW_SID}&fp=${UTLS_FP}&type=tcp"
  [[ -n "${REALITY_FLOW:-}" ]] && VLESS_URL+="&flow=${REALITY_FLOW}"
  echo -e "\nClient URL: $VLESS_URL\n"
  exit 0
fi

if [[ "${REVOKE_ALL:-0}" == "1" ]]; then
  require_root
  # Optional confirmation unless forced
  if [[ "${FORCE:-0}" != "1" ]]; then
    # quick, tty-safe prompt (20s timeout)
    if [ -t 0 ] || [ -t 1 ]; then
      u=0 s=0
      [[ -f /etc/sing-box/uuids     ]] && u=$(wc -l < /etc/sing-box/uuids || echo 0)
      [[ -f /etc/sing-box/short_ids ]] && s=$(wc -l < /etc/sing-box/short_ids || echo 0)
      printf "\nThis will DELETE ALL links (UUIDs=%s, SIDs=%s) and mint ONE new link. Continue? [y/N]: " "$u" "$s" > /dev/tty
      read -r -t 20 ans < /dev/tty || { echo; warn "Timed out."; exit 124; }
      [[ "$ans" =~ ^([Yy]|[Yy][Ee][Ss])$ ]] || { warn "Cancelled."; exit 2; }
    else
      fatal "Non-interactive session. Use --yes with --revoke-all."
    fi
  fi

  # 1) Nuke stores in-place
  install -d -m 0750 /etc/sing-box
  : > /etc/sing-box/uuids
  : > /etc/sing-box/short_ids

  # 2) Mint exactly one new link (UUID + ShortID)
  NEW_UUID="$(gen_uuid4)"
  NEW_SID="$(gen_sid "${SID_LEN:-8}")"
  printf '%s\n' "$NEW_UUID" >> /etc/sing-box/uuids
  printf '%s\n' "$NEW_SID"  >> /etc/sing-box/short_ids
  normalize_store_files

  # 3) Re-render config and reload service
  singbox_write_config || fatal "Failed to write sing-box config"
  if command -v systemctl >/dev/null 2>&1; then
    timeout 12s systemctl reload-or-restart sing-box 2>/dev/null \
      || timeout 12s systemctl restart sing-box 2>/dev/null \
      || warn "sing-box reload/restart timed out; continuing"
  fi
  msg "Revocation complete. Minted a fresh primary link."
  exit 0
fi
prompt_missing_inputs
run_advanced_gate
HS_EFF="${HANDSHAKE_HOST:-$SNI}"
pick_free_wg_if
derive_wg_table
install_pkgs
enable_sysctl
if [[ "$ROLE" == "2nd" ]]; then
  msg "=== Configuring as 2nd hop (egress) ==="
  wg_setup_h2
  msg "Hop-2 ready. Copy /root/wg-link-bundle.tar.gz to hop-1."
  exit 0
fi
# ROLE == 1st
msg "=== Configuring as 1st hop (edge) ==="
wg_setup_h1
install_singbox
check_domain_tls
singbox_write_config
save_iptables
msg "Edge ready. Traffic accepted on TCP ${REALITY_PORT} and egressed via ${WG_IF}."