# Dual‑Hop: VLESS REALITY ↔ WireGuard

**Two-hop layout** for resilient egress:
- **Hop‑1 (edge/entry):** VLESS + REALITY server over TCP, binds outbound traffic to a WireGuard interface over UDP.
- **Hop‑2 (egress/exit):** WireGuard server + NAT to the Internet.

Tested on **Ubuntu 22.04 / 24.04**. Script is idempotent, IPv4/IPv6 aware, and includes strict error handling. 

The script is tuned for Security and Speed and Stealth while keeping it easy to use.

---

## Topology (overview)

```
Client ──(VLESS/REALITY over TCP)──> Hop‑1 (edge)
                                \                         \
                                 \__ binds to wg0 ________\__ WireGuard
                                                           \
                                                            ──> Hop‑2 (egress) ── NAT ──> Internet
```

---
2-3 X faster than a Single-Hop OpenVPN and 2X faster than WireGuard-WireGuard Dual-Hop per my own testing on the same servers and on the same devices.
# Why use this?

* **Stealthy entry, clean exit.** REALITY makes the TLS handshake look like a legit site (decoy SNI), so it blends in against DPI and crude SNI blocks. Traffic then **binds to WireGuard** and exits from a separate box, keeping your client-facing IP and your egress IP **decoupled**.
* **Speed.** 2X faster than Using Wireguard-Wireguard over UDP Dual-hop. 
* **Resilient under pressure.** Split-hop design means you can rotate the egress host without touching the public entry point—or swap the entry point without rebuilding your WG server. Fewer moving parts exposed to any single failure or takedown.
* **Multi-user, multi-SID by design.** Add users or rotate short_ids on the fly; old and new links can coexist for zero-downtime credential changes.
* **DNS that doesn’t leak.** DoH with explicit SNI/IP pins and optional host-level DNS lockdown, so your box isn’t betraying you with plain :53.
* **Sane defaults, hard edges.** Idempotent setup, strict file perms, systemd hardening, clear failure modes, and an **admin fast-path** that skips the wizard for day-to-day ops (`--new-user`, `--revoke-*`, `--list-users`, `--rotate`).
* **IPv4/IPv6 aware.** Dual-stack where it helps, v4-only when the network is hostile to v6.
* **Built-In** tools for checking if the decoy domain (SNI) will work with the setup or not and allows you to change the domain if the previous one is not compatible. 

# Who is this for?

* **People working around hostile networks.** Individuals and teams in censored or filtered environments who need stable, low-profile access without advertising that they’re tunneling.
* **Small orgs and power users.** Anyone who wants a **controlled egress** point (cloud, colo, or home) while keeping the public-facing entry separate for safety and flexibility.
* **Ops/SRE/Red-team folks.** You want simple, auditable plumbing with quick key/SID rotation and minimal “mystery config.”
* **Developers with region constraints.** Route your app’s outbound through a specific region without exposing your REALITY entry node to abuse.

If the above matches your threat model and tolerance for DIY, this setup gives you stealth, control, and clean separation without baroque complexity.

---

## Quick start

> You must run as **root**, All commands are can be listed using --help

### 1) On Hop‑2 (egress)

```bash
# Install & configure WG server with NAT on the egress host
bash installer.sh --role 2nd --wg-port 51820
```

This generates and enables `/etc/wireguard/wg0.conf` and writes a bundle for Hop‑1 at:
```
/root/wg-link-bundle.tar.gz
```

Copy the bundle to Hop‑1:
```bash
scp /root/wg-link-bundle.tar.gz root@<hop-1>:/root/
```

### 2) On Hop‑1 (edge)

```bash
# Install & configure WG client, REALITY inbound, DNS, and sing-box service
bash installer.sh --role 1st --reality-port 443 \
  --sni addons.mozilla.org \
  --handshake www.cloudflare.com \
  --wg-port 51820
```

The script will validate your REALITY decoy (SNI/handshake) and then start **sing-box** with a
single canonical config at `/etc/sing-box/config.json`.

A shareable client URL is printed at the end.

---

## Admin fast‑path (no wizard)

These management operations **run before** any interactive wizard and exit cleanly.
They also **rebuild** `/etc/sing-box/config.json` if it already exists (Hop‑1).

- **List users** (newest SID per UUID):
  ```bash
  ./installer.sh --list-users
  ```
- **List ALL URLs (every SID × every UUID)**:
  ```bash
  ./installer.sh --list-users=all
  ```
- **Append a new user** (UUID); optionally mint a **new SID** too:
  ```bash
  ./installer.sh --new-user
  ./installer.sh --new-user --new-sid
  ```
- **Fresh link** (single command that sets who can connect):
  - Replace everyone with a brand-new UUID; optionally mint a new SID:
    ```bash
    ./installer.sh --new              # defaults to replace
    ./installer.sh --new=replace --new-sid
    ```
  - Add an extra UUID (keeps existing ones); optionally mint a new SID too:
    ```bash
    ./installer.sh --new=add
    ./installer.sh --new=add --new-sid
    ```
- **Revoke** a specific UUID or SID:
  ```bash
  ./installer.sh --revoke-uuid <uuid>
  ./installer.sh --revoke-sid  <sid8hex>
  ```
- **Rotate REALITY keypair** (changes `pbk`; all clients must update):
  ```bash
  ./installer.sh --rotate
  ```

> Notes
> - **Multiple users** are supported: the VLESS inbound `"users": [...]` contains every UUID in the store.
> - **Multiple SIDs** are supported concurrently: `"reality.short_id": [...]` contains all 8‑hex SIDs in the store.
> - `--new-sid` **adds** a new SID when used with `--new-user` or `--new[=add|replace]`.

---

## Interactive flows (when not using `--silent=1`)

- **Flow 1 – Key settings** (optional): “Review/edit key settings (ports, SNI, DNS)?”  
  Lets you adjust the common knobs you’ll most likely want to touch.
- **Flow 2 – Advanced settings** (optional): “Review advanced settings?”  
  Only advanced‑only parameters show here; **no duplication** with Flow 1.

To force advanced prompts:
```bash
./installer.sh --advanced
# aliases: --wizard, --tune
```

To run non‑interactive:
```bash
./installer.sh --silent=1 --role 1st --reality-port 443 --sni <host> --handshake <host-or-ip> --wg-port 51820
```

---

## Flags (selected)

Networking basics:
- `--role 1st|2nd` — Node role (edge or egress).
- `--wg-port <udp>` — WireGuard port (default: 51820).
- `--wg-if <name>` — WireGuard interface (default: wg0).

REALITY (Hop‑1):
- `--reality-port <tcp>` — TCP port to listen on (default: 443).
- `--sni <host>` — SNI presented in ClientHello (must be on certificate SAN).
- `--handshake <host-or-ip>` — Decoy endpoint host or IP.
- `--handshake-port <tcp>` — Decoy TLS port (default: 443).
- `--utls-fp chrome|firefox|safari|edge|ios|android|randomized` — FP hint used in share URLs.
- `--reality-flow xtls-rprx-vision` — Optional flow in share URL.

SNI Compatibility:
- `--probe --sni example.com` Check if decoy SNI is compatibile
- `--probe --sni example.com --handshake www.example.com` Check if decoy SNI and Handshake is compatibile.

Forcing a mismatched domain or one that doesn't support 1.3 TLS will result in "TLS handshake: REALITY: processed invalid connection".

DNS:
- `--dns cloudflare|google|quad9|adguard|opendns|nextdns|custom`
- `--dns-use-v6 auto|1|0` — Permit DoH over IPv6; defaults to `auto` (follows IPv6 mode).
- `--dns-nextdns-id <id>` — Required for NextDNS.
- `--dns-custom-url`, `--dns-custom-sni`, `--dns-custom-ip4`, `--dns-custom-ip6` — For custom DoH.
- `--dns-lockdown off|mark53|drop53` — Host DNS egress policy (edge).  
  - `off`: no policy.  
  - `mark53`: mark local :53 to route via WG policy table.  
  - `drop53`: **very strict**; breaks host DNS unless you’ve re‑homed upstreams (requires `DNS_LOCKDOWN_FORCE=1`).

Admin fast‑path:
- `--list-users` or `--list-users=all`
- `--new` (`replace|add`) & `--new-user`
- `--new-sid` (only meaningful with `--new`/`--new-user`)
- `--revoke-uuid`, `--revoke-sid`
- `--rotate`

Purge Singbox
- `--purge-singbox` If you got a messy Install, Purge Singbox and Rerun the script.

Other:
- `--ipv6-mode dual|v4only|v6only`
- `--silent` — Non‑interactive mode.

---

## Files & locations

- **Log:** `/var/log/dualhop-vlessreality-wg.log`
- **WireGuard:**
  - Hop‑2 server: `/etc/wireguard/wg0.conf` (by default)
  - Hop‑1 client: `/etc/wireguard/wg0.conf` (binds app traffic via policy table 51820)
  - Keys are stored under `/etc/wireguard/keys-*`
  - Link bundle for Hop‑1: `/root/wg-link-bundle.tar.gz`
- **sing-box (Hop‑1):**
  - Config: `/etc/sing-box/config.json`
  - REALITY keypair: `/etc/sing-box/reality.key` (rotated by `--rotate`)
  - User/SID store (multi‑user):  
    - `/etc/sing-box/uuids` (one UUID per line)  
    - `/etc/sing-box/short_ids` (one 8‑hex SID per line)  
    - Legacy singletons (kept in sync when replacing): `/etc/sing-box/uuid`, `/etc/sing-box/short_id`
  - Systemd hardening overrides: `/etc/systemd/system/sing-box.service.d/{override.conf,hardening.conf}`

Permissions are tightened (`chmod 600`) on sensitive files.

---

## Shareable client URL

Printed at the end of Hop‑1 setup. Format (example):

```
vless://<UUID>@<HOST>:<PORT>?encryption=none&security=reality&sni=<SNI>&pbk=<PUBLIC_KEY>&sid=<SID>&fp=<FP>&type=tcp[#dualhop-edge]
```

- **Rotate pbk?** Clients must update their URL (`--rotate` changes pbk).
- **Add SID?** Adding SIDs does **not** invalidate old ones. Replacing SIDs does.

---

## Troubleshooting

- **Port in use** on Hop‑1: the script will offer to kill/re‑port under TTY; otherwise it fails with context and suggests `--reality-port`.
- **Decoy test fails** (SAN/TLS1.3/X25519/connectivity): you’ll be prompted to adjust `--sni/--handshake/--handshake-port` or exit.
- **sing-box won’t start**: the script prints `journalctl` for `sing-box`. Validate config with:
  ```bash
  sing-box check -c /etc/sing-box/config.json
  ```
- **DNS lockdown `drop53`** breaks host DNS: set `DNS_LOCKDOWN_FORCE=1` only when you’ve rehomed upstreams to wg0.

---

## Security notes

- REALITY private key and user store files are permissioned (`chmod 600`).
- WireGuard private keys are permissioned (`chmod 600`).
- Systemd limits privileges for `sing-box` via drop‑in units.
- Logs may include operational messages but not raw private keys.

---

## Uninstall (manual)

```bash
# Stop services
systemctl disable --now sing-box || true
systemctl disable --now wg-quick@wg0 || true

# Remove configs (optional — backup first)
rm -rf /etc/sing-box /etc/wireguard

# Remove iptables persists
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6
systemctl disable --now netfilter-persistent || true
```

---

