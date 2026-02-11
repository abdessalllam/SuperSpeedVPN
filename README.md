# Dual-Hop: VLESS REALITY ↔ WireGuard

This script sets up a **Split-Hop VPN**. You enter the network through a VLESS+REALITY node (TCP/gRPC/H2), which tunnels your traffic over a local WireGuard interface to a second server, where it exits to the internet.

**Why do this?**
1.  **Speed:** It is significantly faster than OpenVPN and standard WireGuard-over-UDP dual-hop setups.
2.  **IP Decoupling:** Your clients connect to Server A (Edge). The internet sees traffic coming from Server B (Exit). If Server B gets blacklisted, you swap it out without changing the keys or URLs on your clients.
3.  **Stealth:** The entry point looks like a normal TLS website (REALITY). The internal link is WireGuard.

---

## The Topology

```
[ Client ] ---> [ Hop-1 (Edge) ] ==============> [ Hop-2 (Exit) ] ---> [ Internet ]
              (VLESS + REALITY)    (WireGuard)       (NAT)
```

- **Hop-1 (Edge):** Accepts VLESS connections. "Steals" the handshake of a real website (like Mozilla or Cloudflare). Routes traffic into a WireGuard tunnel.
- **Hop-2 (Exit):** Standard WireGuard server. NATs the traffic out.

---

## Installation

You need two Ubuntu servers (22.04 or 24.04 recommended).
**Run this as root.**

### Step 1: Set up the Exit Node (Hop-2) first
Login to the server you want your traffic to appear from.

```bash
bash installer.sh --role 2nd
```

When it finishes, it will print a **JSON configuration** (and a text version) to the console. **Copy this.** You will need it for the next step.

> *Note: If you have a specific port in mind, use `--wg-port 51820`.*

### Step 2: Set up the Edge Node (Hop-1)
Login to the server your clients will actually connect to. Paste the config you got from Step 1 into a new file (e.g., `wg.json`).

**The Easy Way (using the import file):**
1. Paste the JSON from Hop-2 into a file named defaul file name `wg-config.json` or anything you like such as `wg.json`.
2. Run the installer:
If the name is not the default `wg-config.json`, then you need to attach `--wg-import wg.json`.
```bash
bash installer.sh --role 1st --wg-import wg.json
```

**The Interactive Way:**
Just run `bash installer.sh` and select **Role 1st**. It will ask you for the keys and IPs generated in Step 1.

The script will:
1.  Install Sing-box and WireGuard.
2.  **Probe** your chosen SNI (decoy domain) to make sure it actually supports TLS 1.3 and H2 so you don't look suspicious.
3.  Generate your `vless://` link.

---

## Transport Modes
The script supports modern Xray/Sing-box transport protocols. You can select these during the wizard or force them via flags:

*   **Vision (TCP):** Fastest. Low overhead. Use this if your network doesn't mangle TCP. (`--mode vision`)
*   **HTTPUpgrade:** The new standard. Replaces standard WS/H2. fast and reliable (`--mode httpupgrade`)
*   **gRPC:** Good for cloudflare-heavy networks or if you need multiplexing. (`--mode grpc`)
*   **H2:** Legacy HTTP/2. Good stealth, slightly higher overhead. (`--mode h2`)

---

## Admin Commands (Day-to-Day)

Don't re-run the whole wizard just to add a user. Use the admin fast-path.

**List all client links:**
```bash
./installer.sh --list-links
```

**Add a new user (UUID):**
```bash
./installer.sh --new-user
```
*Adds a user to the existing config without restarting the WireGuard interface.*

**Revoke a user:**
```bash
./installer.sh --revoke-uuid <uuid_here>
```

**Rotate the REALITY keys:**
*Paranoid? Rotate the private/public keys. Note: This breaks all existing client links.*
```bash
./installer.sh --rotate
```

**Change the SNI / Decoy:**
If your decoy domain gets blocked or stops working, just re-run the installer with the new settings. The script is idempotent—it will update the config without nuking your user list.
```bash
./installer.sh --role 1st --sni www.new-decoy.com ...
```

---

## Advanced Usage

### DNS Lockdown
You can force the Edge node to route *all* DNS queries through the tunnel, or block local DNS entirely to prevent leaks.
*   `--dns-lockdown mark53`: Routes local DNS queries into the WireGuard tunnel.
*   `--dns-lockdown drop53`: **Hardcore.** Drops any DNS packet not destined for the tunnel.

### Custom DNS
Want to use NextDNS?
```bash
./installer.sh --dns nextdns --dns-nextdns-id YOUR_ID
```

### Checking your Decoy (SNI)
Before setting up, you can check if a domain is valid for REALITY (supports TLS 1.3, X25519, etc):
```bash
./installer.sh --probe --sni www.microsoft.com
```

### Manual Config Import
If you are upgrading the WireGuard link on Hop-1 without touching Sing-box (the VLESS part), use:
```bash
./installer.sh --update-wg --wg-import new-config.json
```

---

## Files

*   **Config:** `/etc/sing-box/config.json`
*   **Users:** `/etc/sing-box/uuids`
*   **Short IDs:** `/etc/sing-box/short_ids`
*   **WireGuard:** `/etc/wireguard/wg0.conf`
*   **Logs:** `/var/log/dualhop-vlessreality-wg.log`

## Troubleshooting

1.  **Clients can't connect:** Run `./installer.sh --list-links` and make sure the SNI and Public Key in the link match your server.
2.  **It connects but no internet:** Check the handshake on Hop-1 (`wg show`). If there is no handshake, Hop-1 cannot reach Hop-2. Check your firewall rules on Hop-2.
3.  **"Decoy check failed":** The domain you chose (SNI) doesn't support TLS 1.3 or is geographically blocked. Pick a different one (e.g., `www.samsung.com`, `www.googletagmanager.com`).
4.  **I messed up:** Run `./installer.sh --purge-singbox` to wipe the Sing-box part, or `./installer.sh --uninstall` to wipe everything.

---

*Made with ☕ and bash.*
