# Secure Encrypted DNS & Ad-Blocking Server on VPS

A complete guide and codebase to build a private, high-performance, secure DNS server featuring **DNS-over-HTTPS (DoH)**, **DNS-over-TLS (DoT)**, **WireGuard VPN**, and **AdGuard Home** ad-blocking. It also includes a custom real-time query visualizer web portal with live animated particle flows.

---

## Architecture & Flow Overview

```
                   ┌──────────────────────────────────────────┐
                   │               Client Device              │
                   └─────────────────────┬────────────────────┘
                                         │
                 DoH (HTTPS / Port 443)  │  DoT (TLS / Port 853)
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
     ┌───────────────────────┐                       ┌───────────────────────┐
     │ Nginx Reverse Proxy   │                       │  AdGuard Home DoT     │
     │   (Port 443 / SSL)    │                       │     (Port 853)        │
     └───────────┬───────────┘                       └───────────┬───────────┘
                 │ Proxy Pass to                                 │
                 │ AdGuard DoH (Port 8444)                       │
                 ▼                                               │
     ┌───────────────────────────────────────────────────────────▼───────────┐
     │                     AdGuard Home DNS Core                             │
     │    (Filters queries, blocks ads/malware, cache hits resolution)       │
     └───────────┬───────────────────────────────────────────────┬───────────┘
                 │                                               │
                 │ Query Details (UDP/TCP)                       │ Resolves Clean Domain
                 ▼                                               ▼
     ┌────────────────────────┐                      ┌───────────────────────┐
     │  Python Stats API      │                      │  Upstream DNS Core    │
     │      (Port 8085)       │                      │  (Cloudflare/Google)  │
     └───────────┬────────────┘                      └───────────────────────┘
                 │ Serves stats over /api/stats
                 ▼
     ┌────────────────────────┐
     │ RealTime Web Dashboard │
     │  (Canvas flow system)  │
     └────────────────────────┘
```

---

## 🛠️ Step 1: Free Domain Setup via DuckDNS.org

To support secure encryption (DoH/DoT), you need a domain name to bind your SSL certificates. DuckDNS provides free domains with dynamic IP update support.

1. Go to [DuckDNS.org](https://www.duckdns.org/) and log in.
2. Create a subdomain (e.g., `yourdomain`).
3. Add your VPS public IPv4 address (`A` record).
4. If your VPS has IPv6 enabled, add your public IPv6 address (`AAAA` record).
5. **Auto-Update Script:** To ensure your DuckDNS domain always points to your VPS IP, set up an automatic update script on your VPS:
   * Create a script at `/etc/duckdns/duck.sh`:
     ```bash
     #!/bin/bash
     echo url="https://www.duckdns.org/update?domains=YOUR_SUBDOMAIN&token=YOUR_DUCKDNS_TOKEN&ip=" | curl -k -o /var/log/duckdns.log -K -
     ```
   * Set executable permissions:
     ```bash
     sudo chmod 700 /etc/duckdns/duck.sh
     ```
   * Add a cron job to run it every 5 minutes:
     ```bash
     crontab -e
     # Add the following line:
     */5 * * * * /etc/duckdns/duck.sh >/dev/null 2>&1
     ```

---

## 🔒 Step 2: VPS Firewall & Network Hardening

To prevent your DNS server from being abused in Open Resolver DDoS amplification attacks, public access to standard **Port 53 (UDP/TCP)** must be blocked, while keeping **Port 443 (DoH)** and **Port 853 (DoT)** open.

### 1. Cloud Infrastructure Ingress Rules (e.g., Oracle Cloud OCI)
Add the following Ingress rules in your VPS Virtual Cloud Network (VCN) Security Lists:
* **TCP Port 22 / 2222** (SSH Management)
* **TCP Port 80** (HTTP - required for Let's Encrypt verification)
* **TCP Port 443** (HTTPS - DNS-over-HTTPS)
* **TCP & UDP Port 853** (DNS-over-TLS / DNS-over-QUIC)
* **UDP Port 51820** (WireGuard VPN)

### 2. Host Firewall (UFW / iptables) configuration
Run the following commands on your Ubuntu VPS to secure Port 53 and allow encrypted protocols:
```bash
# Allow standard SSH and WireGuard VPN
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 51820/udp

# Allow HTTP and HTTPS (DoH)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow DNS-over-TLS (DoT)
sudo ufw allow 853/tcp
sudo ufw allow 853/udp

# Block public DNS Port 53 (but allow it on local interfaces and VPN)
sudo ufw route reject proto udp to any port 53
sudo ufw route reject proto tcp to any port 53
sudo ufw allow in on lo to any port 53
sudo ufw allow in on wg0 to any port 53

# Enable Firewall
sudo ufw enable
```

---

## 🛡️ Step 3: Install & Configure WireGuard

WireGuard lets you connect to the server securely for management purposes (like viewing the AdGuard Home Admin UI).

1. Install WireGuard:
   ```bash
   sudo apt update && sudo apt install -y wireguard
   ```
2. Generate private and public keys:
   ```bash
   wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
   ```
3. Create `/etc/wireguard/wg0.conf`:
   ```ini
   [Interface]
   PrivateKey = SERVER_PRIVATE_KEY
   Address = 10.66.66.1/24
   ListenPort = 51820
   
   # IP Forwarding rules
   PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o enp0s6 -j MASQUERADE
   PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o enp0s6 -j MASQUERADE
   ```
4. Enable IP forwarding in `/etc/sysctl.conf`:
   ```bash
   sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
   sudo sysctl -p
   ```
5. Start and enable WireGuard:
   ```bash
   sudo systemctl enable --now wg-quick@wg0
   ```

---

## 🐳 Step 4: Install AdGuard Home

AdGuard Home acts as the filtering DNS core engine.

1. Install AdGuard Home via the official automated script:
   ```bash
   curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh
   ```
2. Open the AdGuard setup wizard by visiting `http://10.66.66.1:3000` via your WireGuard connection.
3. Configure the settings:
   * **Admin Web Interface:** Bind to `10.66.66.1` on port `80`.
   * **DNS Server:** Bind to `127.0.0.1`, `10.66.66.1`, and your public IPv4/IPv6 addresses on port `53`.
4. In the AdGuard Dashboard, go to **Settings ➔ Encryption Settings**:
   * Enable encryption.
   * Server Name: `yourdomain.duckdns.org`
   * Bind the **DNS-over-TLS** server to port `853`.
   * Bind the **DNS-over-HTTPS** server to port `8444` (we will use Nginx on port `443` as the public-facing DoH proxy).
   * Provide the paths to your SSL certificates (configured in Step 5).

---

## 🔑 Step 5: Acquire a Wildcard SSL Certificate (Certbot)

A wildcard SSL certificate allows you to use client identifiers (e.g., `musab.yourdomain.duckdns.org`) dynamically. These are authenticated under the same certificate and parsed into separate client logs inside AdGuard Home!

### 1. Manual Setup with DuckDNS DNS-01 Verification
Since DuckDNS does not have an official certbot plugin out-of-the-box, we perform DNS-01 validation using manual scripts.

* Create the authenticator script `/etc/letsencrypt/duckdns.sh`:
  ```bash
  #!/bin/bash
  TOKEN="YOUR_DUCKDNS_TOKEN"
  DOMAIN="YOUR_SUBDOMAIN"
  curl -s "https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&txt=$CERTBOT_VALIDATION"
  sleep 30
  ```
* Create the cleanup script `/etc/letsencrypt/duckdns-clean.sh`:
  ```bash
  #!/bin/bash
  TOKEN="YOUR_DUCKDNS_TOKEN"
  DOMAIN="YOUR_SUBDOMAIN"
  curl -s "https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&clear=true"
  ```
* Make both executable:
  ```bash
  sudo chmod +x /etc/letsencrypt/duckdns.sh /etc/letsencrypt/duckdns-clean.sh
  ```
* Run Certbot to issue the wildcard certificate:
  ```bash
  sudo certbot certonly --manual --preferred-challenges=dns \
    --manual-auth-hook /etc/letsencrypt/duckdns.sh \
    --manual-cleanup-hook /etc/letsencrypt/duckdns-clean.sh \
    -d "yourdomain.duckdns.org" -d "*.yourdomain.duckdns.org"
  ```

---

## 🚀 Step 6: Nginx Reverse Proxy Configuration

Nginx hosts our visualizer web files and proxies public incoming `/dns-query` (DoH) requests on port `443` to AdGuard Home's internal HTTP server running on port `8444`.

1. Install Nginx:
   ```bash
   sudo apt install -y nginx
   ```
2. Copy the configuration provided in `nginx-default.conf` into `/etc/nginx/sites-available/default`.
3. Check config and reload Nginx:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

---

## 📊 Step 7: Web Portal & Python Stats API Deployment

The visualizer frontend relies on a lightweight Python daemon that polls AdGuard Home statistics locally and presents them via a secure API.

1. **Deploy Frontend Web Portal:**
   * Move all the `.html` files (`index.html`, `RealTime.html`, `faq.html`, etc.) and `.png` assets in this repository to `/var/www/html/`.
   * Set permissions:
     ```bash
     sudo chown -R www-data:www-data /var/www/html/
     sudo chmod -R 644 /var/www/html/*
     ```
2. **Deploy Backend Python API:**
   * Copy the `stats_api.py` script to `/usr/local/bin/dnsmalik_stats_api.py`.
   * Copy the `dnsmalik-stats.service` systemd config file to `/etc/systemd/system/dnsmalik-stats.service`.
   * Start and enable the backend daemon:
     ```bash
     sudo systemctl daemon-reload
     sudo systemctl enable --now dnsmalik-stats.service
     ```

---

## 📱 Step 8: Client Devices Setup Guide

Once the server is running, configure your client devices to use secure, encrypted DNS.

### 1. Android (DoT - Port 853)
Android natively supports **DNS-over-TLS (DoT)** via the "Private DNS" setting. You can enter **any custom prefix** to identify your device in the logs.
1. Open your Android device **Settings** ➔ **Network & Internet** ➔ **Private DNS**.
2. Select **Private DNS provider hostname**.
3. Enter your custom hostname. Examples:
   * `phone.yourdomain.duckdns.org`
   * `tablet.yourdomain.duckdns.org`
4. Tap **Save**.

### 2. Windows 11 (DoH - Port 443)
Windows 11 supports native **DNS-over-HTTPS (DoH)** templates.
1. Open **Settings** ➔ **Network & internet** ➔ Select **Wi-Fi** or **Ethernet** ➔ click **Edit** next to **DNS server assignment** (set to **Manual**, toggle **IPv4** to **On**).
2. **Preferred DNS:** Type your DNS server's raw IPv4 address (do not enter the HTTPS url here).
3. **DNS over HTTPS:** Change the dropdown menu from *Off* to **On (manual template)**.
4. **DNS over HTTPS template:** Paste your secure DoH URL:
   `https://windows.yourdomain.duckdns.org/dns-query`
5. **Fall-back to plaintext:** Set this to **Off**.
6. Click **Save**.

### 3. macOS / iOS (DoH/DoT Profile)
Apple devices require a Configuration Profile (`.mobileconfig`) to be installed for encrypted DNS.
* Create a file named `dns.mobileconfig` with the following contents:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.EN.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://mac.yourdomain.duckdns.org/dns-query</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures macOS/iOS to use Secure DNS-over-HTTPS</string>
            <key>PayloadDisplayName</key>
            <string>Secure DoH</string>
            <key>PayloadIdentifier</key>
            <string>org.secure.doh</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>8A6B3D6E-C1B0-4A3C-9F4D-9B8A7C6D5E4F</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Secure DNS</string>
    <key>PayloadIdentifier</key>
    <string>org.secure</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>9F8E7D6C-5B4A-3C2B-1A09-8F7E6D5C4B3A</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```
* Share the file with macOS (double-click to install in System Settings ➔ Profiles) or iOS (install via Settings ➔ Profile Downloaded).
