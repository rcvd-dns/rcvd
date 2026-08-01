# Testing RCVD with Cloudflare Quick Tunnels

(no login required)

This guide is for developers and curious users who want to try RCVD's DoH endpoint with the absolute minimum setup. No public IP. No port forwarding. No DNS records. No certificates to manage.

**Goal:** Get a working DoH endpoint you can query from Firefox, Chrome or curl in about 10 minutes.

---

## Read This First: Important Limitations

Before proceeding, understand what Quick Tunnels are and are not:

1. **URL is ephemeral.** Every time you restart the tunnel, you get a new random URL like `modern-stack-42d9.trycloudflare.com`. This means you cannot configure it as a permanent DoH server in Firefox or your OS DNS settings — it will break on next restart. (the tunnel/machine/container)

2. **Cloudflare sees your DNS queries.** All traffic passes through Cloudflare's edge network. You might as well be using 1.1.1.1 DoH if you plan to use this long-term. This deployment guide is for rcvd testing, with quick tunnels when the tester wants to get more familiar with `rcvd` before doing a more involved deployment.

> DO NOT use this setup for production or anywhere you consider your DNS queries sensitive.

3. **No account needed for Quick Tunnels.** The `trycloudflare.com` subdomain is generated automatically, no Cloudflare account required. If you want a persistent URL, see the Named Tunnels note at the bottom of this guide.

4. **Cloudflare handles TLS.** RCVD listens on plain HTTP internally (port 8080). Cloudflare's edge handles HTTPS and certificates. You do NOT need `rcvd` internal certmagic options in your config file or any cert configuration for this quick-tunnel setup.

5. **No open ports required.** This is useful for testing on AWS, GCP, Azure when there is limited connectivity.This also works from behind CGNAT, ISP routers / gateways, hotel WiFi, or any network with outbound internet access. Nothing needs to be opened on your firewall or router.

---

## What You Need

- RCVD binary (built or downloaded)

- `cloudflared` CLI tool (free, no account needed for Quick Tunnels)

- Outbound internet access

## A Note on QUIC

This setup uses QUIC in two places:

- **RCVD → Quad9 upstream:** The example config in this guide uses DoQ (DNS-over-QUIC, RFC 9250) to forward queries from your RCVD server to Quad9.

- **cloudflared tunnel transport:** In this guide the tunnel is simply a mechanism for INBOUND traffic to use, e.g. pointing your Web Browser. It Uses QUIC (HTTP/3) by default for the connection between your RCVD server and Cloudflare's edge. (Falls back to HTTP/2 (TCP) automatically if QUIC is blocked on your network.)

> So the full stack - from your RCVD server out to the upstream resolver - is QUIC end-to-end.

> These are **two separate outbound QUIC connections on different ports** - they do not nest inside each other. 

> `cloudflared` tunnels plain HTTP traffic on port 8080 locally on your machine. **The DoQ connection to Quad9 goes directly outbound on port 853 and never passes through the cloudflare tunnel you created.**

```
Your machine:
  RCVD ──[DoQ/QUIC port 853]──────────────────► Quad9
  cloudflared ──[QUIC/HTTP3 port 7844]──► Cloudflare Edge ──► User
```

## DoQ and Certificates — Why This Guide Exists

There are two completely separate TLS contexts in RCVD and they serve different purposes. This is the part that confuses most people.

**When RCVD talks TO an upstream resolver (RCVD is the client):**
```
RCVD ──[DoQ]──► Quad9
```
- Quad9 presents its certificate, RCVD validates it
- You do not need any cert or key for this — you are the client
- The upstream IP in your config (`9.9.9.9`) is all that is needed

**When RCVD serves DNS TO a user (RCVD is the server):**
```
Firefox ──[DoH]──► RCVD
```
- RCVD must present a valid certificate to Firefox
- This is where cert management becomes a real problem
- With Cloudflare tunnel: Cloudflare presents the cert, RCVD serves plain HTTP internally — **no cert needed on your side**
- With certmagic: RCVD fetches its own Let's Encrypt cert automatically
- With manual: you provide your own `tls_cert` + `tls_key` files

**In plain words:** When RCVD is a client talking to Quad9, certs are automatic and invisible. When RCVD is a server talking to Firefox, you need to deal with certs somehow. The Cloudflare tunnel removes that problem entirely for testing — which is exactly why this guide exists.

## DoQ is Not a Browser Protocol

You may look at the example config in this guide and see `doq = true` and wonder — does my browser need to support DoQ?

**No. DoQ is a resolver-to-resolver protocol, not a browser-to-resolver protocol.**

DoQ (DNS-over-QUIC, RFC 9250) was designed for:
- Stub resolver → recursive resolver
- Recursive resolver → authoritative resolver
- DNS forwarders talking to each other

**No major browser supports DoQ natively. (*May 2026)** Firefox, Chrome, and Safari all use DoH (DNS-over-HTTPS) when you configure a custom DNS server in browser settings.

The `doq = true` in the example config is RCVD's **outbound** connection to Quad9 — not what your browser uses. Your browser speaks DoH to the Cloudflare tunnel URL. RCVD receives that DoH query, then forwards it to Quad9 using DoQ. Two different protocols, two different legs:

```
Firefox ──[DoH/HTTPS]──► Cloudflare ──► RCVD:8080 ──[DoQ/QUIC]──► Quad9
         (browser speaks DoH)              (RCVD speaks DoQ internally)
```

The `doq = true` line in the config is correct and intentional — it just controls the outbound upstream protocol, not what the browser sees.

---

## Step 1: Install cloudflared

**macOS:**
```bash
brew install cloudflare/cloudflare/cloudflared
```

**Linux (Debian/Ubuntu):**
```bash
curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared
```

**Linux (direct binary):**
```bash
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
```

**Verify:**
```bash
cloudflared --version
```

---

## Step 2: Create RCVD Config for Quick Tunnel

In this example, RCVD listens on plain HTTP port 8080. Cloudflare handles HTTPS externally - no TLS config needed in RCVD (with this quick-tunnel option)

Create `etc/rcvd-cloudflare-tunnel-test.toml`:

```toml
# RCVD — Cloudflare Quick Tunnel Test Config
# For testing only. Not for production use.
# - No TLS cert needed (Cloudflare handles it)
# - RCVD listens on HTTP only (port 8080)
# - DNS queries pass through Cloudflare's network

[resolver]
enabled = false

[upstream_service]
enabled = true
listen_doh = "127.0.0.1:8080"  # HTTP only, local only — Cloudflare connects here
listen_dot = ""
listen_doq = ""

# No TLS configuration — Cloudflare terminates TLS externally
tls_automation = false

[[upstreams]]
name = "Quad9-Filtering"
host = "9.9.9.9"
port = 853
doq = true
dot = false
doh = false

[cache]
enabled = true
max_size = 1024
ttl_min = 60
ttl_max = 3600

[logging]
level = "info"
format = "text"
```

---

## Step 3: Start RCVD

```bash
./rcvd -config etc/rcvd-cloudflare-tunnel-test.toml
```

You should see:
```
DoH endpoint listening on 127.0.0.1:8080
```

---

## Step 4: Start the Cloudflare Tunnel

In a second terminal:

```bash
cloudflared tunnel --url http://localhost:8080
```

cloudflared will generate a random subdomain when connecting to the Cloudflare network and print it in the terminal for you to use and share. The output will serve traffic from the server on your local machine to the public internet at a public URL.

After a few seconds you will see output like:

```
✓ Outbound-only connection established to Cloudflare edge
✓ Connection secured · TLS 1.3 · Post-quantum encryption
✓ Your URL: https://modern-stack-42d9.trycloudflare.com
```

**Copy that URL.** You will use it in the next step.

---

## Step 5: Test Your DoH Endpoint

Replace `modern-stack-42d9.trycloudflare.com` with your actual URL from Step 4.

**Test with curl (JSON response):**
```bash
curl -s -H 'accept: application/dns-json' \
  'https://modern-stack-42d9.trycloudflare.com/dns-query?name=example.com&type=A' \
  | python3 -m json.tool
```

Expected output:
```json
{
    "Status": 0,
    "TC": false,
    "RD": true,
    "RA": true,
    "AD": false,
    "CD": false,
    "Question": [{"name": "example.com.", "type": 1}],
    "Answer": [{"name": "example.com.", "type": 1, "TTL": 3600, "data": "93.184.216.34"}]
}
```

**Test with dig (if you have dns-over-https support):**
```bash
# Using the q tool (if available)
q example.com @https://modern-stack-42d9.trycloudflare.com/dns-query
```

---

## Step 6: Test in Firefox (Optional)

1. Open Firefox → Preferences → General → scroll to **Network Settings** → **Settings...**
2. Select **Enable DNS over HTTPS**
3. Choose **Custom**
4. Enter your tunnel URL: `https://modern-stack-42d9.trycloudflare.com/dns-query`
5. Click OK
6. Browse to any website — DNS is now going through RCVD via the tunnel

> **Reminder:** This URL will stop working when you restart the tunnel. You will get a new URL each time.

---

## Teardown

Stop RCVD with `Ctrl+C` in its terminal.
Stop cloudflared with `Ctrl+C` in its terminal.

No cleanup needed — Quick Tunnels leave no persistent state.

## Limitations

- CF Quick Tunnels are subject to a hard limit on the number of concurrent requests that can be proxied at any point in time. Currently, this limit is 200 in-flight requests. If a Quick Tunnel hits this limit, the HTTP response will return a 429 status code.

- CF Quick Tunnels do not support Server-Sent Events (SSE).

## Troubleshooting

**curl returns connection error:**
- Verify RCVD is running: `curl 'http://localhost:8080/dns-query?name=example.com&type=A'`
- Verify cloudflared is running and tunnel URL is active
- Check RCVD logs for errors

**DNS queries time out:**
- Check RCVD can reach Quad9: `dig @9.9.9.9 example.com`
- Verify outbound port 853 is not blocked by your network

**cloudflared exits immediately:**
- Check your outbound internet access
- Try a different network (some corporate networks block cloudflared)

---

## Upgrading to Named Tunnels (Persistent URL)

If you want a persistent URL without changing to the full standalone deployment:

1. Create a free Cloudflare account at cloudflare.com
2. Run `cloudflared tunnel login`
3. Create a named tunnel: `cloudflared tunnel create rcvd-test`
4. Configure a stable subdomain (e.g., `dns-server.yourdomain.com`)
5. Your URL is now permanent and survives restarts

See [Cloudflare Tunnel documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) for full setup.

---

## Next Steps

Once you have validated RCVD works for your use case, consider graduating to a more permanent deployment:

- **Persistent URL via Cloudflare Named Tunnel:** Requires a free Cloudflare account and login. Gives you a stable subdomain that survives tunnel restarts without needing RCVD's certmagic options. See the "Upgrading to Named Tunnels" section above.
  > ⚠️ **Privacy warning:** All DNS queries still pass through Cloudflare's network - both in Quick Tunnels and Named Tunnels. Cloudflare can theoretically see every domain you resolve. This is acceptable for testing but is a significant privacy tradeoff for any ongoing personal or team use. 
  
  > **If DNS privacy matters to you, do not use any Cloudflare tunnel as a long-term solution.**

- **Private team use (no Cloudflare):** See [Tailscale pattern in STANDALONE-DOH-DEPLOYMENT.md](STANDALONE-DOH-DEPLOYMENT.md)
- **Public production endpoint (no Cloudflare):** See [STANDALONE-DOH-DEPLOYMENT.md](STANDALONE-DOH-DEPLOYMENT.md)
