# Standalone DoH Deployment Guide

RCVD (in MODE-2) can act as a DNS-over-HTTPS server that people on the internet can query.

RCVD was created to handle TLS termination internally and integrates certmagic to help with this, for users that want to take advantage of this power feature.

...Contrary to traditional DNS servers and tools that require a separate reverse proxy (Apache, Nginx, Caddy) to handle HTTPS certificates.

This guide covers prerequisites, deployment patterns, and realistic options for different user types.

## Certificate Options

RCVD supports multiple certificate sources:

- **Production (Internet-facing):** Automatic certificate management via Let's Encrypt (free, auto-renewed)

- **Enterprise:** Load your own certificate files from your internal CA (e.g., corporate PKI, Cloudflare CA)
  - Cloudflare CA example: `cloudflare-CA-ECC-Root-Certificate.cert`
  - Just configure `tls_cert` and `tls_key` paths in the config

- **Testing/Development:** Auto-generated self-signed certificates (test-only, untrusted by browsers)

## Prerequisites

### 1. Domain Name (Can be configured before OR after startup)
You need a domain (or subdomain) that will point to your server's public IP.

**With certmagic on-demand mode:**
- You can start RCVD first, then point the domain — either order works
- The first TLS connection triggers the cert fetch from Let's Encrypt automatically
- No cert needs to exist before RCVD starts

**Setup:**
- (you need to already have registered or be managing a domain name, and have access to create / edit it's records.)
- In your DNS provider's control panel, create an A record pointing to your server's public IP
- Optionally verify DNS propagation: `dig yourdomain.com +short`

### 2. Internet Connectivity
Your server must be reachable on port 443 (or your chosen HTTPS port) from the public internet.

**Network requirements:**
- Public IP address (not behind CGNAT or relay)
- Port 443 inbound allowed by firewall/ISP
- Stable connectivity (power + internet uptime)

### 3. Privileges
RCVD needs to listen on port 443 (privileged port < 1024).

**Options:**
- Run as root (not recommended for production)
- Use `setcap` on Linux: `sudo setcap cap_net_bind_service=+ep ./rcvd`
- Use non-standard port (e.g., 8443) and reverse-proxy from port 443
- Use systemd socket activation (advanced)

---

## Deployment Patterns by User Type

### Pattern 1: Enterprise Admin (Traditional Deployment)

**Scenario:** Company wants to deploy DoH for internal employees.

**Resources:**
- Static IP or failover setup
- DNS infrastructure (AD, Route53, Infoblox)
- Monitoring and logging (Prometheus, ELK)
- TLS certificate already managed by company

**Deployment:**
```bash
# 1. Provision VM on company infrastructure
# 2. Create DNS record: dns-company.internal → server-ip
# 3. Configure RCVD
listen_doh = "0.0.0.0:443"
allowed_domains = ["dns-company.internal"]
staging = false  # Production certs via Let's Encrypt

# 4. Start RCVD with systemd
sudo systemctl start rcvd

# 5. Test from employee workstation
curl -H 'accept: application/dns-json' \
  'https://dns-company.internal/dns-query?name=google.com&type=A'
```

**Advantages:**
- Enterprise-grade monitoring and control
- Existing infrastructure integration
- Offline networks possible with custom CA

**Cost:** Server only (no additional tooling needed)

---

### Pattern 2: Cloud Homelab (Testing/Learning)

**Scenario:** Developer wants to test DoH on cloud VPS without complexity.

**Resources:**
- $5-10/month VPS (Linode, DigitalOcean, Vultr, Hetzner)
- Subdomain of existing domain
- 30 minutes setup time

**Deployment:**
```bash
# 1. Provision Ubuntu 24.04 LTS VPS
# 2. Create subdomain: dns-lab.example.com → vps-ip
# 3. Install RCVD
wget https://github.com/rcvd-dns/rcvd/releases/download/v0.1/rcvd-linux-x64
chmod +x rcvd

# 4. Create config (rcvd-doh-standalone.toml)
listen_doh = "0.0.0.0:443"
allowed_domains = ["dns-lab.example.com"]
staging = false  # Production cert (free from Let's Encrypt)

# 5. Run in background
sudo ./rcvd -config rcvd-doh-standalone.toml &

# 6. Test
curl -H 'accept: application/dns-json' \
  'https://dns-lab.example.com/dns-query?name=example.com&type=A'
```

**Advantages:**
- Simple one-binary deployment
- Automatic HTTPS (no cert management)
- Quad9 upstream already configured
- Sub-$200/year for dedicated server

**Realistic cost:** $5-15/month for VPS

---

### Pattern 3: Tailscale Private Mesh (No Public Internet Required)

**Scenario:** Small team, home lab, or paranoid admins who want DoH without exposing to internet.

**Resources:**
- Tailscale account (free tier supports up to 100 devices)
- Any Linux machine (home server, Raspberry Pi, laptop)
- Tailscale client on target devices

**Deployment:**
```bash
# 1. Install Tailscale on server
curl -fsSL https://tailscale.com/install.sh | sh

# 2. Join tailnet (Tailscale private network)
sudo tailscale up

# 3. Get Tailscale IP
tailscale ip -4  # e.g., 100.105.23.45

# 4. Create RCVD config
listen_doh = "0.0.0.0:443"
allowed_domains = ["rcvd-home"]  # Only accessible within tailnet
staging = false

# 5. Run RCVD
sudo ./rcvd -config rcvd-doh-standalone.toml

# 6. On client machine (also in tailnet)
curl -H 'accept: application/dns-json' \
  'https://rcvd-home:443/dns-query?name=example.com&type=A'
```

**Advantages:**
- Zero port forwarding hassle
- Encrypted tunnel by default (Wireguard)
- Works across ISP boundaries
- No certificate issues (Tailscale mTLS)
- Free tier supports 100 devices

**Cost:** Free (Tailscale) + server cost

**Ideal for:**
- Home labs
- Small team clusters
- Testing before public deployment
- Privacy-conscious admins

---

### Pattern 4: Docker Compose (One-Click Testing)

**Scenario:** Quick evaluation without installing Go/building from source.

**Resources:**
- Docker + Docker Compose (free)
- Subdomain or localhost testing
- 5 minutes setup

**Deployment:**
```yaml
# docker-compose.yml
version: '3.8'
services:
  rcvd:
    image: rcvd:latest  # Replace with actual image
    ports:
      - "443:443"       # HTTPS DoH
      - "853:853"       # DoT
    volumes:
      - ./rcvd-doh-standalone.toml:/etc/rcvd.toml:ro
      - rcvd-certs:/root/.rcvd/certs
    environment:
      - RCVD_CONFIG=/etc/rcvd.toml
    restart: unless-stopped

volumes:
  rcvd-certs:
```

Then:
```bash
docker-compose up -d
docker-compose logs -f rcvd
```

**Advantages:**
- No local build needed
- Portable across Linux/Mac/Windows
- Easy cleanup (docker-compose down)
- Volume persistence for certificates

**Cost:** Free

---

### Pattern 5: Raspberry Pi / Home Server (Always-On)

**Scenario:** Home labber wants persistent DoH without cloud costs.

**Resources:**
- Raspberry Pi 4 ([$35-75](https://raspberrypi.com))
- Home internet (ISP router)
- Dynamic DNS service (Cloudflare, DuckDNS) if IP changes

**Deployment:**
```bash
# 1. Setup Raspberry Pi (Raspberry Pi OS Lite recommended)
# 2. Install Go (if building from source)
# 3. Compile RCVD
git clone https://github.com/rcvd-dns/rcvd
cd rcvd
go build -o rcvd ./cmd/rcvd

# 4. Forward port 443 in home router
# Router settings → Port Forwarding
# External port 443 → Internal IP (Pi IP):443

# 5. Create dynamic DNS record (if IP not static)
# Use Cloudflare API, DuckDNS, or similar

# 6. Config RCVD
listen_doh = "0.0.0.0:443"
allowed_domains = ["dns-home.duckdns.org"]
staging = false

# 7. Run in systemd
sudo systemctl enable rcvd
sudo systemctl start rcvd
```

**Advantages:**
- One-time $35-75 hardware cost
- Zero monthly fees
- Full control over data
- Learning experience
- Can add blocklists easily

**Disadvantages:**
- Home ISP may block port 443 outbound
- Residential ISP may not allow public services (TOS)
- Dynamic IP requires DDNS update mechanism
- Home internet reliability may vary

**Realistic cost:** $50-100 upfront, $0/month

---

### Pattern 6: Kubernetes (Enterprise Scale)

**Scenario:** Large organization needing HA/load-balanced DoH.

**Deployment:**
```yaml
# kubernetes/rcvd-doh.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rcvd-config
data:
  rcvd.toml: |
    [upstream_service]
    enabled = true
    listen_doh = "0.0.0.0:443"
    tls_automation = true
    [tls_automation]
    allowed_domains = ["dns.example.com"]
    staging = false

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rcvd-doh
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rcvd-doh
  template:
    metadata:
      labels:
        app: rcvd-doh
    spec:
      containers:
      - name: rcvd
        image: rcvd:v0.1
        ports:
        - containerPort: 443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/rcvd
        - name: certs
          mountPath: /root/.rcvd/certs
      volumes:
      - name: config
        configMap:
          name: rcvd-config
      - name: certs
        persistentVolumeClaim:
          claimName: rcvd-certs

---
apiVersion: v1
kind: Service
metadata:
  name: rcvd-doh
spec:
  type: LoadBalancer
  selector:
    app: rcvd-doh
  ports:
  - port: 443
    targetPort: 443
    protocol: TCP
```

**Advantages:**
- HA setup (multiple replicas)
- Auto-scaling
- Rolling updates (zero downtime)
- Monitoring integration (Prometheus)

**Cost:** Kubernetes cluster cost (varies by provider)

---

## Comparison Table

| Pattern | Cost/Month | Setup Time | Public? | Reliability | Best For |
|---------|-----------|-----------|---------|-------------|----------|
| Enterprise | $0-500+ | Hours | Yes | 99.9%+ | Companies, ISPs |
| Cloud VPS | $5-15 | 30min | Yes | 99% | Developers, Labs |
| Tailscale | $0 (free) | 10min | No | 99.9% | Teams, Home labs |
| Docker | $0 | 5min | Local only | 100% | Testing, CI/CD |
| Raspberry Pi | $0 | 1hr | Conditional | 95% | Hobbyists |
| Kubernetes | $50-1000+ | Hours | Yes | 99.99% | Enterprise scale |

---

## Choosing Your Pattern

**Ask yourself:**

1. **Do I need public internet access?**
   - Yes → Cloud VPS, Enterprise, or Kubernetes
   - No → Tailscale, Docker, or Raspberry Pi

2. **How much am I willing to spend?**
   - $0/month → Tailscale, Docker, or home Raspberry Pi
   - $5-15/month → Cloud VPS
   - $100+/month → Enterprise/Kubernetes

3. **How critical is uptime?**
   - Hobby (95%) → Raspberry Pi, single VPS
   - Important (99%) → Cloud VPS with monitoring
   - Critical (99.9%+) → Kubernetes, enterprise setup

4. **Do I know my ISP's policies?**
   - Home ISP may block port 443 or forbid public services
   - Check TOS; consider cloud instead

---

## Security Considerations

1. **Certificates**: Let's Encrypt certs are publicly visible. Domain names WILL be logged in CT databases.
2. **Logging**: Enable query logging if you want to audit who queried what (privacy tradeoff).
3. **Upstream selection**: Quad9 is recommended (DNSSEC, no-logging, nonprofit). Consider alternatives if you have specific requirements.
4. **Access control**: Tailscale pattern is inherently access-controlled. Public patterns should use firewall rules + monitoring.

---

## Testing Your Deployment

Once running:

```bash
# Test DoH query
curl -H 'accept: application/dns-message' \
  --data-binary @<(echo -n "AAAAAQ...|base64-encoded-query") \
  'https://your-domain.com/dns-query' | xxd

# Or simpler (JSON):
curl -H 'accept: application/dns-json' \
  'https://your-domain.com/dns-query?name=example.com&type=A'

# Test with Firefox
# Preferences → Network Settings → DNS over HTTPS
# URL: https://your-domain.com/dns-query
# Test: navigate to any website, should resolve via DoH
```

---

## Next Steps

1. Choose your deployment pattern above
2. Follow the deployment steps
3. Configure `allowed_domains` in `rcvd-doh-standalone.toml`
4. Start RCVD
5. Test with curl or Firefox
6. Monitor logs: `journalctl -u rcvd -f` (if using systemd)

For questions, see [docs/CONFIG.md](CONFIG.md) for all configuration options.
