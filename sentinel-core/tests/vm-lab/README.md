# SSS Red-Team vs Blue-Team VM Lab

A complete test environment that demonstrates the Sentinel Security System (SSS)
defending an Ubuntu server against 12 categories of cyberattacks launched from
Kali Linux. The lab runs two identical attack passes — one against an unprotected
host (baseline), one against the same host protected by SSS — and produces a
side-by-side HTML comparison report.

---

## Architecture

```
┌─────────────────────────┐         NAT Network         ┌──────────────────────────────┐
│   Kali Linux (Attacker) │ ◄──────────────────────────► │   Ubuntu 20.04 (Target)      │
│                         │                              │                              │
│  nmap, hydra, hping3,   │                              │  VulnApp (:8888)             │
│  sqlmap, slowloris,     │                              │  SSH (:22)                   │
│  arpspoof, curl, dig    │                              │                              │
│                         │                              │  ┌──────────────────────┐    │
│  attacks/*.sh           │                              │  │  SSS Docker Stack    │    │
│  run-all-attacks.sh     │                              │  │  - Data Collector    │    │
│                         │                              │  │  - AI Engine         │    │
│                         │                              │  │  - Policy Orchestr.  │    │
│                         │                              │  │  - DRL Engine        │    │
│                         │                              │  │  - Alert Service     │    │
│                         │                              │  │  - Admin Console     │    │
│                         │                              │  │    (:3000)           │    │
│                         │                              │  └──────────────────────┘    │
└─────────────────────────┘                              └──────────────────────────────┘
```

---

## Prerequisites

### VirtualBox / VMware Configuration

1. **Two VMs**:
   - Ubuntu 20.04 LTS Desktop (4 GB RAM, 2 vCPUs minimum)
   - Kali Linux (2 GB RAM, 2 vCPUs minimum)

2. **NAT Network** (both VMs on the same one):
   - VirtualBox: *File > Preferences > Network > NAT Networks > Add*
     - Network CIDR: `10.0.2.0/24` (default) — adjust scripts if different
   - Assign both VMs to this NAT Network in their network adapter settings.

3. **Connectivity check**: Each VM should be able to `ping` the other by IP.

### Software (installed automatically by setup scripts)

| VM     | Installed by              | Key packages                                              |
|--------|---------------------------|-----------------------------------------------------------|
| Ubuntu | `target/setup-target.sh`  | Docker Engine, Docker Compose v2, git, Python 3, iptables |
| Kali   | `attacker/setup-attacker.sh` | nmap, hydra, hping3, sqlmap, slowloris, arpspoof, dig |

---

## Quick Start

### Step 1 — Set up the Ubuntu target

```bash
# On the Ubuntu VM:
git clone https://github.com/MuzeenMir/sentinel.git /opt/sentinel
cd /opt/sentinel/sentinel-core/tests/vm-lab/target

# Install Docker, base packages, create sentinel user
sudo chmod +x setup-target.sh
sudo ./setup-target.sh

# Deploy the intentionally vulnerable web app (port 8888)
chmod +x deploy-vuln-app.sh
./deploy-vuln-app.sh
```

Verify: open `http://<UBUNTU_IP>:8888` in a browser — you should see the VulnApp
home page.

### Step 2 — Set up the Kali attacker

```bash
# On the Kali VM:
# Copy the tests/vm-lab/attacker directory (or clone the repo)
git clone https://github.com/MuzeenMir/sentinel.git /opt/sentinel
cd /opt/sentinel/sentinel-core/tests/vm-lab/attacker

# Verify tools and configure target IP
sudo chmod +x setup-attacker.sh
sudo ./setup-attacker.sh <UBUNTU_IP>
```

### Step 3 — Run the BASELINE (unprotected) attacks

```bash
# On the Kali VM:
cd /opt/sentinel/sentinel-core/tests/vm-lab/comparison

# This tears down SSS on Ubuntu (via SSH or manual prompt), then attacks
sudo chmod +x run-baseline.sh
sudo ./run-baseline.sh
```

Results are saved to `attacker/results/baseline_<timestamp>/`.

### Step 4 — Deploy SSS on Ubuntu and run PROTECTED attacks

```bash
# On the Ubuntu VM — deploy SSS:
cd /opt/sentinel/sentinel-core/tests/vm-lab/target
chmod +x deploy-sss.sh
./deploy-sss.sh

# Verify SSS is running:
#   Admin Console: http://<UBUNTU_IP>:3000
#   API Gateway:   http://<UBUNTU_IP>:8080/health
```

```bash
# On the Kali VM — run the same attacks against the now-protected target:
cd /opt/sentinel/sentinel-core/tests/vm-lab/comparison
sudo chmod +x run-protected.sh
sudo ./run-protected.sh
```

Results are saved to `attacker/results/protected_<timestamp>/`.

### Step 5 — Generate the comparison report

```bash
# On either VM (wherever Python 3 is available):
cd /opt/sentinel/sentinel-core/tests/vm-lab/comparison

python3 generate-report.py \
    ../attacker/results/baseline_<timestamp> \
    ../attacker/results/protected_<timestamp> \
    --output sss_lab_report.html
```

Open `sss_lab_report.html` in a browser to view the side-by-side diff.

---

## Attack Inventory

| #  | Attack                | Tool            | Category           | SSS Detection Method                 |
|----|-----------------------|-----------------|--------------------|--------------------------------------|
| 01 | Port Scan (SYN)       | nmap -sS        | Reconnaissance     | Behavioral features (fan-out)        |
| 02 | Vuln Scan (NSE)       | nmap scripts    | Reconnaissance     | Aggressive probe patterns            |
| 03 | SSH Brute Force       | hydra           | Brute Force        | Connection pattern analysis          |
| 04 | Web Login Brute Force | hydra / curl    | Brute Force        | HTTP request pattern analysis        |
| 05 | SYN Flood             | hping3          | Denial of Service  | SYN ratio + packet rate anomaly      |
| 06 | Slowloris             | slowloris       | Denial of Service  | Slow connection detection            |
| 07 | SQL Injection         | sqlmap / curl   | Web Application    | XGBoost classifier                   |
| 08 | XSS                   | curl payloads   | Web Application    | XGBoost classifier                   |
| 09 | DNS Exfiltration      | dig tunneling   | Data Exfiltration  | Anomalous DNS query patterns         |
| 10 | HTTP Exfiltration     | curl covert     | Data Exfiltration  | Outbound traffic anomaly             |
| 11 | ARP Spoofing          | arpspoof        | Network Attack     | Protocol deviation (L2 alert only)   |
| 12 | C2 Beaconing          | curl periodic   | Command & Control  | Periodicity + behavioral patterns    |

---

## File Structure

```
tests/vm-lab/
├── README.md                        # This file
├── target/                          # Scripts for the Ubuntu VM
│   ├── setup-target.sh              # Install Docker, deps, clone repo
│   ├── deploy-vuln-app.sh           # Build & run the vulnerable web app
│   ├── deploy-sss.sh                # Deploy SSS via Docker Compose
│   ├── teardown-sss.sh              # Stop SSS, flush iptables rules
│   └── vuln-app/                    # Intentionally vulnerable web app
│       ├── app.py                   # Python stdlib HTTP server (~250 lines)
│       ├── Dockerfile
│       └── requirements.txt
├── attacker/                        # Scripts for the Kali VM
│   ├── setup-attacker.sh            # Verify tools, configure target IP
│   ├── run-all-attacks.sh           # Execute all 12 attacks sequentially
│   └── attacks/                     # Individual attack scripts
│       ├── common.sh                # Shared helpers (logging, JSON output)
│       ├── 01-recon-portscan.sh
│       ├── 02-recon-vuln-scan.sh
│       ├── 03-brute-ssh.sh
│       ├── 04-brute-web-login.sh
│       ├── 05-dos-syn-flood.sh
│       ├── 06-dos-slowloris.sh
│       ├── 07-sqli-attack.sh
│       ├── 08-xss-attack.sh
│       ├── 09-data-exfil-dns.sh
│       ├── 10-data-exfil-http.sh
│       ├── 11-arp-spoof.sh
│       └── 12-c2-beacon.sh
└── comparison/                      # Orchestration & reporting
    ├── run-baseline.sh              # Stop SSS, run attacks, collect results
    ├── run-protected.sh             # Start SSS, run attacks, collect results + logs
    └── generate-report.py           # Parse JSON results, produce HTML report
```

---

## SSH Configuration (Optional)

For fully automated runs (no manual steps on Ubuntu), set up SSH keys:

```bash
# On Kali:
ssh-keygen -t ed25519 -f ~/.ssh/sss_lab -N ""
ssh-copy-id -i ~/.ssh/sss_lab sentinel@<UBUNTU_IP>
```

Then add to `attacker/lab.conf`:

```
TARGET_SSH_USER=sentinel
TARGET_SSH_KEY=~/.ssh/sss_lab
SSS_ROOT_ON_TARGET=/opt/sentinel/sentinel-core
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| VMs cannot ping each other | Verify both are on the same NAT Network; check VirtualBox/VMware network settings |
| Docker fails to start on Ubuntu | Run `sudo systemctl start docker` and check `journalctl -u docker` |
| VulnApp not accessible | Run `docker logs vuln-app` on Ubuntu; ensure port 8888 is allowed in UFW |
| SSS services not starting | Check `docker compose logs` in the sentinel-core directory; ensure enough RAM (4 GB+) |
| hping3/arpspoof needs root | All attack scripts should be run with `sudo` |
| hydra connection timeouts | SSS may have already blocked the attacker IP; check iptables on Ubuntu |
| Report shows "N/A" | Ensure both baseline and protected result directories contain JSON files |

---

## Security Warning

This lab contains **intentionally vulnerable software** and **active attack tools**.

- **Never** run the vulnerable web app on a production or internet-connected machine.
- **Never** run attack scripts against systems you do not own.
- Keep both VMs on an **isolated network** (NAT Network or Internal).
- The vulnerable app stores plaintext passwords and has no security headers — by design.

---

## Expected Results

- **Baseline (No SSS):** 10-12 out of 12 attacks succeed. The unprotected Ubuntu VM
  is fully compromised — ports enumerated, credentials brute-forced, SQL data
  extracted, services disrupted by DoS, data exfiltrated, and C2 channels
  established.

- **Protected (With SSS):** Most attacks are detected and blocked within seconds.
  The AI Engine identifies threat patterns, the Policy Orchestrator generates
  iptables DENY/RATE_LIMIT rules, and the attacker's IP is progressively
  quarantined. The Admin Console at `:3000` shows real-time alerts and policy
  changes.

- **Report:** The HTML comparison report shows a clear difference — green
  "DEFENDED" verdicts for attacks that SSS stopped, red "BYPASSED" for any that
  got through.
