# Nmap Integration

Full Nmap capability integration for Cerberus-StrikeSuite.

## Files

| File | Purpose |
| :--- | :--- |
| `tools/wrappers/nmap_wrapper.py` | 50+ methods covering every Nmap feature |
| `tools/wrappers/__init__.py` | Package exports |
| `backend/app/schemas/scan.py` | Pydantic schemas |
| `backend/app/db/session.py` | Async + sync DB sessions |
| `backend/app/db/models/scan.py` | Scan, ScanHost, ScanPort models |
| `backend/app/db/repositories/scan_repo.py` | Scan CRUD |
| `backend/app/tasks/scan_tasks.py` | Celery task |
| `backend/app/api/v1/endpoints/scanning.py` | REST API |

## Supported Nmap Features

### Host Discovery
- `host_discovery` — Ping scan
- `ping_sweep` — ICMP + TCP + UDP
- `arp_scan` — ARP scan (LAN)

### Port Scanning
- `tcp_syn` — SYN stealth (root)
- `tcp_connect` — Connect
- `tcp_ack` — ACK scan (root)
- `tcp_fin`, `tcp_null`, `tcp_xmas` — Stealth variants (root)
- `udp` — UDP scan (root, slow)
- `sctp_init` — SCTP scan
- `ip_protocol` — IP protocol scan
- `full` — All 65535 ports
- `quick` — Fast top 100

### Service & OS
- `service` — Version detection
- `os` — OS fingerprinting (root)

### NSE Scripts
- `script_vuln` — Vulnerability scripts
- `script_auth` — Auth scripts
- `script_brute` — Brute force scripts
- `script_discovery` — Discovery scripts
- `script_exploit` — Exploit scripts

### Combined
- `aggressive` — `-A` (all-in-one)
- `intense` — Deep scan
- `comprehensive` — TCP + UDP + scripts
- `stealth` — Slow + evasion
- `pentest` — Full pentest workflow

### Other
- `traceroute` — Network path
- `custom` — Arbitrary Nmap args

## Setup

### 1. Install Nmap
```bash
sudo apt update
sudo apt install -y nmap ncat ndiff nping
