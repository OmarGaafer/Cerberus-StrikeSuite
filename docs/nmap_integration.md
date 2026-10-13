# Nmap Integration

Full Nmap capability integration for Cerberus-StrikeSuite.

## Files Included

| File | Purpose |
| :--- | :--- |
| `tools/wrappers/nmap_wrapper.py` | 50+ methods covering every Nmap feature |
| `backend/app/schemas/scan.py` | Pydantic schemas |
| `backend/app/tasks/scan_tasks.py` | Celery async task |
| `backend/app/api/v1/endpoints/scanning.py` | REST API |

## Supported Nmap Features

- Host Discovery (ping, ARP, ICMP)
- Port Scanning (SYN, Connect, ACK, FIN, NULL, Xmas, UDP, SCTP, IP, Idle)
- Service Detection
- OS Detection
- NSE Scripts (auth, vuln, discovery, brute, exploit, safe, vulners)
- Firewall Evasion (fragment, decoy, spoof, bad checksum, data length)
- Timing Control (T0-T5)
- Traceroute
- Target Specification (CIDR, range, file, exclude)
- Combined Scans (Aggressive, Intense, Comprehensive, Stealth, Pentest)
- External tools (Ndiff, Nping)

## Setup

### 1. Install Nmap on the host
```bash
sudo apt update
sudo apt install -y nmap ncat ndiff nping
