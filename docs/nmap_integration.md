# Nmap Integration

Full Nmap capability integration for Cerberus-StrikeSuite.

## Files

| File | Purpose |
| :--- | :--- |
| `tools/wrappers/nmap_wrapper.py` | 50+ methods covering every Nmap feature |
| `tools/wrappers/__init__.py` | Package exports |
| `backend/app/schemas/scan.py` | Pydantic schemas |
| `backend/app/tasks/scan_tasks.py` | Celery async task |
| `backend/app/api/v1/endpoints/scanning.py` | REST API |
| `backend/tests/unit/test_nmap_wrapper.py` | Unit tests |
| `backend/tests/integration/test_api_scanning.py` | Integration tests |

## Supported Features

- Host Discovery: ping, ARP, ICMP, list, no-ping
- Port Scanning: TCP SYN/Connect/ACK/FIN/NULL/Xmas, UDP, SCTP, IP, Idle
- Port Selection: all, top, fast, specific
- Service Detection: light, standard, all
- OS Detection: standard, limit
- NSE Scripts: default, vuln, auth, brute, discovery, exploit, safe, vulners, http/smb/ssh/ssl/dns enum
- Firewall Evasion: fragment, decoy, spoof source/MAC, bad checksum, data length, source port
- Timing: T0-T5
- Traceroute
- Target Spec: CIDR, range, file, exclude
- Combined: aggressive, intense, comprehensive, stealth, pentest
- External: ndiff, nping

## Setup

### 1. Install Nmap
```bash
sudo apt update
sudo apt install -y nmap ncat ndiff nping
