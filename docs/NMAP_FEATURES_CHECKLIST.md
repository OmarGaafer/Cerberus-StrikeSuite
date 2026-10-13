# Nmap Features Checklist

Complete list of all Nmap features integrated.

## 1. Host Discovery
- [x] `host_discovery` — Ping scan
- [x] `ping_sweep` — Full sweep
- [x] `arp_scan` — ARP
- [x] `list_scan` — List only
- [x] `no_ping_scan` — Skip

## 2. Port Scanning
- [x] TCP SYN
- [x] TCP Connect
- [x] TCP ACK
- [x] TCP FIN
- [x] TCP NULL
- [x] TCP Xmas
- [x] UDP
- [x] SCTP INIT
- [x] SCTP Cookie
- [x] IP Protocol
- [x] Idle

## 3. Port Selection
- [x] All ports (1-65535)
- [x] Top ports
- [x] Fast scan
- [x] Specific ports

## 4. Service Detection
- [x] Light
- [x] Standard
- [x] All

## 5. OS Detection
- [x] Standard
- [x] Limited

## 6. NSE Scripts
- [x] Default
- [x] Vuln
- [x] Auth
- [x] Brute
- [x] Discovery
- [x] Exploit
- [x] Safe
- [x] Vulners (CVE)
- [x] HTTP enum
- [x] SMB enum
- [x] SSH enum
- [x] SSL/TLS scan
- [x] DNS enum
- [x] Custom scripts
- [x] Script arguments

## 7. Firewall Evasion
- [x] Fragment packets
- [x] Decoy scan
- [x] Spoof source IP
- [x] Spoof MAC
- [x] Randomize hosts
- [x] Bad checksum
- [x] Data length
- [x] Source port

## 8. Timing
- [x] T0-T5 templates
- [x] Custom timing

## 9. Traceroute
- [x] Standard traceroute

## 10. Target Specification
- [x] CIDR
- [x] IP range
- [x] From file
- [x] Exclude targets
- [x] Exclude from file

## 11. Combined Scans
- [x] Aggressive (-A)
- [x] Intense
- [x] Comprehensive
- [x] Stealth
- [x] Pentest
