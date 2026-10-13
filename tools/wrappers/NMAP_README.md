# NmapWrapper

Full Nmap capability wrapper.

## Quick Reference — All Methods

### Host Discovery
- `host_discovery(target)` — Ping scan
- `ping_sweep(target)` — Full ping sweep
- `arp_scan(target)` — ARP scan (LAN, needs root)
- `list_scan(target)` — List only
- `no_ping_scan(target)` — Skip discovery

### Port Scanning
- `scan_tcp_syn(target, ports)` — SYN (needs root)
- `scan_tcp_connect(target, ports)` — Connect
- `scan_tcp_ack(target, ports)` — ACK (needs root)
- `scan_tcp_fin(target, ports)` — FIN (needs root)
- `scan_tcp_null(target, ports)` — NULL (needs root)
- `scan_tcp_xmas(target, ports)` — Xmas (needs root)
- `scan_udp(target, ports)` — UDP (needs root)
- `scan_sctp_init(target, ports)` — SCTP
- `scan_sctp_cookie(target, ports)` — SCTP COOKIE
- `scan_ip_protocol(target)` — IP protocol
- `scan_idle(target, zombie, ports)` — Idle
- `scan_all_ports(target)` — All 65535 ports
- `scan_top_ports(target, count)` — Top N ports
- `scan_fast(target)` — Fast scan (top 100)
- `scan_specific_ports(target, ports)` — Specific ports

### Service & OS
- `service_detection(target, ports, intensity)`
- `service_light(target)`
- `service_all(target)`
- `os_detection(target, guess)`
- `os_detection_limit(target)`

### NSE Scripts
- `script_default(target, ports)`
- `script_category(target, category, ports)`
- `script_by_name(target, script, ports)`
- `script_with_args(target, script, args, ports)`
- `script_vuln(target, ports)`
- `script_auth(target, ports)`
- `script_brute(target, ports)`
- `script_discovery(target, ports)`
- `script_exploit(target, ports)`
- `script_safe(target, ports)`
- `script_http_enum(target, port)`
- `script_smb_enum(target)`
- `script_ssh_enum(target, port)`
- `script_ssl_scan(target, port)`
- `script_dns_enum(target)`
- `script_vulners(target, ports)`

### Firewall Evasion
- `fragment_packets(target, mtu)`
- `decoy_scan(target, decoys)`
- `spoof_source(target, spoof_ip)`
- `spoof_mac(target, mac)`
- `randomize_hosts(target)`
- `bad_checksum(target)`
- `data_length(target, length)`
- `source_port(target, port)`

### Timing & Traceroute
- `timed_scan(target, timing, ports)`
- `traceroute(target, ports)`

### Target Specification
- `scan_cidr(cidr)`
- `scan_range(start_ip, end_ip)`
- `scan_from_file(file_path)`
- `scan_exclude(target, exclude)`
- `scan_exclude_file(target, exclude_file)`

### Combined
- `aggressive_scan(target)` — `-A`
- `intense_scan(target)` — Deep
- `comprehensive_scan(target)` — TCP + UDP + scripts
- `stealth_scan(target, ports)` — Slow + evasion
- `pentest_scan(target)` — Full pentest

### External
- `ndiff(file1, file2)`
- `nping(target, count, protocol)`

## Usage

```python
from tools.wrappers.nmap_wrapper import NmapWrapper

w = NmapWrapper()

# Simple
r = w.scan_fast("scanme.nmap.org")
for h in r.hosts:
    for p in h.ports:
        if p.state == "open":
            print(f"{p.port}/{p.protocol} - {p.service}")

# Comprehensive
r = w.pentest_scan("10.0.0.1")
print(r.raw_xml)
