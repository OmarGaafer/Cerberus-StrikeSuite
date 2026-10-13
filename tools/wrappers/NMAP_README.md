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



---

# 📊 جدول تغطية كل features Nmap

| Feature | Wrapper Method | API ScanType | ✅ |
| :--- | :--- | :--- | :---: |
| Host Discovery | `host_discovery` | `host_discovery` | ✅ |
| Ping Sweep | `ping_sweep` | `ping_sweep` | ✅ |
| ARP Scan | `arp_scan` | `arp_scan` | ✅ |
| TCP SYN | `scan_tcp_syn` | `tcp_syn` | ✅ |
| TCP Connect | `scan_tcp_connect` | `tcp_connect` | ✅ |
| TCP ACK | `scan_tcp_ack` | `tcp_ack` | ✅ |
| TCP FIN | `scan_tcp_fin` | `tcp_fin` | ✅ |
| TCP NULL | `scan_tcp_null` | `tcp_null` | ✅ |
| TCP Xmas | `scan_tcp_xmas` | `tcp_xmas` | ✅ |
| UDP | `scan_udp` | `udp` | ✅ |
| SCTP INIT | `scan_sctp_init` | `sctp_init` | ✅ |
| SCTP Cookie | `scan_sctp_cookie` | — | ✅ |
| IP Protocol | `scan_ip_protocol` | `ip_protocol` | ✅ |
| Idle | `scan_idle` | `idle` | ✅ |
| All Ports | `scan_all_ports` | `full` | ✅ |
| Top Ports | `scan_top_ports` | — | ✅ |
| Fast Scan | `scan_fast` | `quick` | ✅ |
| Specific Ports | `scan_specific_ports` | (via ports param) | ✅ |
| Service Detection | `service_detection` | `service` | ✅ |
| OS Detection | `os_detection` | `os` | ✅ |
| NSE Default | `script_default` | — | ✅ |
| NSE Vuln | `script_vuln` | `script_vuln` | ✅ |
| NSE Auth | `script_auth` | `script_auth` | ✅ |
| NSE Brute | `script_brute` | `script_brute` | ✅ |
| NSE Discovery | `script_discovery` | `script_discovery` | ✅ |
| NSE Exploit | `script_exploit` | `script_exploit` | ✅ |
| NSE Vulners | `script_vulners` | — | ✅ |
| HTTP Enum | `script_http_enum` | — | ✅ |
| SMB Enum | `script_smb_enum` | — | ✅ |
| SSH Enum | `script_ssh_enum` | — | ✅ |
| SSL Scan | `script_ssl_scan` | — | ✅ |
| DNS Enum | `script_dns_enum` | — | ✅ |
| Fragment | `fragment_packets` | — | ✅ |
| Decoy | `decoy_scan` | — | ✅ |
| Spoof Source | `spoof_source` | — | ✅ |
| Spoof MAC | `spoof_mac` | — | ✅ |
| Randomize | `randomize_hosts` | — | ✅ |
| Bad Checksum | `bad_checksum` | — | ✅ |
| Data Length | `data_length` | — | ✅ |
| Source Port | `source_port` | — | ✅ |
| Timing | `timed_scan` | — | ✅ |
| Traceroute | `traceroute` | `traceroute` | ✅ |
| CIDR | `scan_cidr` | — | ✅ |
| Range | `scan_range` | — | ✅ |
| From File | `scan_from_file` | — | ✅ |
| Exclude | `scan_exclude` | — | ✅ |
| Aggressive | `aggressive_scan` | `aggressive` | ✅ |
| Intense | `intense_scan` | `intense` | ✅ |
| Comprehensive | `comprehensive_scan` | `comprehensive` | ✅ |
| Stealth | `stealth_scan` | `stealth` | ✅ |
| Pentest | `pentest_scan` | `pentest` | ✅ |
| Ndiff | `ndiff` | — | ✅ |
| Nping | `nping` | — | ✅ |

**إجمالي: 51 feature** — كلهم مغطّيين.

---

# ✅ قائمة التحقق النهائية

## الملفات (11):
- [ ] 1. `tools/wrappers/nmap_wrapper.py`
- [ ] 2. `tools/__init__.py`
- [ ] 3. `tools/wrappers/__init__.py`
- [ ] 4. `backend/app/schemas/scan.py`
- [ ] 5. `backend/app/tasks/scan_tasks.py`
- [ ] 6. `backend/app/api/v1/endpoints/scanning.py`
- [ ] 7. `backend/app/api/v1/router.py` (تعديل)
- [ ] 8. `backend/tests/unit/test_nmap_wrapper.py`
- [ ] 9. `backend/tests/integration/test_api_scanning.py`
- [ ] 10. `docs/nmap_integration.md`
- [ ] 11. `tools/wrappers/NMAP_README.md`

## تحقق على GitHub:
- [ ] شجرة الملفات فيها `tools/wrappers/`
- [ ] شجرة الملفات فيها `docs/`
- [ ] صفحة Commits فيها **11 commits**
- [ ] `router.py` فيه `scanning` في imports
- [ ] `router.py` فيه `api_v1_router.include_router(scanning.router, ...)`

---

# 🎯 بعد الرفع

**قولي "خلصت"** وأنا:
1. أساعدك تنزّل المشروع على جهازك
2. تثبيت Nmap
3. تشغيل السيرفر
4. اختبار كل حاجة
5. ربط Nmap بالـ AI agents

**أنا معاك خطوة بخطوة.** 💪
