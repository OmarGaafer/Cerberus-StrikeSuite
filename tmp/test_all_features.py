import sys, os, time
sys.path.insert(0, os.getcwd())
from tools.wrappers.nmap_wrapper import NmapWrapper

w = NmapWrapper()
TARGET = "scanme.nmap.org"

# (label, function, needs_root)
TESTS = [
    ("Host Discovery",     lambda: w.host_discovery(TARGET), False),
    ("Ping Sweep",         lambda: w.ping_sweep("127.0.0.1"), False),
    ("ARP Scan",           lambda: w.arp_scan("127.0.0.1"), True),
    ("TCP SYN",            lambda: w.scan_tcp_syn(TARGET, "22,80"), True),
    ("TCP Connect",        lambda: w.scan_tcp_connect(TARGET, "22,80"), False),
    ("TCP ACK",            lambda: w.scan_tcp_ack(TARGET, "22,80"), True),
    ("TCP FIN",            lambda: w.scan_tcp_fin(TARGET, "22,80"), True),
    ("TCP NULL",           lambda: w.scan_tcp_null(TARGET, "22,80"), True),
    ("TCP Xmas",           lambda: w.scan_tcp_xmas(TARGET, "22,80"), True),
    ("UDP",                lambda: w.scan_udp(TARGET, "1-50"), True),
    ("IP Protocol",        lambda: w.scan_ip_protocol(TARGET), True),
    ("Service Detection",  lambda: w.service_detection(TARGET, "22,80"), False),
    ("OS Detection",       lambda: w.os_detection("127.0.0.1"), True),
    ("NSE Default",        lambda: w.script_default(TARGET, "80"), False),
    ("NSE Vuln",           lambda: w.script_vuln(TARGET, "80"), False),
    ("NSE Auth",           lambda: w.script_auth(TARGET, "22"), False),
    ("NSE Discovery",      lambda: w.script_discovery(TARGET, "80"), False),
    ("NSE Vulners",        lambda: w.script_vulners(TARGET, "80"), False),
    ("Fragment Packets",   lambda: w.fragment_packets(TARGET), True),
    ("Decoy Scan",         lambda: w.decoy_scan(TARGET, "RND:5"), True),
    ("Timing T4",          lambda: w.timed_scan(TARGET, "-T4", "22,80"), False),
    ("Traceroute",         lambda: w.traceroute(TARGET), True),
    ("CIDR",               lambda: w.scan_cidr("127.0.0.1/32"), False),
    ("IP Range",           lambda: w.scan_range("127.0.0.1", "127.0.0.1"), False),
    ("Top Ports",          lambda: w.scan_top_ports(TARGET, 100), False),
    ("Fast Scan",          lambda: w.scan_fast(TARGET), False),
    ("Aggressive",         lambda: w.aggressive_scan(TARGET), True),
    ("Stealth",            lambda: w.stealth_scan(TARGET, "22,80"), True),
]

print("=" * 70)
print(f"Testing NmapWrapper on {TARGET}")
print("=" * 70)

passed = failed = skipped = 0

for label, fn, needs_root in TESTS:
    if needs_root and os.geteuid() != 0:
        print(f"[SKIP] {label:25s} (needs root)")
        skipped += 1
        continue
    try:
        start = time.time()
        r = fn()
        elapsed = time.time() - start
        if r.success:
            print(f"[PASS] {label:25s} ({elapsed:5.1f}s) - {len(r.hosts)} hosts")
            passed += 1
        else:
            print(f"[FAIL] {label:25s} - {(r.error or '')[:60]}")
            failed += 1
    except Exception as e:
        print(f"[ERR ] {label:25s} - {e}")
        failed += 1

print("=" * 70)
print(f"PASSED: {passed}   FAILED: {failed}   SKIPPED: {skipped}")
print("=" * 70)
