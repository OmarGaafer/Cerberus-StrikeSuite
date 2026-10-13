"""
Nmap Wrapper Usage Examples
============================
Run from project root:
    python3 examples/nmap_usage.py
"""
import sys
import os
import json

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.wrappers.nmap_wrapper import NmapWrapper


def section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def example_1_quick_scan():
    section("Example 1: Quick scan (top 100 ports)")
    w = NmapWrapper()
    r = w.scan_fast("scanme.nmap.org")

    print(f"Success:  {r.success}")
    print(f"Elapsed:  {r.elapsed:.2f}s")
    print(f"Hosts:    {len(r.hosts)}")

    for host in r.hosts:
        print(f"\nHost: {host.ip} ({host.hostname}) - {host.state}")
        for port in host.ports:
            if port.state == "open":
                print(f"  {port.port}/{port.protocol}  {port.service}  {port.product} {port.version}")


def example_2_host_discovery():
    section("Example 2: Host discovery (ping only)")
    w = NmapWrapper()
    r = w.host_discovery("scanme.nmap.org")

    print(f"Live hosts: {len(r.hosts)}")
    for host in r.hosts:
        print(f"  {host.ip} - {host.state}")


def example_3_service_detection():
    section("Example 3: Service detection on specific ports")
    w = NmapWrapper()
    r = w.service_detection("scanme.nmap.org", "22,80,443")

    for host in r.hosts:
        for port in host.ports:
            if port.state == "open":
                print(f"{port.port}: {port.service} | {port.product} {port.version}")
                if port.cpe:
                    print(f"   CPE: {', '.join(port.cpe)}")


def example_4_script_scan():
    section("Example 4: NSE vulnerability scan")
    w = NmapWrapper()
    r = w.script_vuln("scanme.nmap.org", "80")

    for host in r.hosts:
        for port in host.ports:
            for script_id, output in port.scripts.items():
                print(f"\n[{script_id}]")
                print(output[:300])


def example_5_custom_scan():
    section("Example 5: Custom scan with raw arguments")
    w = NmapWrapper()
    # Combine custom Nmap args
    r = w.run("scanme.nmap.org", "-sV -p 22,80 --script default")

    print(f"Command: {r.command}")
    print(f"Success: {r.success}")
    for host in r.hosts:
        for port in host.ports:
            if port.state == "open":
                print(f"  {port.port}: {port.service}")


def example_6_traceroute():
    section("Example 6: Traceroute")
    w = NmapWrapper()
    r = w.traceroute("scanme.nmap.org")

    for host in r.hosts:
        for hop in host.traceroute:
            print(f"  TTL {hop['ttl']:>3}  {hop['ipaddr']:<18}  {hop['rtt']}ms")


def example_7_json_output():
    section("Example 7: JSON serialization of results")
    w = NmapWrapper()
    r = w.scan_specific_ports("scanme.nmap.org", "22,80")

    output = {
        "target": r.target,
        "success": r.success,
        "elapsed": r.elapsed,
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "state": h.state,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "version": p.version,
                    }
                    for p in h.ports
                ],
            }
            for h in r.hosts
        ],
    }

    print(json.dumps(output, indent=2)[:1500])


def example_8_error_handling():
    section("Example 8: Error handling")
    w = NmapWrapper(binary_path="nmap")
    r = w.run("invalid-target-that-does-not-exist-12345.com", "-sn")

    if r.success:
        print(f"Hosts found: {len(r.hosts)}")
    else:
        print(f"Error: {r.error}")


def example_9_comprehensive():
    section("Example 9: Comprehensive scan (all features)")
    w = NmapWrapper()
    # This takes longer, so only run if you want
    print("Running comprehensive scan... (this may take 1-2 minutes)")
    r = w.aggressive_scan("scanme.nmap.org")

    print(f"Success: {r.success}")
    print(f"Elapsed: {r.elapsed:.1f}s")
    for host in r.hosts:
        print(f"\nHost: {host.ip}")
        if host.os_matches:
            print("OS matches:")
            for osm in host.os_matches[:3]:
                print(f"  {osm['name']} ({osm['accuracy']}%)")
        print("Open ports:")
        for port in host.ports:
            if port.state == "open":
                print(f"  {port.port}: {port.service} {port.version}")


def example_10_batch_targets():
    section("Example 10: Batch scan multiple targets")
    w = NmapWrapper()
    targets = ["scanme.nmap.org", "127.0.0.1"]

    for target in targets:
        print(f"\n--- Scanning {target} ---")
        r = w.scan_fast(target)
        print(f"  Success: {r.success}, Hosts: {len(r.hosts)}")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    print("NmapWrapper Usage Examples")
    print("=" * 70)

    examples = {
        "1": ("Quick scan", example_1_quick_scan),
        "2": ("Host discovery", example_2_host_discovery),
        "3": ("Service detection", example_3_service_detection),
        "4": ("NSE vuln scan", example_4_script_scan),
        "5": ("Custom scan", example_5_custom_scan),
        "6": ("Traceroute", example_6_traceroute),
        "7": ("JSON output", example_7_json_output),
        "8": ("Error handling", example_8_error_handling),
        "9": ("Comprehensive scan", example_9_comprehensive),
        "10": ("Batch scan", example_10_batch_targets),
    }

    import sys
    if len(sys.argv) > 1:
        # Run specific example
        key = sys.argv[1]
        if key in examples:
            examples[key][1]()
        else:
            print(f"Unknown example: {key}")
            print("Available:", ", ".join(examples.keys()))
    else:
        # Run safe examples only
        safe = ["1", "2", "3", "6", "7", "10"]
        for k in safe:
            try:
                examples[k][1]()
            except Exception as e:
                print(f"[{examples[k][0]}] Error: {e}")

        print("\n" + "=" * 70)
        print("Available examples: " + ", ".join(f"{k}={v[0]}" for k, v in examples.items()))
        print("Run a specific one: python3 examples/nmap_usage.py <number>")
        print("=" * 70)


if __name__ == "__main__":
    main()
