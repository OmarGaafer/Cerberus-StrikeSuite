"""
NmapWrapper - Full Nmap capability wrapper for Cerberus-StrikeSuite
"""
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
import shlex
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    state: str = "unknown"
    os_matches: List[Dict] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    host_scripts: Dict[str, str] = field(default_factory=dict)
    traceroute: List[Dict] = field(default_factory=list)
    uptime: str = ""
    distance: str = ""


@dataclass
class NmapResult:
    target: str
    command: str
    hosts: List[HostResult] = field(default_factory=list)
    raw_xml: str = ""
    raw_text: str = ""
    success: bool = False
    error: str = ""
    elapsed: float = 0.0
    nmap_version: str = ""


class NmapWrapper:
    def __init__(self, binary_path: str = "nmap", default_timeout: int = 900):
        self.binary = binary_path
        self.default_timeout = default_timeout

    def run(self, target: str, arguments: str = "-sV", timeout: Optional[int] = None) -> NmapResult:
        timeout = timeout or self.default_timeout
        result = NmapResult(target=target, command=f"{self.binary} {arguments} {target}")
        tmp_xml = tempfile.NamedTemporaryFile(suffix=".xml", delete=False).name
        tmp_text = tempfile.NamedTemporaryFile(suffix=".txt", delete=False).name
        try:
            args = shlex.split(arguments)
            cmd = [self.binary] + args + ["-oX", tmp_xml, "-oN", tmp_text, target]
            start = time.time()
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result.elapsed = time.time() - start
            if proc.returncode != 0 and not os.path.exists(tmp_xml):
                result.error = proc.stderr or "Nmap failed"
                return result
            if os.path.exists(tmp_xml):
                with open(tmp_xml, "r", encoding="utf-8", errors="ignore") as f:
                    result.raw_xml = f.read()
                result.hosts = self._parse_xml(result.raw_xml, result)
            if os.path.exists(tmp_text):
                with open(tmp_text, "r", encoding="utf-8", errors="ignore") as f:
                    result.raw_text = f.read()
            result.success = True
        except subprocess.TimeoutExpired:
            result.error = f"Nmap timed out after {timeout}s"
        except FileNotFoundError:
            result.error = f"Nmap binary not found at '{self.binary}'"
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        finally:
            for p in (tmp_xml, tmp_text):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
        return result

    # ---------- Host Discovery ----------
    def host_discovery(self, target): return self.run(target, "-sn")
    def ping_sweep(self, target): return self.run(target, "-sn -PE -PS443 -PA80 -PP")
    def arp_scan(self, target): return self.run(target, "-sn -PR")
    def list_scan(self, target): return self.run(target, "-sL")
    def no_ping_scan(self, target): return self.run(target, "-Pn")

    # ---------- Port Scanning ----------
    def scan_tcp_syn(self, target, ports="1-1000"): return self.run(target, f"-sS -p {ports}")
    def scan_tcp_connect(self, target, ports="1-1000"): return self.run(target, f"-sT -p {ports}")
    def scan_tcp_ack(self, target, ports="1-1000"): return self.run(target, f"-sA -p {ports}")
    def scan_tcp_fin(self, target, ports="1-1000"): return self.run(target, f"-sF -p {ports}")
    def scan_tcp_null(self, target, ports="1-1000"): return self.run(target, f"-sN -p {ports}")
    def scan_tcp_xmas(self, target, ports="1-1000"): return self.run(target, f"-sX -p {ports}")
    def scan_udp(self, target, ports="1-1000"): return self.run(target, f"-sU -p {ports}", timeout=1800)
    def scan_sctp_init(self, target, ports="1-1000"): return self.run(target, f"-sY -p {ports}")
    def scan_sctp_cookie(self, target, ports="1-1000"): return self.run(target, f"-sZ -p {ports}")
    def scan_ip_protocol(self, target): return self.run(target, "-sO")
    def scan_idle(self, target, zombie, ports="1-1000"): return self.run(target, f"-sI {zombie} -p {ports}")
    def scan_all_ports(self, target): return self.run(target, "-sS -p-", timeout=3600)
    def scan_top_ports(self, target, count=1000): return self.run(target, f"--top-ports {count}")
    def scan_fast(self, target): return self.run(target, "-F")
    def scan_specific_ports(self, target, ports): return self.run(target, f"-p {ports}")

    # ---------- Service Detection ----------
    def service_detection(self, target, ports="1-1000", intensity=7):
        return self.run(target, f"-sV --version-intensity {intensity} -p {ports}")
    def service_light(self, target): return self.run(target, "-sV --version-light")
    def service_all(self, target): return self.run(target, "-sV --version-all", timeout=3600)

    # ---------- OS Detection ----------
    def os_detection(self, target, guess=True):
        args = "-O"
        if guess: args += " --osscan-guess"
        return self.run(target, args)
    def os_detection_limit(self, target): return self.run(target, "-O --osscan-limit")

    # ---------- NSE Scripts ----------
    def script_default(self, target, ports=""):
        args = "-sC"
        if ports: args += f" -p {ports}"
        return self.run(target, args)
    def script_category(self, target, category, ports=""):
        args = f"--script {category}"
        if ports: args += f" -p {ports}"
        return self.run(target, args, timeout=1800)
    def script_by_name(self, target, script, ports=""):
        args = f"--script {script}"
        if ports: args += f" -p {ports}"
        return self.run(target, args, timeout=1800)
    def script_with_args(self, target, script, script_args, ports=""):
        args_str = ",".join(f"{k}={v}" for k, v in script_args.items())
        args = f"--script {script} --script-args {args_str}"
        if ports: args += f" -p {ports}"
        return self.run(target, args, timeout=1800)
    def script_vuln(self, target, ports=""): return self.script_category(target, "vuln", ports)
    def script_auth(self, target, ports=""): return self.script_category(target, "auth", ports)
    def script_brute(self, target, ports=""): return self.script_category(target, "brute", ports)
    def script_discovery(self, target, ports=""): return self.script_category(target, "discovery", ports)
    def script_exploit(self, target, ports=""): return self.script_category(target, "exploit", ports)
    def script_safe(self, target, ports=""): return self.script_category(target, "safe", ports)
    def script_http_enum(self, target, port=80):
        return self.run(target, f"-p {port} --script http-enum,http-title,http-headers")
    def script_smb_enum(self, target):
        return self.run(target, "-p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery")
    def script_ssh_enum(self, target, port=22):
        return self.run(target, f"-p {port} --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos")
    def script_ssl_scan(self, target, port=443):
        return self.run(target, f"-p {port} --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle")
    def script_dns_enum(self, target):
        return self.run(target, "-p 53 --script dns-zone-transfer,dns-recursion,dns-service-discovery")
    def script_vulners(self, target, ports="1-1000"):
        return self.run(target, f"-sV -p {ports} --script vulners", timeout=1800)

    # ---------- Firewall Evasion ----------
    def fragment_packets(self, target, mtu=8): return self.run(target, f"-f --mtu {mtu}")
    def decoy_scan(self, target, decoys="RND:10"): return self.run(target, f"-D {decoys}")
    def spoof_source(self, target, spoof_ip): return self.run(target, f"-S {spoof_ip}")
    def spoof_mac(self, target, mac="0"): return self.run(target, f"--spoof-mac {mac}")
    def randomize_hosts(self, target): return self.run(target, "--randomize-hosts")
    def bad_checksum(self, target): return self.run(target, "--badsum")
    def data_length(self, target, length=32): return self.run(target, f"--data-length {length}")
    def source_port(self, target, port=53): return self.run(target, f"--source-port {port}")

    # ---------- Timing ----------
    def timed_scan(self, target, timing, ports="1-1000"):
        return self.run(target, f"{timing} -p {ports}")

    # ---------- Traceroute ----------
    def traceroute(self, target, ports="80,443"):
        return self.run(target, f"--traceroute -p {ports}")

    # ---------- Target Specification ----------
    def scan_cidr(self, cidr): return self.run(cidr, "-sV")
    def scan_range(self, start_ip, end_ip): return self.run(f"{start_ip}-{end_ip}", "-sV")
    def scan_from_file(self, file_path): return self.run(f"-iL {file_path}", "-sV")
    def scan_exclude(self, target, exclude): return self.run(target, f"--exclude {exclude}")
    def scan_exclude_file(self, target, exclude_file):
        return self.run(target, f"--excludefile {exclude_file}")

    # ---------- Combined Scans ----------
    def aggressive_scan(self, target): return self.run(target, "-A", timeout=3600)
    def intense_scan(self, target):
        return self.run(target, "-sS -sV -O -p- -T4 --script default,vuln", timeout=7200)
    def comprehensive_scan(self, target):
        return self.run(target, "-sS -sU -sV -O -p- -T4 --script default,vuln,discovery --traceroute", timeout=14400)
    def stealth_scan(self, target, ports="1-1000"):
        return self.run(target, f"-sS -T2 -f --data-length 32 --randomize-hosts --max-retries 1 -p {ports}", timeout=7200)
    def pentest_scan(self, target):
        return self.run(target, "-sS -sV -O -p- -T4 --script default,discovery,safe,vuln,auth --version-all --traceroute", timeout=10800)

    # ---------- External tools ----------
    def ndiff(self, file1, file2):
        try:
            proc = subprocess.run(["ndiff", file1, file2], capture_output=True, text=True, timeout=60)
            return proc.stdout
        except Exception as e:
            return f"ndiff error: {e}"
    def nping(self, target, count=4, protocol="tcp"):
        try:
            proc = subprocess.run(["nping", f"--{protocol}", "-c", str(count), target],
                                  capture_output=True, text=True, timeout=120)
            return NmapResult(target=target, command=f"nping --{protocol} -c {count} {target}",
                              raw_text=proc.stdout, success=(proc.returncode == 0),
                              error=proc.stderr if proc.returncode != 0 else "")
        except Exception as e:
            return NmapResult(target=target, command="nping", error=str(e))

    # ---------- XML Parser ----------
    def _parse_xml(self, xml_content, result):
        hosts = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            result.error = f"XML parse error: {e}"
            return hosts
        version_el = root.find("version")
        if version_el is not None:
            result.nmap_version = version_el.get("version", "")
        for host_el in root.findall("host"):
            host = self._parse_host(host_el)
            if host:
                hosts.append(host)
        return hosts

    def _parse_host(self, host_el):
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            at = addr.get("addrtype")
            if at in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif at == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            return None
        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"
        uptime_el = host_el.find("uptime")
        uptime = uptime_el.get("seconds", "") if uptime_el is not None else ""
        distance_el = host_el.find("distance")
        distance = distance_el.get("value", "") if distance_el is not None else ""
        os_matches = []
        for osm in host_el.findall("os/osmatch"):
            os_matches.append({"name": osm.get("name", ""), "accuracy": osm.get("accuracy", "")})
        ports = []
        for port_el in host_el.findall("ports/port"):
            port_id = int(port_el.get("portid", "0"))
            proto = port_el.get("protocol", "")
            st = port_el.find("state")
            pstate = st.get("state", "unknown") if st is not None else "unknown"
            preason = st.get("reason", "") if st is not None else ""
            svc = port_el.find("service")
            cpe_list = [c.text for c in svc.findall("cpe") if c.text] if svc is not None else []
            scripts = {}
            for s in port_el.findall("script"):
                scripts[s.get("id", "")] = s.get("output", "")
            ports.append(PortResult(
                port=port_id, protocol=proto, state=pstate, reason=preason,
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
                cpe=cpe_list, scripts=scripts,
            ))
        host_scripts = {}
        for s in host_el.findall("hostscript/script"):
            host_scripts[s.get("id", "")] = s.get("output", "")
        traceroute = []
        for hop in host_el.findall("trace/hop"):
            traceroute.append({
                "ttl": hop.get("ttl", ""), "ipaddr": hop.get("ipaddr", ""),
                "rtt": hop.get("rtt", ""), "host": hop.get("host", ""),
            })
        return HostResult(ip=ip, mac=mac, vendor=vendor, hostname=hostname,
                          state=state, os_matches=os_matches, ports=ports,
                          host_scripts=host_scripts, traceroute=traceroute,
                          uptime=uptime, distance=distance)
