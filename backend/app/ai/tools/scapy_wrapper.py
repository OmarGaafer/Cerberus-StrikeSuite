"""Scapy Wrapper — Python interface for packet crafting and network analysis."""

import asyncio
from typing import Any

import structlog

logger = structlog.get_logger()


class ScapyWrapper:
    """Wrapper for Scapy network packet manipulation."""

    def __init__(self):
        try:
            import scapy.all as scapy
            self.scapy = scapy
            self.available = True
            logger.info("scapy_loaded", version=scapy.__version__)
        except ImportError:
            self.scapy = None
            self.available = False
            logger.warning("scapy_not_installed")

    async def arp_scan(self, ip_range: str) -> dict[str, Any]:
        """Scan a network range for live hosts using ARP."""
        if not self.available:
            return {"error": "scapy not installed", "status": "failed"}
        try:
            def _scan():
                arp_request = self.scapy.ARP(pdst=ip_range)
                broadcast = self.scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_request
                answered, _ = self.scapy.srp(packet, timeout=2, verbose=False)
                return [
                    {"ip": received.psrc, "mac": received.hwsrc}
                    for _, received in answered
                ]
            devices = await asyncio.to_thread(_scan)
            return {
                "status": "completed",
                "ip_range": ip_range,
                "devices_found": len(devices),
                "devices": devices,
            }
        except Exception as e:
            logger.error("arp_scan_error", error=str(e))
            return {"status": "failed", "error": str(e)}

    async def icmp_ping(self, target: str) -> dict[str, Any]:
        """Send an ICMP echo request to a target."""
        if not self.available:
            return {"error": "scapy not installed", "status": "failed"}
        try:
            def _ping():
                packet = self.scapy.IP(dst=target) / self.scapy.ICMP()
                return self.scapy.sr1(packet, timeout=2, verbose=False)
            response = await asyncio.to_thread(_ping)
            if response:
                return {
                    "status": "completed",
                    "target": target,
                    "alive": True,
                    "response_summary": response.summary(),
                }
            return {"status": "completed", "target": target, "alive": False}
        except Exception as e:
            logger.error("icmp_ping_error", error=str(e))
            return {"status": "failed", "error": str(e)}

    async def tcp_syn_scan(
        self, target: str, ports: list[int] | None = None
    ) -> dict[str, Any]:
        """Perform a TCP SYN scan on target ports."""
        if not self.available:
            return {"error": "scapy not installed", "status": "failed"}
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443,
                     445, 3306, 3389, 5432, 8080, 8443]
        try:
            def _scan():
                open_ports = []
                for port in ports:
                    packet = (
                        self.scapy.IP(dst=target)
                        / self.scapy.TCP(dport=port, flags="S")
                    )
                    response = self.scapy.sr1(packet, timeout=1, verbose=False)
                    if response and response.haslayer(self.scapy.TCP):
                        if response[self.scapy.TCP].flags == 0x12:
                            open_ports.append(port)
                return open_ports
            open_ports = await asyncio.to_thread(_scan)
            return {
                "status": "completed",
                "target": target,
                "ports_scanned": len(ports),
                "open_ports": open_ports,
                "open_count": len(open_ports),
            }
        except Exception as e:
            logger.error("tcp_syn_scan_error", error=str(e))
            return {"status": "failed", "error": str(e)}

    async def traceroute(
        self, target: str, max_hops: int = 30
    ) -> dict[str, Any]:
        """Perform a simple traceroute to the target."""
        if not self.available:
            return {"error": "scapy not installed", "status": "failed"}
        try:
            def _trace():
                hops = []
                for ttl in range(1, max_hops + 1):
                    packet = (
                        self.scapy.IP(dst=target, ttl=ttl)
                        / self.scapy.ICMP()
                    )
                    reply = self.scapy.sr1(packet, timeout=2, verbose=False)
                    if reply is None:
                        hops.append({"hop": ttl, "ip": "*"})
                    elif reply.type == 0:
                        hops.append({"hop": ttl, "ip": reply.src, "final": True})
                        break
                    else:
                        hops.append({"hop": ttl, "ip": reply.src})
                return hops
            hops = await asyncio.to_thread(_trace)
            return {"status": "completed", "target": target, "hops": hops}
        except Exception as e:
            logger.error("traceroute_error", error=str(e))
            return {"status": "failed", "error": str(e)}