"""Network Tools — AI-accessible network reconnaissance utilities."""

import structlog

from app.ai.tools.scapy_wrapper import ScapyWrapper

logger = structlog.get_logger()


class NetworkTools:
    """Network reconnaissance tools for the AI engine."""

    def __init__(self):
        self.scapy = ScapyWrapper()

    async def discover_network(self, ip_range: str) -> dict:
        """AI tool: discover live hosts on a network."""
        logger.info("network_discover", range=ip_range)
        return await self.scapy.arp_scan(ip_range)

    async def ping_host(self, target: str) -> dict:
        """AI tool: check if a host is alive."""
        logger.info("network_ping", target=target)
        return await self.scapy.icmp_ping(target)

    async def scan_ports(
        self, target: str, ports: list[int] | None = None
    ) -> dict:
        """AI tool: scan for open ports."""
        logger.info("network_port_scan", target=target)
        return await self.scapy.tcp_syn_scan(target, ports)

    async def trace_route(self, target: str) -> dict:
        """AI tool: trace network path to target."""
        logger.info("network_trace", target=target)
        return await self.scapy.traceroute(target)