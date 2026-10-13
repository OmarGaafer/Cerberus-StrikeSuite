from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class ScanType(str, Enum):
    HOST_DISCOVERY = "host_discovery"
    PING_SWEEP = "ping_sweep"
    ARP_SCAN = "arp_scan"
    TCP_SYN = "tcp_syn"
    TCP_CONNECT = "tcp_connect"
    TCP_ACK = "tcp_ack"
    TCP_FIN = "tcp_fin"
    TCP_NULL = "tcp_null"
    TCP_XMAS = "tcp_xmas"
    UDP = "udp"
    SCTP_INIT = "sctp_init"
    IP_PROTOCOL = "ip_protocol"
    IDLE = "idle"
    SERVICE = "service"
    OS = "os"
    SCRIPT_VULN = "script_vuln"
    SCRIPT_AUTH = "script_auth"
    SCRIPT_BRUTE = "script_brute"
    SCRIPT_DISCOVERY = "script_discovery"
    SCRIPT_EXPLOIT = "script_exploit"
    QUICK = "quick"
    FULL = "full"
    AGGRESSIVE = "aggressive"
    INTENSE = "intense"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    PENTEST = "pentest"
    TRACEROUTE = "traceroute"
    CUSTOM = "custom"


class ScanRequest(BaseModel):
    target: str = Field(..., description="IP, CIDR, hostname, or range")
    scan_type: ScanType = ScanType.QUICK
    ports: Optional[str] = None
    custom_args: Optional[str] = None
    timing: Optional[str] = None
    scripts: Optional[List[str]] = None
    script_args: Optional[Dict[str, str]] = None
    exclude: Optional[str] = None
    engagement_id: Optional[str] = None
    roe_acknowledged: bool = False


class ScriptResultSchema(BaseModel):
    id: str
    output: str


class PortResultSchema(BaseModel):
    port: int
    protocol: str
    state: str
    reason: Optional[str] = ""
    service: Optional[str] = ""
    product: Optional[str] = ""
    version: Optional[str] = ""
    extrainfo: Optional[str] = ""
    cpe: List[str] = []
    scripts: Dict[str, str] = {}


class HostResultSchema(BaseModel):
    ip: str
    mac: Optional[str] = ""
    vendor: Optional[str] = ""
    hostname: Optional[str] = ""
    state: str
    uptime: Optional[str] = ""
    distance: Optional[str] = ""
    os_matches: List[Dict[str, Any]] = []
    ports: List[PortResultSchema] = []
    host_scripts: Dict[str, str] = {}
    traceroute: List[Dict[str, Any]] = []


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    command: Optional[str] = None
    hosts: List[HostResultSchema] = []
    error: Optional[str] = None
    elapsed: Optional[float] = None
    nmap_version: Optional[str] = None
