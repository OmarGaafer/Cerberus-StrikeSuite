"""REST API endpoints for Nmap scanning."""
from fastapi import APIRouter, HTTPException, status
import uuid
import sys
import os

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.schemas.scan import ScanRequest, ScanType
from tools.wrappers.nmap_wrapper import NmapWrapper

router = APIRouter(prefix="/scanning", tags=["Scanning"])


@router.get("/types/available")
async def list_scan_types():
    return [s.value for s in ScanType]


@router.post("/nmap")
async def start_nmap_scan(req: ScanRequest):
    if not req.roe_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rules of Engagement must be acknowledged",
        )

    scan_id = str(uuid.uuid4())
    w = NmapWrapper()

    dispatch = {
        ScanType.HOST_DISCOVERY: lambda: w.host_discovery(req.target),
        ScanType.PING_SWEEP: lambda: w.ping_sweep(req.target),
        ScanType.ARP_SCAN: lambda: w.arp_scan(req.target),
        ScanType.TCP_SYN: lambda: w.scan_tcp_syn(req.target, req.ports or "1-1000"),
        ScanType.TCP_CONNECT: lambda: w.scan_tcp_connect(req.target, req.ports or "1-1000"),
        ScanType.TCP_ACK: lambda: w.scan_tcp_ack(req.target, req.ports or "1-1000"),
        ScanType.TCP_FIN: lambda: w.scan_tcp_fin(req.target, req.ports or "1-1000"),
        ScanType.TCP_NULL: lambda: w.scan_tcp_null(req.target, req.ports or "1-1000"),
        ScanType.TCP_XMAS: lambda: w.scan_tcp_xmas(req.target, req.ports or "1-1000"),
        ScanType.UDP: lambda: w.scan_udp(req.target, req.ports or "1-1000"),
        ScanType.SCTP_INIT: lambda: w.scan_sctp_init(req.target, req.ports or "1-1000"),
        ScanType.IP_PROTOCOL: lambda: w.scan_ip_protocol(req.target),
        ScanType.SERVICE: lambda: w.service_detection(req.target, req.ports or "1-1000"),
        ScanType.OS: lambda: w.os_detection(req.target),
        ScanType.SCRIPT_VULN: lambda: w.script_vuln(req.target, req.ports or ""
