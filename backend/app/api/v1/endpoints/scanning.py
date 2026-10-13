"""REST API endpoints for Nmap scanning."""
from fastapi import APIRouter, HTTPException, status, Depends
import uuid
import sys
import os

_project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "..")
)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.schemas.scan import ScanRequest, ScanType
from app.db.session import get_db
from app.db.repositories.scan_repo import ScanRepository
from tools.wrappers.nmap_wrapper import NmapWrapper

router = APIRouter(prefix="/scanning", tags=["Scanning"])


@router.get("/types/available")
async def list_scan_types():
    """List all supported scan types."""
    return [s.value for s in ScanType]


@router.post("/nmap")
async def start_nmap_scan(req: ScanRequest, db=Depends(get_db)):
    """Start an Nmap scan synchronously and store results."""
    if not req.roe_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rules of Engagement must be acknowledged",
        )

    scan_id = str(uuid.uuid4())

    # Create initial DB record (best-effort)
    try:
        ScanRepository.create(db, scan_id, req.target, req.scan_type.value)
    except Exception:
        pass

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
        ScanType.SCRIPT_VULN: lambda: w.script_vuln(req.target, req.ports or ""),
        ScanType.SCRIPT_AUTH: lambda: w.script_auth(req.target, req.ports or ""),
        ScanType.SCRIPT_BRUTE: lambda: w.script_brute(req.target, req.ports or ""),
        ScanType.SCRIPT_DISCOVERY: lambda: w.script_discovery(req.target, req.ports or ""),
        ScanType.SCRIPT_EXPLOIT: lambda: w.script_exploit(req.target, req.ports or ""),
        ScanType.QUICK: lambda: w.scan_fast(req.target),
        ScanType.FULL: lambda: w.scan_all_ports(req.target),
        ScanType.AGGRESSIVE: lambda: w.aggressive_scan(req.target),
        ScanType.INTENSE: lambda: w.intense_scan(req.target),
        ScanType.COMPREHENSIVE: lambda: w.comprehensive_scan(req.target),
        ScanType.STEALTH: lambda: w.stealth_scan(req.target, req.ports or "1-1000"),
        ScanType.PENTEST: lambda: w.pentest_scan(req.target),
        ScanType.TRACEROUTE: lambda: w.traceroute(req.target, req.ports or "80,443"),
        ScanType.CUSTOM: lambda: w.run(req.target, req.custom_args or "-sV"),
    }

    fn = dispatch.get(req.scan_type)
    if fn is None:
        raise HTTPException(400, f"Unsupported scan type: {req.scan_type}")

    result = fn()

    # Persist full results
    try:
        ScanRepository.complete(db, scan_id, result)
    except Exception:
        pass

    return {
        "scan_id": scan_id,
        "status": "completed" if result.success else "failed",
        "target": req.target,
        "command": result.command,
        "elapsed": result.elapsed,
        "nmap_version": result.nmap_version,
        "hosts_count": len(result.hosts),
        "error": result.error,
        "hosts": [
            {
                "ip": h.ip, "mac": h.mac, "vendor": h.vendor,
                "hostname": h.hostname, "state": h.state,
                "os_matches": h.os_matches,
                "ports": [
                    {"port": p.port, "protocol": p.protocol, "state": p.state,
                     "reason": p.reason, "service": p.service, "product": p.product,
                     "version": p.version, "extrainfo": p.extrainfo,
                     "cpe": p.cpe, "scripts": p.scripts}
                    for p in h.ports
                ],
                "host_scripts": h.host_scripts,
                "traceroute": h.traceroute,
            }
            for h in result.hosts
        ],
    }


@router.get("/")
async def list_scans(limit: int = 50, db=Depends(get_db)):
    """List recent scans."""
    scans = ScanRepository.list_recent(db, limit)
    return [
        {
            "scan_id": str(s.id),
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db=Depends(get_db)):
    """Get scan results by ID."""
    scan = ScanRepository.get(db, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": str(scan.id),
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "success": scan.success,
        "elapsed": scan.elapsed,
        "hosts_count": len(scan.hosts),
    }
