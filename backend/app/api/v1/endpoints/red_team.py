"""
Red Team Endpoints — Controlled proof-of-concept vulnerability validation.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.network_tools import NetworkTools
from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.red_team import (
    RedTeamCompletionResponse,
    RedTeamFindingResponse,
    RedTeamStartResponse,
    RedTeamStatusResponse,
)
from app.services.red_team_service import RedTeamService

router = APIRouter()


# ─── Red Team Lifecycle ───────────────────────────────────

@router.post("/{engagement_id}/start", response_model=RedTeamStartResponse)
async def start_red_team(
    engagement_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start Red Team execution."""
    red_team_service = RedTeamService(db)
    return await red_team_service.start_execution(engagement_id, current_user.id)


@router.get("/{engagement_id}/status", response_model=RedTeamStatusResponse)
async def get_status(
    engagement_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current Red Team execution status."""
    red_team_service = RedTeamService(db)
    return await red_team_service.get_status(engagement_id, current_user.id)


@router.get("/{engagement_id}/findings", response_model=list[RedTeamFindingResponse])
async def get_findings(
    engagement_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all confirmed vulnerabilities from Red Team execution."""
    red_team_service = RedTeamService(db)
    return await red_team_service.get_findings(engagement_id, current_user.id)


@router.post("/{engagement_id}/complete", response_model=RedTeamCompletionResponse)
async def complete_red_team(
    engagement_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark the Red Team phase as complete and proceed to risk assessment."""
    red_team_service = RedTeamService(db)
    return await red_team_service.complete(engagement_id, current_user.id)


# ─── Network Reconnaissance (Scapy-powered) ──────────────

class ArpScanRequest(BaseModel):
    ip_range: str

class PingRequest(BaseModel):
    target: str

class PortScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None


@router.post("/network/arp-scan", summary="ARP scan for live hosts")
async def arp_scan_endpoint(
    payload: ArpScanRequest,
    current_user: User = Depends(get_current_user),
):
    """Discover live hosts on a local network using ARP."""
    tools = NetworkTools()
    return await tools.discover_network(payload.ip_range)


@router.post("/network/ping", summary="ICMP ping a host")
async def ping_endpoint(
    payload: PingRequest,
    current_user: User = Depends(get_current_user),
):
    """Check if a host is alive using ICMP echo request."""
    tools = NetworkTools()
    return await tools.ping_host(payload.target)


@router.post("/network/port-scan", summary="TCP SYN port scan")
async def port_scan_endpoint(
    payload: PortScanRequest,
    current_user: User = Depends(get_current_user),
):
    """Scan target ports using TCP SYN (half-open) scan."""
    tools = NetworkTools()
    return await tools.scan_ports(payload.target, payload.ports)


@router.post("/network/traceroute", summary="Trace network route")
async def traceroute_endpoint(
    payload: PingRequest,
    current_user: User = Depends(get_current_user),
):
    """Trace the network path to a target using ICMP TTL manipulation."""
    tools = NetworkTools()
    return await tools.trace_route(payload.target)