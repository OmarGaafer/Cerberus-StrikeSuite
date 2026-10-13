"""Repository for Scan-related DB operations (sync)."""
from typing import Optional, List
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models.scan import Scan, ScanHost, ScanPort


class ScanRepository:
    @staticmethod
    def create(db: Session, scan_id: str, target: str, scan_type: str,
               command: str = "", engagement_id: Optional[UUID] = None,
               created_by: Optional[UUID] = None) -> Scan:
        scan = Scan(
            id=scan_id, target=target, scan_type=scan_type, command=command,
            status="running", engagement_id=engagement_id, created_by=created_by,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def complete(db: Session, scan_id: str, result) -> Optional[Scan]:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = "completed" if result.success else "failed"
        scan.success = result.success
        scan.error = result.error
        scan.elapsed = result.elapsed
        scan.nmap_version = result.nmap_version
        scan.raw_xml = result.raw_xml
        scan.raw_text = result.raw_text
        for h in result.hosts:
            host = ScanHost(
                scan_id=scan.id, ip=h.ip, mac=h.mac, vendor=h.vendor,
                hostname=h.hostname, state=h.state, uptime=h.uptime,
                distance=h.distance, os_matches=h.os_matches,
                host_scripts=h.host_scripts, traceroute=h.traceroute,
            )
            db.add(host)
            db.flush()
            for p in h.ports:
                port = ScanPort(
                    host_id=host.id, port=p.port, protocol=p.protocol,
                    state=p.state, reason=p.reason, service=p.service,
                    product=p.product, version=p.version, extrainfo=p.extrainfo,
                    cpe=p.cpe, scripts=p.scripts,
                )
                db.add(port)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def get(db: Session, scan_id: str) -> Optional[Scan]:
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def list_by_engagement(db: Session, engagement_id: UUID) -> List[Scan]:
        return (db.query(Scan).filter(Scan.engagement_id == engagement_id)
                .order_by(Scan.created_at.desc()).all())

    @staticmethod
    def list_recent(db: Session, limit: int = 50) -> List[Scan]:
        return db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()

    @staticmethod
    def delete(db: Session, scan_id: str) -> bool:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True
