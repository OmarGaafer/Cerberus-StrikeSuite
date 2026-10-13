"""Database models for Nmap scan results."""
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.db.models.base import Base


class Scan(Base):
    """Represents a single Nmap scan."""
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)
    command = Column(Text)
    status = Column(String(50), default="pending", index=True)  # pending|running|completed|failed
    success = Column(Boolean, default=False)
    error = Column(Text)
    elapsed = Column(Float, default=0.0)
    nmap_version = Column(String(50))
    raw_xml = Column(Text)
    raw_text = Column(Text)

    engagement_id = Column(UUID(as_uuid=True), ForeignKey("engagements.id"), nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    hosts = relationship("ScanHost", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target_type", "target", "scan_type"),
    )


class ScanHost(Base):
    """A host discovered during a scan."""
    __tablename__ = "scan_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17))
    vendor = Column(String(255))
    hostname = Column(String(255))
    state = Column(String(20), default="unknown")
    uptime = Column(String(50))
    distance = Column(String(20))
    os_matches = Column(JSON, default=list)
    host_scripts = Column(JSON, default=dict)
    traceroute = Column(JSON, default=list)

    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("ScanPort", back_populates="host", cascade="all, delete-orphan")


class ScanPort(Base):
    """A port discovered on a host."""
    __tablename__ = "scan_ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("scan_hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), nullable=False)
    state = Column(String(20), nullable=False, index=True)
    reason = Column(String(50))
    service = Column(String(100))
    product = Column(String(255))
    version = Column(String(255))
    extrainfo = Column(String(255))
    cpe = Column(JSON, default=list)
    scripts = Column(JSON, default=dict)

    host = relationship("ScanHost", back_populates="ports")
