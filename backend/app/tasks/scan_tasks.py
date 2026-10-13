"""Celery tasks for Nmap scans."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_wrapper: Optional[object] = None


def get_wrapper():
    """Lazily instantiate the NmapWrapper (singleton per worker)."""
    global _wrapper
    if _wrapper is None:
        from tools.wrappers.nmap_wrapper import NmapWrapper
        _wrapper = NmapWrapper(binary_path="nmap")
    return _wrapper


def _dispatch_scan(w, target, scan_type, ports, custom_args, timing, scripts, script_args, exclude):
    """Route a scan_type string to the correct NmapWrapper method."""
    dispatch = {
        "host_discovery": lambda: w.host_discovery(target),
        "ping_sweep": lambda: w.ping_sweep(target),
        "arp_scan": lambda: w.arp_scan(target),
        "tcp_syn": lambda: w.scan_tcp_syn(target, ports),
        "tcp_connect": lambda: w.scan_tcp_connect(target, ports),
        "tcp_ack": lambda: w.scan_tcp_ack(target, ports),
        "tcp_fin": lambda: w.scan_tcp_fin(target, ports),
        "tcp_null": lambda: w.scan_tcp_null(target, ports),
        "tcp_xmas": lambda: w.scan_tcp_xmas(target, ports),
        "udp": lambda: w.scan_udp(target, ports),
        "sctp_init": lambda: w.scan_sctp_init(target, ports),
        "ip_protocol": lambda: w.scan_ip_protocol(target),
        "service": lambda: w.service_detection(target, ports),
        "os": lambda: w.os_detection(target),
        "script_vuln": lambda: w.script_vuln(target, ports),
        "script_auth": lambda: w.script_auth(target, ports),
        "script_brute": lambda: w.script_brute(target, ports),
        "script_discovery": lambda: w.script_discovery(target, ports),
        "script_exploit": lambda: w.script_exploit(target, ports),
        "quick": lambda: w.scan_fast(target),
        "full": lambda: w.scan_all_ports(target),
        "aggressive": lambda: w.aggressive_scan(target),
        "intense": lambda: w.intense_scan(target),
        "comprehensive": lambda: w.comprehensive_scan(target),
        "stealth": lambda: w.stealth_scan(target, ports),
        "pentest": lambda: w.pentest_scan(target),
        "traceroute": lambda: w.traceroute(target, ports),
        "custom": lambda: w.run(target, custom_args or "-sV"),
    }
    fn = dispatch.get(scan_type)
    if fn is None:
        raise ValueError(f"Unknown scan type: {scan_type}")
    return fn()


def _persist_results(scan_id, result):
    """
    Persist scan results to the database.

    If the DB session or repository is unavailable, log a warning
    and return gracefully so the Celery task does not fail.
    """
    try:
        from app.db.session import SessionLocal
        from app.db.repositories.scan_repo import ScanRepository

        db = SessionLocal()
        try:
            ScanRepository.complete(db, scan_id, result)
            logger.info(f"[scan_tasks] Persisted scan {scan_id} to DB")
        finally:
            db.close()
    except ImportError as e:
        logger.warning(f"[scan_tasks] DB modules not available, skipping persist: {e}")
    except Exception as e:
        logger.error(f"[scan_tasks] DB persist failed for {scan_id}: {e}", exc_info=True)


# ─── Celery task registration ────────────────────────────────
try:
    from celery import shared_task

    @shared_task(bind=True, max_retries=2, default_retry_delay=30)
    def run_nmap_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str] = None,
        custom_args: Optional[str] = None,
        timing: Optional[str] = None,
        scripts: Optional[list] = None,
        script_args: Optional[dict] = None,
        exclude: Optional[str] = None,
    ):
        """Async Celery task for running an Nmap scan and saving results."""
        w = get_wrapper()
        ports = ports or "1-1000"

        try:
            result = _dispatch_scan(
                w, target, scan_type, ports,
                custom_args, timing, scripts, script_args, exclude,
            )
            _persist_results(scan_id, result)

            return {
                "scan_id": scan_id,
                "success": result.success,
                "hosts_count": len(result.hosts),
                "elapsed": result.elapsed,
                "error": result.error,
            }
        except ValueError as e:
            logger.error(f"[scan_tasks] Invalid scan_type for {scan_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"[scan_tasks] Scan {scan_id} failed: {e}", exc_info=True)
            raise self.retry(exc=e)

except ImportError:
    # Celery not installed — provide a synchronous fallback.
    # Useful for tests and local dev without a broker.
    def run_nmap_scan(
        scan_id: str,
        target: str,
        scan_type: str,
        ports: Optional[str] = None,
        custom_args: Optional[str] = None,
        timing: Optional[str] = None,
        scripts: Optional[list] = None,
        script_args: Optional[dict] = None,
        exclude: Optional[str] = None,
    ):
        """Synchronous fallback when Celery is not installed."""
        w = get_wrapper()
        ports = ports or "1-1000"

        result = _dispatch_scan(
            w, target, scan_type, ports,
            custom_args, timing, scripts, script_args, exclude,
        )
        _persist_results(scan_id, result)

        return {
            "scan_id": scan_id,
            "success": result.success,
            "hosts_count": len(result.hosts),
            "elapsed": result.elapsed,
            "error": result.error,
        }
