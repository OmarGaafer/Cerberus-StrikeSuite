import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


def test_list_scan_types(client):
    r = client.get("/api/v1/scanning/types/available")
    assert r.status_code == 200
    assert "quick" in r.json()


def test_scan_requires_roe(client):
    r = client.post("/api/v1/scanning/nmap", json={
        "target": "scanme.nmap.org",
        "scan_type": "quick",
        "roe_acknowledged": False,
    })
    assert r.status_code == 400
