"""Health and readiness endpoint tests (Drips Wave #1034)."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "shieldscan"
    assert data["phase"] == 1
    assert data["scanner_version"] == "3.0"
    assert data["wave_program"] == "Stellar Wave 6"
    assert len(data["checks"]) >= 5


def test_ready_returns_database_ok():
    resp = client.get("/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["database"] == "ok"
