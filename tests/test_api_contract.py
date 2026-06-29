"""API contract tests — stable error envelope (Drips Wave #159)."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _error_code(resp) -> str:
    return resp.json()["error"]["code"]


def test_validation_error_envelope():
    resp = client.post("/api/scans", json={"target_url": "ab"})
    assert resp.status_code == 422
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "message" in body["error"]
    assert "details" in body["error"]


def test_authorisation_required_error():
    resp = client.post(
        "/api/scans",
        json={"target_url": "http://127.0.0.1:4280", "authorised": False},
    )
    assert resp.status_code == 400
    assert _error_code(resp) == "AUTHORISATION_REQUIRED"


def test_not_found_error():
    resp = client.get("/api/scans/99999")
    assert resp.status_code == 404
    assert _error_code(resp) == "NOT_FOUND"


def test_create_scan_success_envelope():
    resp = client.post(
        "/api/scans",
        json={"target_url": "http://127.0.0.1:4280", "authorised": True},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["target_url"] == "http://127.0.0.1:4280"
    assert data["status"] == "queued"
    assert "id" in data


def test_list_scans_returns_array():
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_report_not_found_error():
    resp = client.get("/api/scans/99999/report/download")
    assert resp.status_code == 404
    assert _error_code(resp) == "NOT_FOUND"
