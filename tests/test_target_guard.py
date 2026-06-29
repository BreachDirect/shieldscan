"""Target guard unit tests."""

import pytest
from fastapi import HTTPException

from app.services.target_guard import validate_scan_request


def test_rejects_unauthorised():
    with pytest.raises(HTTPException) as exc:
        validate_scan_request("http://example.com", authorised=False)
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "AUTHORISATION_REQUIRED"


def test_normalises_url_without_scheme():
    url = validate_scan_request("127.0.0.1:4280", authorised=True)
    assert url == "http://127.0.0.1:4280"


def test_blocks_file_scheme():
    with pytest.raises(HTTPException) as exc:
        validate_scan_request("file:///etc/passwd", authorised=True)
    assert exc.value.detail["code"] == "TARGET_NOT_ALLOWED"
