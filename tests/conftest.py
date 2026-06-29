"""Pytest configuration — in-memory SQLite for contract tests."""

import os

os.environ.setdefault("SHIELDSCAN_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SCANNER_MODE", "builtin")
os.environ.setdefault("ZAP_API_KEY", "changeme")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app


@pytest.fixture(autouse=True)
def _init_database():
    init_db()
    yield


@pytest.fixture
def client():
    return TestClient(app)
