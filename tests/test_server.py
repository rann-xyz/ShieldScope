"""
Integration tests for the FastAPI server.
Uses TestClient — no external API calls.
"""
import os
os.environ.pop("WEBACITY_API_KEY", None)
os.environ.pop("DDXYZ_API_KEY", None)

import pytest
from fastapi.testclient import TestClient
from app.server import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "environment" in data


def test_config_endpoint_no_api_key(client):
    resp = client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert data["apiConfigured"] is False


def test_scan_wallet_requires_address(client):
    resp = client.post("/api/scan/wallet", json={"chain": "eth"})
    assert resp.status_code == 400


def test_scan_wallet_blocked_without_api_key(client):
    resp = client.post("/api/scan/wallet", json={
        "address": "0x1234567890123456789012345678901234567890",
        "chain": "eth"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "BLOCKED"
    assert "not configured" in data["summary"].lower()


def test_scan_contract_blocked_without_api_key(client):
    resp = client.post("/api/scan/contract", json={
        "contract_address": "0x1234567890123456789012345678901234567890",
        "chain": "eth"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "BLOCKED"


def test_scan_url_blocked_without_api_key(client):
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "BLOCKED"


def test_scan_url_requires_url(client):
    resp = client.post("/api/scan/url", json={})
    assert resp.status_code == 400


def test_report_structure(client):
    resp = client.post("/api/scan/wallet", json={
        "address": "0x1234567890123456789012345678901234567890"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "target" in data
    assert "category" in data
    assert "risk_level" in data
    assert "risk_score" in data
    assert "summary" in data
    assert "issues" in data
    assert "evidence" in data
    assert isinstance(data["issues"], list)
    assert isinstance(data["evidence"], list)
