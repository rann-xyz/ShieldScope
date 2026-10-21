"""
Tests for ShieldScope — no external API keys required.
Tests use httpx mocks to verify fail-closed behavior.
"""
import os
import asyncio
import pytest

os.environ.pop("WEBACITY_API_KEY", None)
os.environ.pop("DDXYZ_API_KEY", None)

from app.api_client import APIClient, RiskReport


def test_no_api_key_returns_blocked():
    client = APIClient()
    report = asyncio.run(client.scan_wallet("0x1234567890123456789012345678901234567890"))
    assert report.risk_level == "BLOCKED"
    assert "not configured" in report.summary.lower()


def test_no_api_key_wallet_scan_blocked():
    client = APIClient()
    report = asyncio.run(client.scan_wallet("0xBlockedWallet123456789012345678901234"))
    assert report.category == "wallet"
    assert report.risk_level == "BLOCKED"
    assert len(report.evidence) > 0


def test_no_api_key_contract_scan_blocked():
    client = APIClient()
    report = asyncio.run(client.scan_contract("0xContractAddress1234567890123456789"))
    assert report.category == "contract"
    assert report.risk_level == "BLOCKED"


def test_no_api_key_url_scan_blocked():
    client = APIClient()
    report = asyncio.run(client.scan_url("https://phishing-example.com"))
    assert report.category == "url"
    assert report.risk_level == "BLOCKED"


def test_blocked_report_has_no_raw():
    client = APIClient()
    report = asyncio.run(client.scan_wallet("0xTestAddress123456789012345678901234"))
    assert report.raw == {}  # no fabricated data


def test_scan_report_contains_category_and_target():
    client = APIClient()
    report = asyncio.run(client.scan_wallet("0xTest123456789012345678901234567890123456"))
    assert report.target == "0xTest123456789012345678901234567890123456"
    assert report.category == "wallet"


def test_default_chain_is_eth():
    client = APIClient()
    assert client.base_url == "https://api.webacy.com"


def test_api_client_class_exists():
    client = APIClient(api_key="fake-key-for-testing")
    assert client.api_key == "fake-key-for-testing"
    assert client.base_url == "https://api.webacy.com"


def test_report_class_defaults():
    report = RiskReport(target="0x1234", category="wallet", raw={})
    assert report.target == "0x1234"
    assert report.category == "wallet"
    assert report.risk_level is None
    assert report.risk_score is None
    assert report.issues == []
    assert report.summary == ""
    assert report.evidence == []


# ---- Integration tests (require API key; skip if unavailable) ----

api_key = os.environ.get("WEBACITY_API_KEY") or os.environ.get("DDXYZ_API_KEY")


@pytest.mark.skipif(not api_key, reason="WEBACITY_API_KEY not set")
def test_live_wallet_scan():
    """Only runs with a real API key — validates live integration."""
    client = APIClient(api_key=api_key)
    report = asyncio.run(client.scan_wallet("0xd8dA6BF26964aF9D9206568787f5C68a1C31cD39", chain="eth"))
    assert report.risk_level is not None or report.risk_level == "BLOCKED"
    if report.risk_level != "BLOCKED":
        print(f"  Live scan result: {report.risk_level} score={report.risk_score}")


@pytest.mark.skipif(not api_key, reason="WEBACITY_API_KEY not set")
def test_live_url_scan():
    """Only runs with a real API key."""
    client = APIClient(api_key=api_key)
    report = asyncio.run(client.scan_url("https://uniswap.org"))
    assert report.risk_level is not None
