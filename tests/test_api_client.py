"""
Comprehensive tests for ShieldScope API client.

Tests use httpx.mock_transport to simulate HTTP responses — no real API
calls are made. Every test uses a fake API key to isolate HTTP behavior.

Tested scenarios:
- Missing credentials (fail-closed BLOCKED)
- Successful 200 responses (wallet, contract, URL)
- Authentication errors (401)
- Permission errors (403)
- Rate limit errors (429)
- Timeouts
- Malformed JSON responses
- Rate limiting (in-memory)
- Endpoint/path verification
"""
import os
import asyncio
import json
import pytest
import httpx

# Ensure tests run without real credentials
os.environ.pop("WEBACITY_API_KEY", None)
os.environ.pop("DDXYZ_API_KEY", None)

from app.api_client import APIClient, RiskReport, BASE_URL, DEFAULT_CHAIN, _rate_buckets


FAKE_KEY = "test-api-key-for-shieldscope-mvp"


def make_client(api_key=FAKE_KEY, transport=None):
    """Create a client with mocked transport."""
    if transport is None:
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json={}))
    client = APIClient(api_key=api_key)
    client._client = httpx.AsyncClient(transport=transport, base_url=BASE_URL)
    return client


def _ok_handler(json_data=None):
    """Handler returning a 200 with optional JSON."""
    def handler(req):
        return httpx.Response(200, json=json_data or {}, request=req)
    return handler


# ===== Test: Missing credentials (fail-closed) =====

def test_no_api_key_returns_blocked():
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_wallet("0x1234567890123456789012345678901234567890"))
    assert report.risk_level == "BLOCKED"
    assert "not configured" in report.summary.lower()


def test_no_api_key_wallet_scan_blocked():
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_wallet("0xBlockedWallet123456789012345678901234"))
    assert report.category == "wallet"
    assert report.risk_level == "BLOCKED"
    assert len(report.evidence) > 0


def test_no_api_key_contract_scan_blocked():
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_contract("0xContractAddress1234567890123456789"))
    assert report.category == "contract"
    assert report.risk_level == "BLOCKED"


def test_no_api_key_url_scan_blocked():
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_url("https://phishing-example.com"))
    assert report.category == "url"
    assert report.risk_level == "BLOCKED"


def test_blocked_report_has_no_raw():
    """Blocked reports never include raw API data."""
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_wallet("0xTestAddress123456789012345678901234"))
    assert report.raw == {}


def test_blocked_report_has_evidence():
    client = APIClient(api_key=None)
    report = asyncio.run(client.scan_wallet("0xTestAddress123456789012345678901234"))
    assert report.evidence
    assert "configured" in report.evidence[0].lower()


# ===== Test: Endpoint verification =====

class TestEndpoints:
    def test_wallet_uses_get_addresses(self):
        """Verify GET /addresses/{address}?chain=...&modules=..."""
        captured = {}
        def handler(req):
            captured["method"] = req.method
            captured["path"] = req.url.path
            captured["params"] = dict(req.url.params)
            captured["headers"] = dict(req.headers)
            return httpx.Response(200, json={"overallRisk": 10}, request=req)

        client = make_client(transport=httpx.MockTransport(handler))
        asyncio.run(client.scan_wallet(
            "0xabcdef123456789012345678901234567890abcdef",
            chain="base",
            modules=["sanctions_compliance", "fraud_detection"],
        ))
        assert captured["method"] == "GET"
        assert captured["path"] == "/addresses/0xabcdef123456789012345678901234567890abcdef"
        assert captured["params"]["chain"] == "base"
        assert "sanctions_compliance" in captured["params"]["modules"]
        assert captured["headers"]["x-api-key"] == FAKE_KEY

    def test_contract_uses_get_contracts(self):
        """Verify GET /contracts/{address}?chain=...&fromBytecode=true"""
        captured = {}
        def handler(req):
            captured["method"] = req.method
            captured["path"] = req.url.path
            captured["params"] = dict(req.url.params)
            return httpx.Response(200, json={"risk_score": 30}, request=req)

        client = make_client(transport=httpx.MockTransport(handler))
        asyncio.run(client.scan_contract("0xContract", chain="eth", from_bytecode=True))
        assert captured["method"] == "GET"
        assert captured["path"] == "/contracts/0xContract"
        assert captured["params"]["chain"] == "eth"
        assert captured["params"]["fromBytecode"] == "true"

    def test_contract_no_from_bytecode_param(self):
        captured = {}
        def handler(req):
            captured["params"] = dict(req.url.params)
            return httpx.Response(200, json={"risk_score": 20}, request=req)
        client = make_client(transport=httpx.MockTransport(handler))
        asyncio.run(client.scan_contract("0xC1", chain="eth"))
        assert "fromBytecode" not in captured["params"]

    def test_url_uses_post_url_with_body(self):
        """Verify POST /url with JSON body {"url": "..."}."""
        captured = {}
        def handler(req):
            captured["method"] = req.method
            captured["path"] = req.url.path
            captured["body"] = json.loads(req.content)
            captured["headers"] = dict(req.headers)
            return httpx.Response(200, json={"riskLevel": "low"}, request=req)

        client = make_client(transport=httpx.MockTransport(handler))
        asyncio.run(client.scan_url("https://uniswap.org"))
        assert captured["method"] == "POST"
        assert captured["path"] == "/url"
        assert captured["body"]["url"] == "https://uniswap.org"
        assert captured["headers"]["x-api-key"] == FAKE_KEY


# ===== Test: Successful responses =====

class TestWalletScanSuccess:
    def test_high_risk_wallet(self):
        client = make_client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={
                "overallRisk": 85.5,
                "addressType": "EOA",
                "issues": [{"title": "Sanctioned address", "severity": "high", "description": "OFAC SDN list"}],
                "details": {"chain": "eth", "balance": "1.23 ETH"},
            }, request=req)))
        report = asyncio.run(client.scan_wallet("0x1234567890123456789012345678901234567890", chain="eth"))
        assert report.risk_score == 85.5
        assert report.risk_level == "HIGH"
        assert report.category == "wallet"
        assert len(report.issues) == 1
        assert "OFAC" in report.evidence[0]

    def test_low_risk_wallet(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({"overallRisk": 5, "issues": []})))
        report = asyncio.run(client.scan_wallet("0xlow", chain="eth"))
        assert report.risk_level == "LOW"

    def test_no_issues_extracted(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({"overallRisk": 0, "issues": []})))
        report = asyncio.run(client.scan_wallet("0xclean", chain="eth"))
        assert len(report.issues) == 0
        assert report.risk_level == "LOW"


class TestContractScanSuccess:
    def test_medium_risk_contract(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({
            "risk_score": 72,
            "issues": [{"title": "Unverified source", "severity": "medium"}],
            "details": {"owner": "0xowner", "verified": False},
        })))
        report = asyncio.run(client.scan_contract("0xContractAddr12345678901234567890", chain="eth"))
        assert report.risk_score == 72
        assert report.risk_level == "MEDIUM"
        assert report.category == "contract"


class TestUrlScanSuccess:
    def test_high_risk_url(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({
            "riskLevel": "high",
            "description": "Known phishing site impersonating Uniswap",
        })))
        report = asyncio.run(client.scan_url("https://fake-uniswap.com"))
        assert report.risk_level == "HIGH"
        assert report.risk_score == 90
        assert report.category == "url"
        assert "phishing" in report.evidence[0].lower()

    def test_low_risk_url(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({
            "riskLevel": "low",
            "description": "Known safe domain",
        })))
        report = asyncio.run(client.scan_url("https://example.com"))
        assert report.risk_level == "LOW"
        assert report.risk_score == 20

    def test_unknown_url(self):
        client = make_client(transport=httpx.MockTransport(_ok_handler({
            "riskLevel": "unknown",
            "description": "No verdict available",
        })))
        report = asyncio.run(client.scan_url("https://random-new-site.com"))
        assert report.risk_level == "UNKNOWN"
        assert report.risk_score == 0


# ===== Test: Error handling (fail-closed) =====

class TestErrorHandling:
    def test_401_authentication_error(self):
        def handler(req):
            raise httpx.HTTPStatusError("Unauthorized", request=req, response=httpx.Response(401, request=req))
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "auth" in report.summary.lower()

    def test_403_forbidden_error(self):
        def handler(req):
            raise httpx.HTTPStatusError("Forbidden", request=req, response=httpx.Response(403, request=req))
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "forbidden" in report.summary.lower()

    def test_429_rate_limited(self):
        def handler(req):
            raise httpx.HTTPStatusError("Rate limited", request=req, response=httpx.Response(429, request=req))
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "rate limit" in report.summary.lower()

    def test_500_server_error(self):
        def handler(req):
            raise httpx.HTTPStatusError("Server error", request=req, response=httpx.Response(500, request=req))
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "500" in report.summary

    def test_timeout_error(self):
        def handler(req):
            raise httpx.TimeoutException("timeout", request=req)
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "timed out" in report.summary.lower()

    def test_malformed_json(self):
        def handler(req):
            return httpx.Response(200, content="not json at all", request=req)
        client = make_client(transport=httpx.MockTransport(handler))
        report = asyncio.run(client.scan_wallet("0xaddr", chain="eth"))
        assert report.risk_level == "BLOCKED"


# ===== Test: Rate limiting (in-memory) =====

@pytest.fixture(autouse=True)
def clear_rate_buckets():
    _rate_buckets.clear()
    yield
    _rate_buckets.clear()


class TestRateLimiting:
    def test_rate_limit_triggers_blocked(self):
        """After 10 requests, rate limiter kicks in."""
        client = make_client(transport=httpx.MockTransport(_ok_handler({"overallRisk": 10})))

        for i in range(10):
            report = asyncio.run(client.scan_wallet(f"0x{i:040d}", chain="eth"))
            assert report.risk_level != "BLOCKED", f"Request {i+1} should succeed"

        report = asyncio.run(client.scan_wallet("0xff" + "0" * 38, chain="eth"))
        assert report.risk_level == "BLOCKED"
        assert "rate limit" in report.summary.lower()


# ===== Test: Dataclass defaults =====

class TestRiskReportDefaults:
    def test_defaults(self):
        r = RiskReport(target="0x1234", category="wallet", raw={})
        assert r.target == "0x1234"
        assert r.category == "wallet"
        assert r.raw == {}
        assert r.risk_score is None
        assert r.risk_level is None
        assert r.issues == []
        assert r.summary == ""
        assert r.evidence == []


# ===== Test: Config / constants =====

class TestConfig:
    def test_base_url(self):
        assert BASE_URL == "https://api.webacy.com"

    def test_default_chain(self):
        assert DEFAULT_CHAIN == "eth"

    def test_client_uses_api_key(self):
        c = APIClient(api_key="my-key")
        assert c.api_key == "my-key"

    def test_headers_contain_api_key(self):
        c = APIClient(api_key="secret-key")
        headers = c._headers()
        assert headers == {"x-api-key": "secret-key"}

    def test_headers_empty_without_key(self):
        c = APIClient(api_key=None)
        assert c._headers() == {}


# ===== Integration tests (require real API key; skip if unavailable) =====

api_key = os.environ.get("WEBACITY_API_KEY") or os.environ.get("DDXYZ_API_KEY")


@pytest.mark.skipif(not api_key, reason="WEBACITY_API_KEY not set")
def test_live_wallet_scan():
    """Only runs with a real API key — validates live integration."""
    client = APIClient(api_key=api_key)
    report = asyncio.run(client.scan_wallet("0xd8dA6BF26964aF9D9206568787f5C68a1C31cD39", chain="eth"))
    assert report.risk_level is not None


@pytest.mark.skipif(not api_key, reason="WEBACITY_API_KEY not set")
def test_live_url_scan():
    """Only runs with a real API key."""
    client = APIClient(api_key=api_key)
    report = asyncio.run(client.scan_url("https://uniswap.org"))
    assert report.risk_level is not None
