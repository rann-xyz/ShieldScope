"""
ShieldScope — Web3 Security Scanner MVP
DD.xyz by Webacy Startup Accelerator Grant

Backend API client for Webacy risk intelligence endpoints.
All requests go through a thin async wrapper that enforces rate
limits and never logs the API key.
"""

from __future__ import annotations

import os
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ----- Configuration -----

def _get_api_key() -> Optional[str]:
    """Read the Webacy API key from environment — never log it."""
    return os.environ.get("WEBACITY_API_KEY") or os.environ.get("DDXYZ_API_KEY")

API_KEY = _get_api_key()
BASE_URL = "https://api.webacy.com"
DEFAULT_TIMEOUT = 30.0
DEFAULT_CHAIN = "eth"

# In-memory rate limiter (process-local — see README for distributed caveat)
_rate_buckets: Dict[str, list[float]] = {}
RATE_LIMIT_BUDGET = 10          # max requests
RATE_LIMIT_WINDOW = 60          # per 60 seconds


def _rate_ok(key: str) -> bool:
    now = time.time()
    bucket = _rate_buckets.setdefault(key, [])
    _rate_buckets[key] = [t for t in bucket if t > now - RATE_LIMIT_WINDOW]
    if len(_rate_buckets[key]) >= RATE_LIMIT_BUDGET:
        return False
    _rate_buckets[key].append(now)
    return True


# ----- Response models -----

@dataclass
class RiskReport:
    """Evidence-based risk report returned to the frontend."""
    target: str
    category: str               # wallet, contract, url
    raw: Dict[str, Any]
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    issues: list = field(default_factory=list)
    summary: str = ""
    evidence: list = field(default_factory=list)


class APIClient:
    """Async HTTP client for Webacy APIs.

    Fails closed: if the API key is missing or a request errors,
    :meth:`scan_*` raises or returns a *blocked* report so the
    frontend can show "not verified" rather than fake data.
    """

    def __init__(self, api_key: Optional[str] = None, base_url: str = BASE_URL):
        self.api_key = api_key or API_KEY
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

        if not self.api_key:
            import logging
            logger = logging.getLogger("shieldscope")
            logger.warning(
                "api_key_missing — API calls will return 'blocked' (fail-closed)"
            )

    async def _get_client(self) -> "httpx.AsyncClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, base_url=self.base_url)
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()

    def _headers(self) -> Dict[str, str]:
        return {"x-api-key": self.api_key} if self.api_key else {}

    def _blocked_report(self, target: str, category: str, detail: str) -> RiskReport:
        """Return a report explicitly marked BLOCKED — never fake a pass."""
        return RiskReport(
            target=target,
            category=category,
            raw={},
            risk_level="BLOCKED",
            summary=detail,
            evidence=[detail],
        )

    async def scan_wallet(self, address: str, chain: str = DEFAULT_CHAIN,
                          modules: Optional[list] = None) -> RiskReport:
        if not self.api_key:
            return self._blocked_report(address, "wallet",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.")

        if not _rate_ok("wallet"):
            return self._blocked_report(address, "wallet", "Rate limit exceeded. Try again later.")

        params: Dict[str, Any] = {"chain": chain}
        if modules:
            params["modules"] = ",".join(modules)
        url = f"/addresses/{address}"

        try:
            client = await self._get_client()
            resp = await client.get(url, headers=self._headers(), params=params)
            data = resp.json()
        except Exception as exc:
            return self._blocked_report(address, "wallet",
                f"Request failed: {exc.__class__.__name__}")

        score = data.get("overallRisk") or data.get("risk_score") or data.get("risk")
        level = _grade_to_level(score)
        issues = _extract_issues(data)
        evidence = _extract_evidence(data, issues)

        return RiskReport(
            target=address,
            category="wallet",
            raw=data,
            risk_score=score,
            risk_level=level,
            issues=issues,
            summary=f"Wallet analyzed on {chain}. Overall risk: {score}",
            evidence=evidence,
        )

    async def scan_contract(self, contract_address: str, chain: str = DEFAULT_CHAIN,
                            from_bytecode: bool = False) -> RiskReport:
        if not self.api_key:
            return self._blocked_report(contract_address, "contract",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.")

        if not _rate_ok("contract"):
            return self._blocked_report(contract_address, "contract", "Rate limit exceeded.")

        params: Dict[str, Any] = {"chain": chain}
        if from_bytecode:
            params["fromBytecode"] = "true"
        url = f"/contracts/{contract_address}"

        try:
            client = await self._get_client()
            resp = await client.get(url, headers=self._headers(), params=params)
            data = resp.json()
        except Exception as exc:
            return self._blocked_report(contract_address, "contract",
                f"Request failed: {exc.__class__.__name__}")

        score = data.get("risk_score") or data.get("overallRisk")
        level = _grade_to_level(score)
        issues = _extract_issues(data)
        evidence = _extract_evidence(data, issues)

        return RiskReport(
            target=contract_address,
            category="contract",
            raw=data,
            risk_score=score,
            risk_level=level,
            issues=issues,
            summary=f"Contract analyzed on {chain}. Overall risk: {score}",
            evidence=evidence,
        )

    async def scan_url(self, url_to_check: str) -> RiskReport:
        if not self.api_key:
            return self._blocked_report(url_to_check, "url",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.")

        if not _rate_ok("url"):
            return self._blocked_report(url_to_check, "url", "Rate limit exceeded.")

        # URL risk endpoint: POST body with {"url": "..."}
        try:
            client = await self._get_client()
            resp = await client.post(
                "/urls/risk",
                headers=self._headers(),
                json={"url": url_to_check},
            )
            data = resp.json()
        except Exception as exc:
            return self._blocked_report(url_to_check, "url",
                f"Request failed: {exc.__class__.__name__}")

        risk_level = data.get("riskLevel", "unknown")
        score = _level_to_score(risk_level)
        desc = data.get("description", "")
        evidence = [desc] if desc else ["No additional context returned"]

        return RiskReport(
            target=url_to_check,
            category="url",
            raw=data,
            risk_score=score,
            risk_level=risk_level.upper(),
            issues=[{"title": risk_level, "severity": risk_level}],
            summary=f"URL analyzed: risk level {risk_level}",
            evidence=evidence,
        )


# ----- Helpers -----

def _grade_to_level(score) -> Optional[str]:
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 80:
        return "HIGH"
    if s >= 50:
        return "MEDIUM"
    return "LOW"


def _level_to_score(level: str) -> Optional[float]:
    mapping = {"high": 90, "medium": 60, "low": 20, "unknown": 0}
    return mapping.get(level.lower())


def _extract_issues(data: dict) -> list:
    issues = []
    if data.get("issues"):
        raw_issues = data["issues"] if isinstance(data["issues"], list) else [data["issues"]]
        for i in raw_issues:
            title = i.get("title") or i.get("name") or i.get("label", "Issue")
            severity = i.get("severity", "medium")
            issues.append({"title": str(title), "severity": str(severity).lower()})
    elif data.get("risk_score") is not None:
        issues.append({"title": "Overall risk score", "severity": "info"})
    elif data.get("risk"):
        issues.append({"title": "Risk flagged", "severity": "medium"})
    return issues


def _extract_evidence(data: dict, issues: list) -> list:
    evidence = []
    # Pull descriptions from issues
    if data.get("issues"):
        for i in (data["issues"] if isinstance(data["issues"], list) else [data["issues"]]):
            desc = i.get("description") or i.get("detail", "")
            if desc:
                evidence.append(str(desc))
    # Pull from details dict
    details = data.get("details") or data.get("detail", {})
    if isinstance(details, dict):
        for k, v in list(details.items())[:5]:
            evidence.append(f"{k}: {v}")
    if not evidence and issues:
        evidence.append("Risk factors identified — see raw report for details.")
    if not evidence:
        evidence.append("No detailed evidence returned by provider.")
    return evidence


# Fallback logger if structlog isn't installed (dev-only)
def _fallback_logger():
    class L:
        def warning(self, *a, **kw): print("WARN", kw.get("msg", kw))
        def info(self, *a, **kw): pass
        def error(self, *a, **kw): print("ERR", kw)
    return L()

try:
    import structlog  # noqa
    _HAS_LOGGING = True
except ImportError:
    _HAS_LOGGING = False


# ----- Convenience: sync wrapper for quick tests -----

def scan_wallet_sync(address: str, chain: str = DEFAULT_CHAIN) -> RiskReport:
    """Quick synchronous scan for tests/dev. Returns blocked report if no event loop."""
    client = APIClient()
    if not client.api_key:
        return client._blocked_report(address, "wallet",
            "API key not configured. Set WEBACITY_API_KEY to enable live checks.")
    try:
        return asyncio.run(client.scan_wallet(address, chain))
    except asyncio.exceptions.InvalidStateError:
        return client._blocked_report(address, "wallet", "Cannot run async scan in sync context.")
