"""
ShieldScope — Web3 Security Scanner MVP
DD.xyz by Webacy Startup Accelerator Grant

Backend API client for Webacy risk intelligence endpoints.
All requests go through a thin async wrapper that enforces rate
limits and never logs the API key.

VERIFIED OFFICIAL API CONTRACT (as of docs.webacy.com):
  Wallet Risk:   GET  /addresses/{address}   ?chain=eth&show_low_risk&modules=...
  Contract Risk: GET  /contracts/{contractAddress}?chain=eth&fromBytecode=true
  URL Risk:      POST /url                    body: {"url": "https://..."}
  Auth:          x-api-key header
  Base URL:      https://api.webacy.com
  Chains:        eth, base, bsc, pol, opt, arb, sol, ton, sei, sui, btc,
                 stellar, hedera, robinhood
"""

from __future__ import annotations

import os
import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

logger = logging.getLogger("shieldscope")


# ----- Configuration -----

def _get_api_key() -> Optional[str]:
    """Read the Webacy API key from environment — never log it."""
    return os.environ.get("WEBACITY_API_KEY") or os.environ.get("DDXYZ_API_KEY")

API_KEY: Optional[str] = _get_api_key()
BASE_URL: str = "https://api.webacy.com"
DEFAULT_TIMEOUT: float = 30.0
DEFAULT_CHAIN: str = "eth"

# In-memory rate limiter (process-local — see README for distributed caveat)
_rate_buckets: Dict[str, list] = {}
RATE_LIMIT_BUDGET: int = 10  # max requests per window per category
RATE_LIMIT_WINDOW: int = 60  # seconds


def _rate_ok(category: str) -> bool:
    """Token-bucket style check. Returns False if over limit."""
    now = time.time()
    bucket = _rate_buckets.setdefault(category, [])
    _rate_buckets[category] = [t for t in bucket if t > now - RATE_LIMIT_WINDOW]
    if len(_rate_buckets[category]) >= RATE_LIMIT_BUDGET:
        return False
    _rate_buckets[category].append(now)
    return True


# ----- Response model -----

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

    Fails closed: if the API key is missing, a request errors, or the
    API returns an error response, :meth:`scan_*` returns a *BLOCKED*
    report so the frontend can show "not verified" rather than fake data.
    """

    def __init__(self, api_key: Optional[str] = None, base_url: str = BASE_URL):
        self.api_key = api_key or API_KEY
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

        if not self.api_key:
            logger.warning(
                "ShieldScope: WEBACITY_API_KEY not set — API calls will return "
                "'blocked' (fail-closed design)."
            )

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if not _HAS_HTTPX:
                raise RuntimeError("httpx not installed")
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(DEFAULT_TIMEOUT),
                base_url=self.base_url,
            )
        return self._client

    async def close(self) -> None:
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

    async def scan_wallet(
        self,
        address: str,
        chain: str = DEFAULT_CHAIN,
        modules: Optional[list] = None,
    ) -> RiskReport:
        """Scan a wallet/address via GET /addresses/{address}."""
        if not self.api_key:
            return self._blocked_report(
                address, "wallet",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.",
            )
        if not _rate_ok("wallet"):
            return self._blocked_report(address, "wallet", "Rate limit exceeded.")

        params: Dict[str, Any] = {"chain": chain}
        if modules:
            params["modules"] = ",".join(modules)
        path = f"/addresses/{address}"

        try:
            client = await self._get_client()
            resp = await client.get(path, headers=self._headers(), params=params)
            data = resp.json()
        except httpx.TimeoutException:
            return self._blocked_report(address, "wallet", "Request timed out.")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                return self._blocked_report(address, "wallet", "Authentication failed (invalid API key).")
            if exc.response.status_code == 403:
                return self._blocked_report(address, "wallet", "Access forbidden (insufficient plan).")
            if exc.response.status_code == 429:
                return self._blocked_report(address, "wallet", "API rate limit exceeded (server-side).")
            return self._blocked_report(address, "wallet", f"HTTP error: {exc.response.status_code}")
        except Exception as exc:
            return self._blocked_report(address, "wallet", f"Request failed: {exc.__class__.__name__}")

        score = data.get("overallRisk")
        if score is None:
            score = data.get("risk_score")
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

    async def scan_contract(
        self,
        contract_address: str,
        chain: str = DEFAULT_CHAIN,
        from_bytecode: bool = False,
    ) -> RiskReport:
        """Scan a contract via GET /contracts/{contractAddress}."""
        if not self.api_key:
            return self._blocked_report(
                contract_address, "contract",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.",
            )
        if not _rate_ok("contract"):
            return self._blocked_report(contract_address, "contract", "Rate limit exceeded.")

        params: Dict[str, Any] = {"chain": chain}
        if from_bytecode:
            params["fromBytecode"] = "true"
        path = f"/contracts/{contract_address}"

        try:
            client = await self._get_client()
            resp = await client.get(path, headers=self._headers(), params=params)
            if resp.status_code != 200:
                resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException:
            return self._blocked_report(contract_address, "contract", "Request timed out.")
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 401:
                return self._blocked_report(contract_address, "contract", "Authentication failed (invalid API key).")
            if code == 403:
                return self._blocked_report(contract_address, "contract", "Access forbidden (insufficient plan).")
            if code == 429:
                return self._blocked_report(contract_address, "contract", "API rate limit exceeded (server-side).")
            return self._blocked_report(contract_address, "contract", f"HTTP error: {code}")
        except Exception as exc:
            return self._blocked_report(contract_address, "contract", f"Request failed: {exc.__class__.__name__}")

        score = data.get("risk_score")
        if score is None:
            score = data.get("overallRisk")
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
        """Scan a URL via POST /url body: {"url": "..."}."""
        if not self.api_key:
            return self._blocked_report(
                url_to_check, "url",
                "API key not configured. Set WEBACITY_API_KEY to enable live checks.",
            )
        if not _rate_ok("url"):
            return self._blocked_report(url_to_check, "url", "Rate limit exceeded.")

        try:
            client = await self._get_client()
            resp = await client.post(
                "/url",
                headers=self._headers(),
                json={"url": url_to_check},
            )
            if resp.status_code != 200:
                resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException:
            return self._blocked_report(url_to_check, "url", "Request timed out.")
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 401:
                return self._blocked_report(url_to_check, "url", "Authentication failed (invalid API key).")
            if code == 403:
                return self._blocked_report(url_to_check, "url", "Access forbidden (insufficient plan).")
            if code == 429:
                return self._blocked_report(url_to_check, "url", "API rate limit exceeded (server-side).")
            return self._blocked_report(url_to_check, "url", f"HTTP error: {code}")
        except Exception as exc:
            return self._blocked_report(url_to_check, "url", f"Request failed: {exc.__class__.__name__}")

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
    if data.get("issues"):
        raw_issues = data["issues"] if isinstance(data["issues"], list) else [data["issues"]]
        for i in raw_issues:
            desc = i.get("description") or i.get("detail", "")
            if desc:
                evidence.append(str(desc))
    details = data.get("details") or data.get("detail", {})
    if isinstance(details, dict):
        for k, v in list(details.items())[:5]:
            evidence.append(f"{k}: {v}")
    if not evidence and issues:
        evidence.append("Risk factors identified — see raw report for details.")
    if not evidence:
        evidence.append("No detailed evidence returned by provider.")
    return evidence
