"""
ShieldScope — FastAPI backend
Wraps the Webacy API client and serves the static frontend.
"""

from __future__ import annotations
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.api_client import APIClient, RiskReport

# Environment detection
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

app = FastAPI(
    title="ShieldScope",
    description="Web3 security scanner — wallet, contract, and URL risk analysis via Webacy APIs",
    version="1.0.0",
)

# Serve frontend
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if _FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=_FRONTEND_DIR, follow_symlink=True), name="static")

# Singleton API client (lazy)
_client: APIClient | None = None

def get_client() -> APIClient:
    global _client
    if _client is None:
        _client = APIClient()
    return _client


class ScanRequest(BaseModel):
    address: str | None = None
    contract_address: str | None = None
    url: str | None = None
    chain: str = "eth"
    from_bytecode: bool = False


class ScanResponse(BaseModel):
    target: str
    category: str
    risk_level: str | None
    risk_score: float | None
    summary: str
    issues: list
    evidence: list


@app.get("/health")
async def health():
    return {"status": "ok", "environment": ENVIRONMENT}


@app.get("/api/config")
async def api_config():
    """Tell the frontend whether the API key is configured."""
    has_key = bool(os.environ.get("WEBACITY_API_KEY") or os.environ.get("DDXYZ_API_KEY"))
    return {
        "apiConfigured": has_key,
        "environment": ENVIRONMENT,
    }


@app.post("/api/scan/wallet")
async def scan_wallet_endpoint(req: ScanRequest):
    if not req.address:
        raise HTTPException(status_code=400, detail="address is required")
    report = await get_client().scan_wallet(req.address, chain=req.chain)
    return _report_to_response(report)


@app.post("/api/scan/contract")
async def scan_contract_endpoint(req: ScanRequest):
    if not req.contract_address:
        raise HTTPException(status_code=400, detail="contract_address is required")
    report = await get_client().scan_contract(req.contract_address, chain=req.chain,
                                               from_bytecode=req.from_bytecode)
    return _report_to_response(report)


@app.post("/api/scan/url")
async def scan_url_endpoint(req: ScanRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="url is required")
    report = await get_client().scan_url(req.url)
    return _report_to_response(report)


def _report_to_response(report: RiskReport) -> ScanResponse:
    return ScanResponse(
        target=report.target,
        category=report.category,
        risk_level=report.risk_level,
        risk_score=report.risk_score,
        summary=report.summary,
        issues=report.issues,
        evidence=report.evidence,
    )


@app.get("/", response_class=FileResponse)
async def root():
    index = _FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse({"documentation": "/docs", "health": "/health"})
