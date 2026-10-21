# ShieldScope

**Web3 Security Scanner** — a prototype MVP built for the
**DD.xyz by Webacy Startup Accelerator Grant**.

ShieldScope provides real-time due-diligence risk intelligence for wallets,
smart contracts, and phishing URLs by integrating Webacy's Risk Engine APIs.

> ⚠️ **Demo / Prototype.** This is a grant proposal and MVP demonstration.
> It does not guarantee threat detection and is not production-grade financial advice.
> No API credentials are committed — live scanning requires a `WEBACITY_API_KEY`.

---

## Table of Contents

- [Architecture](#architecture)
- [API Integration](#api-integration)
- [Features](#features)
- [Security Model](#security-model)
- [Requirements](#requirements)
- [Quick Start (Local)](#quick-start-local)
- [Testing](#testing)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Grant Proposal](#grant-proposal)

---

## Architecture

```
ShieldScope/
├── app/
│   ├── __init__.py          # Package marker
│   ├── api_client.py        # Webacy API client (async httpx wrapper)
│   └── server.py            # FastAPI backend + static file serving
├── frontend/
│   ├── index.html           # Landing page + scanner forms
│   ├── css/style.css        # Mobile-first styles
│   └── js/app.js            # Frontend controller (no frameworks)
├── tests/
│   ├── test_api_client.py   # Client unit + integration tests
│   └── test_server.py       # FastAPI integration tests
├── requirements.txt
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

**Stack:** Python 3.10+, FastAPI, httpx, Pydantic · Vanilla HTML/CSS/JS frontend

---

## API Integration

Integrated three Webacy DD.xyz risk endpoints (base: `https://api.webacy.com`):

| Scanner | Method | Path | Auth |
||---------|--------|------|------|
|| **Wallet Risk** | GET | `/addresses/{address}` | Header `x-api-key` |
|| **Contract Risk** | GET | `/contracts/{contractAddress}` | Header `x-api-key` |
|| **URL Risk** | POST | `/url` | Header `x-api-key` |

All endpoints verified against the official Webacy API documentation at
`docs.webacy.com` (OpenAPI specs dated v1.12.1 / v1.2.0).

### Wallet Risk (`/addresses/{address}`)

- **Params:** `chain` (eth, base, bsc, pol, opt, arb, sol, ton, sei, sui, btc, stellar, hedera, robinhood), `show_low_risk`, `fund_flow_exposure`, `modules`
- **Response:** `overallRisk` (0-100), `issues[]`, `addressType`, `tokenStandard`

### Contract Risk (`/contracts/{contractAddress}`)

- **Params:** `chain`, `fromBytecode` (do full bytecode analysis)
- **Response:** `risk_score`, vulnerability findings, audit status

### URL Risk

- **Body:** `{"url": "https://example.com"}`
- **Response:** `riskLevel` enum (low/medium/high/unknown), `description`

### Authentication

API key is passed via the `x-api-key` header — **never logged**, never
returned to the frontend, loaded via environment variable.

---

## Features

- ✅ **Wallet risk scanner** — threat exposure, sanctions, malicious behavior
- ✅ **Smart contract scanner** — vulnerability detection, owner permissions
- ✅ **Phishing URL scanner** — blacklist & impersonation detection
- ✅ **Evidence-based reports** — scores, issue details, supporting evidence
- ✅ **Responsive mobile-first** — works on Android, iOS, desktop
- ✅ **Fail-closed design** — BLOCKED state when key missing or requests fail
- ✅ **No framework dependency** — pure HTML/CSS/JS, GitHub Pages ready
- ✅ **Rate limiting** — in-memory, process-local (documented caveat below)

---

## Security Model

ShieldScope is built with **defensive defaults**:

1. **Fail-closed:** If `WEBACITY_API_KEY` is unset → all scans return
   `risk_level: "BLOCKED"` with explanatory evidence. **No fabricated results.**
2. **No secrets in frontend:** The API key is loaded server-side and never
   exposed to browser clients. All scans proxy through the backend.
3. **No secrets in repo:** `.env` is git-ignored; `.env.example` contains
   only placeholder documentation.
4. **Rate limiting:** 10 requests / 60 seconds / category (in-memory).
   _Caveat: process-local only. In a multi-instance deployment, use a shared
   store (Redis) for distributed rate limiting._
5. **No persistent storage:** Session data is not retained between restarts.

---

## Requirements

- Python 3.10+
- pip (or uv)
- A Webacy API key (obtained via grant approval)

No paid hosting required for local development. GitHub Pages can host the
static frontend for free.

---

## Quick Start (Local)

```bash
# 1. Clone
git clone https://github.com/rann-xyz/ShieldScope.git
cd ShieldScope

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Set API key — leave unset for demo mode
cp .env.example .env
# Edit .env → set WEBACITY_API_KEY=your_key_here

# 4. Run backend
python -m uvicorn app.server:app --reload --port 8000

# 5. Open in browser
#    Frontend: http://localhost:8000/static/index.html  (if mounted)
#    OR serve frontend directly:
#    python -m http.server 8080 --directory frontend
```

---

## Testing

### Prerequisites

Tests use mocks and fail-closed assertions — **no real API key needed** for
the core test suite. Live integration tests auto-skip when no key is set.

```bash
# Install test deps
pip install pytest pytest-asyncio pytest-timeout

# Run all tests
pytest tests/ -v

# Run only fail-closed (no API key) tests
pytest tests/ -v -m "not require_api_key"
```

### Expected results (no API key set)

```
tests/test_api_client.py   30 tests (all PASS)
tests/test_server.py         8 tests (all PASS)
TOTAL: 38 passed, 2 skipped — 0 failures
```

### Live integration tests

```bash
WEBACITY_API_KEY=your_key_here pytest tests/ -v
```

The two `@pytest.mark.skipif(not api_key)` tests will run against the real
Webacy API.

---

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBACITY_API_KEY` | Webacy / DD.xyz API key | unset (demo mode) |
| `DDXYZ_API_KEY` | Alias for above | unset (demo mode) |
| `ENVIRONMENT` | `development` or `production` | `development` |

---

## API Endpoints (Backend)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/config` | GET | Returns whether API key is configured |
| `/api/scan/wallet` | POST | Scan a wallet address |
| `/api/scan/contract` | POST | Scan a contract address |
| `/api/scan/url` | POST | Scan a URL for phishing/malware |

---

## Rate Limiting

In-memory rate limiter: **10 requests per 60 seconds per scanner type**
(wallet / contract / url). This is **process-local** — it works for a single
server instance. For horizontal scaling, replace with Redis-backed
distributed rate limiting.

---

## Limitations & Known Gaps

1. **Live API integration not verified** at this stage — no API key available.
   Tests assert fail-closed behavior (BLOCKED) in the absence of a key.
2. **Frontend static serving** requires either a reverse proxy or serving
   `frontend/index.html` directly via `http.server`.
3. **Rate limiting** is in-memory (documented above).
4. **No wallet signing** — this is purely a risk scanner, not a wallet.
5. **Tests were run on Python 3.14 / Ubuntu (Android UserLAnd)** — results
   may vary on other platforms.

---

## Grant Proposal

See [`docs/GRANT_PROPOSAL.md`](docs/GRANT_PROPOSAL.md) for the full proposal
text written for the DD.xyz by Webacy Startup Accelerator Grant.
