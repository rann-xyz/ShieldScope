# Grant Proposal: ShieldScope

**Applicant:** ShieldScope
**Grant:** DD.xyz by Webacy Startup Accelerator Grant

> **Note:** This is a prototype / MVP submission. No Webacy API key has been
> obtained yet. All test results below use mocked HTTP responses or
> fail-closed assertions. Live API integration is **not yet verified**.
> The grant requests **API credits only** (not a cash payout).

---

## 1. Executive Summary

ShieldScope is a Web3 security scanner that integrates Webacy's Risk Engine
APIs to provide wallet, smart contract, and phishing URL risk analysis in a
single interface. Built for the DD.xyz by Webacy Startup Accelerator Grant,
it demonstrates how real-time risk intelligence can be embedded directly into
dApps, DeFi protocols, and DeFi aggregators to protect users before they
transact.

We request up to **$10,000 in API credits** to complete the live integration,
validate against real addresses, and deliver a production-grade MVP. No cash
payout is requested.

---

## 2. The Problem

Every day, Web3 users lose funds to:
- **Phishing sites** impersonating legitimate projects
- **Malicious smart contracts** with hidden mint/blacklist functions
- **Tainted wallets** associated with hacks, sanctions, or mixing
- **Token approvals** granting unlimited spending to suspicious contracts

Most dApps lack built-in due-diligence tools. Users are left to manually
research addresses, and by then it's too late.

---

## 3. The Solution

ShieldScope provides a unified scanning interface with three capabilities:

### 3.1 Wallet Risk Scanner
Accepts any blockchain address and returns:
- Overall risk score (0–100) via `overallRisk` / `risk_score`
- Threat indicators (sanctions, hacks, mixers, scams)
- Address type classification (EOA, contract, token, etc.)
- Fund flow exposure analysis (opt-in)

**Endpoint:** `GET /addresses/{address}?chain=eth&show_low_risk&modules=...`

### 3.2 Smart Contract Risk Scanner
Analyzes contract addresses for:
- Source code verification status (with optional bytecode analysis)
- Bytecode inspection for honeypot patterns (`fromBytecode=true`)
- Owner/admin key permissions
- Upgradeability and proxy patterns
- Known exploit signatures

**Endpoint:** `GET /contracts/{contractAddress}?chain=eth&fromBytecode=true`

### 3.3 URL Risk Scanner
Checks URLs/domains against:
- Phishing feeds
- Blacklisted malicious sites
- Impersonation detection (similar-looking domains)

**Endpoint:** `POST /url` with body `{"url": "https://example.com"}`

---

## 4. Why Webacy / DD.xyz

| Requirement | Webacy DD.xyz Provides |
||---|---|
| Multi-chain coverage | ✅ Ethereum, Base, BSC, Polygon, Arbitrum, Optimism, Solana, and more |
| Real-time risk intelligence | ✅ Continuous data processing with latest threat feeds |
| Multi-provider aggregation | ✅ 15+ data providers + proprietary analytics |
| Explainable risk scores | ✅ Evidence-based findings, not just scores |
| Easy API integration | ✅ Standard REST API with `x-api-key` auth |

No other provider combines the breadth, depth, and explainability of Webacy's
risk engine in a single accessible API.

---

## 5. Technical Implementation

### Architecture

```
Browser  →  ShieldScope Frontend (HTML/CSS/JS)
              ↓
         ShieldScope Backend (FastAPI)
              ↓  (x-api-key header)
           Webacy DD.xyz API
```

### Current Status (MVP Phase)

> **Status: MVP Complete · Live integration NOT yet verified · No API key obtained · No API credits granted yet**

| Component | Status | Verification |
||---|---|---|
|| Frontend (static) | ✅ Complete | Syntax-validated, serves via `http.server` or FastAPI |
|| FastAPI backend | ✅ Complete | 8 integration tests pass |
|| API client wrapper | ✅ Complete | 35 unit tests pass (mocked HTTP) |
|| Fail-closed logic | ✅ Complete | Tests confirm BLOCKED w/o key |
|| Endpoint verification | ✅ Complete | Read official OpenAPI specs at docs.webacy.com |
|| URL endpoint path | ✅ Corrected | Changed from guessed `/urls/risk` to verified `POST /url` |
|| Live API integration | ⚠️ NOT verified | No Webacy API key obtained yet |

### What has been verified vs. what is mocked

| Aspect | How Verified |
|---|---|
| Endpoint paths | ✅ Confirmed via official OpenAPI specs (docs.webacy.com) |
| Authentication method | ✅ Confirmed: `x-api-key` header |
| Response schemas | ✅ Confirmed via OpenAPI schema definitions |
| Error handling behavior | ✅ Mocked HTTP responses (401, 403, 429, 500, timeout, malformed JSON) |
| Fail-closed design | ✅ Unit tests confirm BLOCKED state without API key |
| Live API calls | ❌ Not tested — no API key available |

### Key Design Decisions

1. **API key proxied, never exposed to frontend** — all scans route through backend
2. **Fail-closed default** — no key = BLOCKED reports, never fake passes
3. **No session persistence** — no user data stored between requests
4. **Process-local rate limiting** — with documented path to Redis for scaling
5. **No credentials in source** — `.env` files git-ignored, `.env.example` has placeholder only

---

## 6. Running Locally (Demo Mode)

```bash
# 1. Clone
git clone https://github.com/rann-xyz/ShieldScope.git
cd ShieldScope

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run backend (no API key needed for demo)
python -m uvicorn app.server:app --reload --port 8000

# 4. Open in browser:
#    http://localhost:8000/
#    http://localhost:8000/docs (API docs)
```

**Without an API key, the application runs in DEMO mode:**
- All scan requests return `risk_level: "BLOCKED"` with an explanatory message
- The frontend shows: "API key not configured — scans will return BLOCKED (no fake results)"
- No fabricated risk scores are ever produced
- To enable live scanning, set `WEBACITY_API_KEY` in a `.env` file (see `.env.example`)

**To enable live scanning (once you have a Webacy API key):**

```bash
cp .env.example .env
# Edit .env and add your key:
# WEBACITY_API_KEY=your_actual_key_here
export $(cat .env | xargs)  # or set in your shell
python -m uvicorn app.server:app --reload --port 8000
```

---

## 7. Grant Utilization Plan

The grant provides **API credits** (not cash). The requested $10,000 in credits
will be used entirely for Webacy DD.xyz API calls during integration and testing.

| Use | Amount |
|---|---|
| API credits (Webacy DD.xyz calls) | $10,000 in credits |

**Timeline:** 3 months
1. Month 1: Integrate wallet scanner with real data, verify endpoint responses
2. Month 2: Integrate contract + URL scanners, add error handling and edge cases
3. Month 3: Performance optimization, documentation, production readiness

The $2,000 development and $500 QA line items from the initial draft are
covered by the applicant's own time — no cash is requested beyond API credits.

---

## 8. Differentiation

- **Fail-closed by design** — prevents false safety assurances when API is
  unavailable or misconfigured
- **Evidence-first reports** — explains *why* an address is risky, not just a score
- **dApp embedding ready** — iframe-friendly, no framework dependency
- **Transparent about limitations** — clearly distinguishes mocked/unverified
  results from verified behavior

---

## 9. Team

ShieldScope is being developed by an independent developer who learns through
hands-on projects and AI-assisted development. The applicant's technical
experience includes Python, FastAPI, AI-assisted development, and building
Web3-related projects published on GitHub.

The applicant has implemented the initial application, backend API integration
layer, frontend interface, input validation, error handling, and automated
tests. The application is designed to fail safely when risk data is
unavailable (BLOCKED state) rather than presenting unverified results as safe.

As an independent developer, AI-assisted tools are used to accelerate
implementation, testing, and debugging while reviewing the resulting code and
validating functionality. The goal is to continue improving technical skills
while building useful, transparent, and accessible security tools for the
Web3 ecosystem.

All code is open-source and will remain so.

---

## 10. Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| API calls executed | 50,000 | Webacy dashboard (once key is granted) |
| Unique scanned addresses | 1,000 | App analytics (post-integration) |
| False positive reports | < 5% | Manual verification |
| Integration partners | 2 | Signed MoUs (pending — to be secured post-grant) |
| Open-source contributors | 5 | GitHub stars/forks (community growth) |

> Metrics 3–5 are targets for **after** API integration. During the grant
> period (no key yet), only unit/integration test coverage is measurable.

---

## 11. Submission Checklist (Reviewer Evidence)

| Requirement | Provided? | Notes |
|---|---|---|
| Repository (public, MIT) | ✅ Yes | `github.com/rann-xyz/ShieldScope` |
| Code compiles / builds | ✅ Yes | `pip install -r requirements.txt` succeeds |
|| Tests pass | ✅ Yes | 43 passed, 2 skipped (live API tests) |
| Setup instructions | ✅ Yes | README + section 6 above |
| Fail-closed documented | ✅ Yes | README "Security Model" + frontend BLOCKED display |
| API endpoints verified | ✅ Yes | Read from official docs.webacy.com OpenAPI specs |
| No secrets in repo | ✅ Yes | `.env` git-ignored, `.env.example` placeholder only |
| App runs locally without paid services | ✅ Yes | `python -m uvicorn app.server:app --port 8000` |
| Screenshots / live demo | ⚠️ Not yet | No browser automation available; screenshots must be captured manually |
| Live API integration verified | ❌ No | No API key obtained yet |

**Screenshot capture instructions (for reviewer):**

```bash
# Start the server
python -m uvicorn app.server:app --reload --port 8000

# Open http://localhost:8000/ in a browser
# Take screenshots of:
#   1. Landing page
#   2. Wallet scanner form + BLOCKED result
#   3. API documentation at /docs
```

No screenshots were captured programmatically because no headless browser is
available in the current environment (no Chromium, no Selenium).

---

## 12. Conclusion

ShieldScope fills a critical gap between complex blockchain security data and
actionable user protection. With Webacy's DD.xyz API credits, we will deliver
a production-grade risk scanner that makes Web3 safer for everyone.

We are committed to:
- Building exclusively on Webacy's API (no competing providers)
- Providing monthly integration progress updates
- Maintaining open-source code transparency

Thank you for your consideration.
