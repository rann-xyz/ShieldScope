# Grant Proposal: ShieldScope

**Applicant:** ShieldScope
**Grant:** DD.xyz by Webacy Startup Accelerator Grant
**Proposal ID:** SHIELD-2025-001

---

## 1. Executive Summary

ShieldScope is a Web3 security scanner that integrates Webacy's Risk Engine
APIs to provide wallet, smart contract, and phishing URL risk analysis in a
single interface. Built for the DD.xyz by Webacy Startup Accelerator Grant,
it demonstrates how real-time risk intelligence can be embedded directly into
dApps, DeFi protocols, and DeFi aggregators to protect users before they
transact.

We request up to **$10,000 in API credits** to complete the live integration,
validate against real addresses, and deliver a production-grade MVP.

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
- Overall risk score (0-100)
- Threat indicators (sanctions, hacks, mixers, scams)
- Address type classification (EOA, contract, token, etc.)
- Fund flow exposure analysis

### 3.2 Smart Contract Risk Scanner
Analyzes contract addresses for:
- Source code verification status
- Bytecode inspection for honeypot patterns
- Owner/admin key permissions
- Upgradeability and proxy patterns
- Known exploit signatures

### 3.3 URL Risk Scanner
Checks URLs/domains against:
- Phishing feeds
- Blacklisted malicious sites
- Impersonation detection (similar-looking domains)

---

## 4. Why Webacy / DD.xyz

| Requirement | Webacy DD.xyz Provides |
|---|---|
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

| Component | Status | Verification |
|---|---|---|
| Frontend (static) | ✅ Complete | Syntax-validated |
| FastAPI backend | ✅ Complete | 7 integration tests pass |
| API client wrapper | ✅ Complete | 8 unit tests pass |
| Fail-closed logic | ✅ Complete | Tests confirm BLOCKED w/o key |
| Live API integration | ⚠️ BLOCKED | Requires granted API key |

### Key Design Decisions

1. **API key proxied, never exposed to frontend** — all scans route through backend
2. **Fail-closed default** — no key = BLOCKED reports, never fake passes
3. **No session persistence** — no user data stored between requests
4. **Process-local rate limiting** — with documented path to Redis for scaling

---

## 6. Grant Utilization Plan

| Budget Allocation | Amount | Purpose |
|---|---|---|
| API Credits | $7,500 | Webacy DD.xyz API calls for integration testing + pilot |
| Development (3 months) | $2,000 | Engineer time, documentation, security review |
| Testing & QA | $500 | Live address validation, edge case testing |

**Timeline:** 3 months
1. Month 1: Integrate wallet scanner with real data
2. Month 2: Integrate contract + URL scanners, add error handling
3. Month 3: Performance optimization, documentation, production readiness

---

## 7. Differentiation

Unlike existing security dashboards that target technical users:
- **ShieldScope is built for dApp embedding** — simple iframe integration
- **No-code friendly** — project owners can scan without reading docs
- **Evidence-first reports** — explains *why* an address is risky
- **Fail-closed by design** — protects against API outages or misconfigurations

---

## 8. Revenue Model (Post-Grant)

- **Free tier:** 100 scans/day for open-source projects
- **Pro tier:** $49/month for 10,000 scans + priority support
- **Enterprise:** Custom pricing for multi-chain monitoring and alerts

---

## 9. Team

Single developer (solo founder) with 3 years of experience in:
- Blockchain security research
- SaaS product development
- Risk intelligence tooling

All code is open-source and will remain so.

---

## 10. Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| API calls executed | 50,000 | Webacy dashboard |
| Unique scanned addresses | 1,000 | App analytics |
| False positive reports | < 5% | Manual verification |
| Integration partners | 2 | Signed MoUs |
| Open-source contributors | 5 | GitHub stars/forks |

---

## 11. Conclusion

ShieldScope fills a critical gap between complex blockchain security data and
actionable user protection. With Webacy's DD.xyz API credits, we will deliver
a production-grade risk scanner that makes Web3 safer for everyone.

We are committed to:
- Building exclusively on Webacy's API (no competing providers)
- Providing monthly integration progress updates
- Maintaining open-source code transparency

Thank you for your consideration.
