# Product Requirements Document (PRD): ShieldScan

**Version:** 1.0  
**Last updated:** 2026-06-29  
**Wave program:** [Stellar Wave 6](https://www.drips.network/wave/stellar) — Jun 23–30, 2026

---

## 1. Overview

| Field | Value |
|---|---|
| **Project** | ShieldScan |
| **Tagline** | AI-assisted web vulnerability assessment for small businesses |
| **Repository** | [BreachDirect/shieldscan](https://github.com/BreachDirect/shieldscan) |
| **Category** | Security tooling · DAST · Web application scanning |
| **Sibling project** | [BreachDirect/RytScan](https://github.com/BreachDirect/RytScan) (Soroban static analysis) |

## 2. Problem Statement

Small businesses deploy web apps without dedicated security teams. Wave contributors ship backends, APIs, and dashboards that handle user data and payments — but web-layer vulnerabilities (missing headers, injection flaws, misconfigured CORS, exposed secrets) are often caught only at review time or after incidents.

Existing DAST tools (OWASP ZAP, Burp) are powerful but require security expertise. Wave contributors and SMB operators need a **fast, authorisation-gated scanner** with plain-English reports they can run locally and in CI during the sprint.

## 3. Drips Wave Alignment

ShieldScan maps to recurring patterns in the [Stellar Wave issue catalog](https://www.drips.network/wave/stellar/issues):

| Wave issue pattern | ShieldScan response |
|---|---|
| [#1034 Health check automation](https://www.drips.network/wave/stellar/issues/b6dc5386-c56c-4c79-9b71-ece7b61d43e8) | `/health` + `/ready` endpoints, `make ci` gate |
| [#159 API contract tests](https://www.drips.network/wave/stellar/issues/c495ac8a-b875-4d03-a8a4-a6f59065dc6d) | Stable error envelope + pytest contract suite |
| [#29 Secure key storage](https://www.drips.network/wave/stellar/issues/58fe0db0-83e4-41eb-9456-a99e2d53355a) | Startup secrets validation; no default API keys in production |
| [#231 Hasura RLS / permissions](https://www.drips.network/wave/stellar/issues/522efcae-a15f-476e-9076-510b1ba87fbe) | Scan authorisation gate + target safety blocklist |
| Backend `make security-ci` pattern | Bandit + dependency audit in Makefile |
| Soroban contract security (RytScan) | Complementary: RytScan covers on-chain; ShieldScan covers web/API layer |

**Wave 6 goal:** Ship Phase 1 platform foundation so contributors can scan authorised lab targets on day one, with CI-ready health and API contracts.

## 4. Solution

ShieldScan provides:

1. **Web dashboard** — enter URL, confirm authorisation, start scan
2. **5-phase built-in scanner** — crawl, passive, OWASP Top 10, extended, deep probes
3. **OWASP ZAP integration** — full DAST when Docker lab is running
4. **AI reports** — Claude API with template fallback for SMB-friendly remediation
5. **CI-ready API** — health, readiness, stable error codes, contract tests

## 5. Target Users

- SMB owners who need plain-English security reports
- Wave contributors shipping web backends and dashboards
- Maintainers triaging `Stellar Wave` security issues on HTTP APIs
- FYP / academic reviewers evaluating DAST architecture

## 6. Phased Delivery

### Phase 1: Platform Foundation & Wave Readiness ✅

| Deliverable | Status |
|---|---|
| FastAPI service with scan CRUD API | ✅ |
| `/health` + `/ready` operational endpoints | ✅ |
| Standardised API error envelope | ✅ |
| Scan authorisation + target safety guard | ✅ |
| Secrets validation on startup | ✅ |
| `make ci` / `make test` / `make security-ci` | ✅ |
| Pytest API contract tests | ✅ |
| GitHub Actions CI workflow | ✅ |
| PRD + architecture documentation | ✅ |
| Docker lab (DVWA, Juice Shop, ZAP) | ✅ |

**Success criteria:**

- [x] `make ci` passes locally
- [x] `/health` returns scanner version and phase list
- [x] `/ready` confirms database connectivity
- [x] API errors return stable `{ error: { code, message, details } }` envelope
- [x] Contract tests cover validation, not-found, and authorisation errors
- [x] Unauthorised scan targets rejected without `authorised: true`
- [x] Documented Wave 6 alignment alongside RytScan

### Phase 2: Built-in Scanner Hardening

- Expand OWASP Top 10 probe coverage and false-positive tuning
- Parameter fuzzing budget controls per target profile
- SARIF v2.1.0 export for GitHub Code Scanning
- Regression fixture suite against DVWA/Juice Shop baselines

### Phase 3: ZAP DAST Integration & Reliability

- ZAP spider/AJAX spider timeout hardening
- Passive scan wait optimisation
- Active scan policy profiles (quick / standard / deep)
- Graceful fallback when ZAP unavailable

### Phase 4: AI Reporting & SMB UX

- Grounded AI reports with finding citations
- Plain-English remediation cards per OWASP category
- Safety score algorithm documentation
- Optional `ANTHROPIC_API_KEY` encrypted storage

### Phase 5: Dashboard & Report Platform

- Scan history trends and severity charts
- HTML/PDF report branding for SMB clients
- Scheduled re-scans and diff reports
- Multi-user scan history (session auth)

### Phase 6: Wave Integrator & Ecosystem

- Unified BreachDirect security CLI (`breach scan web|contract`)
- Cross-reference web findings with RytScan Soroban results
- Drips Wave issue matcher (suggest checks from issue title/body)
- GitHub Action: `BreachDirect/shieldscan-action`

## 7. Non-Goals (Phase 1)

- Multi-tenant SaaS deployment
- On-prem enterprise SSO
- Scanning without explicit user authorisation
- Production scanning of third-party sites without permission

## 8. Success Metrics

| Metric | Phase 1 target |
|---|---|
| `make ci` pass rate | 100% on main |
| API contract test coverage | ≥ 4 error codes locked |
| Health endpoint response time | < 50 ms |
| Time to first scan (lab target) | < 2 min setup |

## 9. Ethics & Compliance

Only scan systems the operator owns or has **written permission** to test. DVWA and Juice Shop are deliberately vulnerable lab apps for education. Production targets require explicit authorisation checkbox confirmation.

---

**Author:** Michael Victory Osisienimo — FUT Minna, Cyber Security Science  
**Organisation:** [BreachDirect](https://github.com/BreachDirect)
