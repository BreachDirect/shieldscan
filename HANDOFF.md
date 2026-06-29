# ShieldScan — Agent Handoff / Project Continuation

**Use this file when starting a new Cursor agent chat.** Paste or `@`-reference it so the new agent has full context without re-explaining the project.

---

## Student & project identity

| Field | Value |
|-------|--------|
| **Student** | Michael Victory Osisienimo |
| **Matric** | 2021/1/81438CS |
| **Institution** | FUT Minna — Department of Cyber Security Science |
| **Supervisor** | DR. FASHOLA |
| **Project title** | Design and Implementation of an AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses |
| **Tool name** | **ShieldScan** |
| **Project type** | Practical software artefact (NOT comparative analysis). Design Science Research. |

---

## Dual-audience design (critical)

- **Lay users (SMB owners):** Simple dashboard, plain-English reports, safety score, “how to fix”
- **Expert panel (viva):** OWASP Top 10 mapping, 5-phase scanner v3.0, ZAP DAST, orchestrator, grounded AI, Docker lab

**One-liner:** Interface for non-specialists; engine and architecture for expert scrutiny.

---

## Repository location

```
/home/victory/Projects/shieldscan/
```

---

## Tech stack

- **Backend:** Python 3.13, FastAPI, Uvicorn, httpx, SQLAlchemy, SQLite
- **Frontend:** static HTML/CSS/JS (`static/`)
- **DAST:** OWASP ZAP via REST API (Docker, port 8081)
- **Built-in scanner:** v3.0 — 5 phases (see below)
- **AI:** Anthropic Claude API + template fallback (`app/services/ai_reporter.py`)
- **Lab:** Docker Compose — DVWA :4280, Juice Shop :3000, ZAP :8081

---

## Scanner v3.0 — five phases

1. **Crawl** — up to 80 pages, depth 4, DVWA path seeding, robots/sitemap
2. **Passive** — headers, TLS, cookies (multiple pages)
3. **OWASP Top 10** — XSS, SQLi, CMDi, IDOR, CSRF, auth (`owasp_top10.py`)
4. **Extended** — CORS, sensitive paths, directory listing (`extended_checks.py`)
5. **Deep probes** — LFI, SSTI, NoSQL, API fuzz, rate limits (`deep_probes.py`)

**Modes:** `SCANNER_MODE=zap` (ZAP + builtin) or `builtin` (builtin only). Orchestrator always runs builtin when ZAP is up.

**Version label:** `/health` returns `"scanner_version": "3.0"`. There is only ONE codebase — v3 is the current built-in engine, not a separate app.

---

## Key files

| Path | Purpose |
|------|---------|
| `app/main.py` | FastAPI entry, `/health` |
| `app/services/scan_orchestrator.py` | Scan state machine, ZAP + builtin, dedupe, AI report |
| `app/services/zap_client.py` | ZAP REST API (spider, AJAX spider, passive wait, active scan) |
| `app/services/builtin_scanner.py` | Runs all 5 phases |
| `app/services/owasp_top10.py` | OWASP probes, param fuzzing |
| `app/services/deep_probes.py` | Phase 5 deep checks |
| `app/services/finding_utils.py` | Parameter label enrichment for display |
| `app/services/ai_reporter.py` | Claude + template reports |
| `static/index.html`, `css/style.css`, `js/app.js` | Dashboard (simplified for lay users) |
| `docker-compose.yml` | ZAP, DVWA, Juice Shop |
| `start.sh` | Start ShieldScan on :8000 |
| `start-lab.sh` | `dvwa` \| `full` \| `zap` |
| `.env` / `.env.example` | Config |

---

## Live demo quick reference

```bash
# Terminal 1
cd /home/victory/Projects/shieldscan
./start-lab.sh full          # DVWA + ZAP + Juice Shop
docker compose ps

# Browser: http://127.0.0.1:4280
# Create/Reset Database → login admin/password → Security → Low

# Terminal 2
./start.sh                   # http://127.0.0.1:8000

# Scan target: http://127.0.0.1:4280
# .env: SCANNER_MODE=zap, ZAP_API_KEY=changeme
```

If Docker permission denied: `sg docker -c "./start-lab.sh full"`

---

## Documentation & deliverables

| File | Description |
|------|-------------|
| `Michael_Victory_ShieldScan_Chapters1-5.docx` | Full thesis (Projects + Downloads) |
| `Michael_Victory_ShieldScan_Chapters1-4.docx` | Older — ignore; use 1-5 |
| `Michael_Victory_ShieldScan_Presentation.pptx` | 12-slide defence deck |
| `generate_thesis_ch1_5.py` | Regenerate thesis DOCX |
| `generate_presentation.py` | Regenerate PPTX |
| `generate_owoicho_format.py` | Legacy ch 1-4 only |

---

## Conversation history (prior agent)

Full transcript (for deep context if needed):

```
/home/victory/.cursor/projects/home-victory-Projects/agent-transcripts/2d41ff54-05b2-4ffd-aca2-7b6eb97ba388/2d41ff54-05b2-4ffd-aca2-7b6eb97ba388.jsonl
```

Topics covered in prior chat: project scaffold, scanner evolution (header-only → OWASP probes → v3 deep probes), dashboard UI, DVWA/Docker setup, viva prep, thesis ch 1-5, presentation slides.

---

## Pending / optional next steps

- [ ] Run live DVWA scan and paste actual finding counts into Chapter 4
- [ ] Add screenshots to presentation slides 9–10
- [ ] Optional: `ANTHROPIC_API_KEY` in `.env` for live AI demo
- [ ] Delete old `Chapters1-4.docx` copies to avoid confusion
- [ ] Chapter 5 already written in `generate_thesis_ch1_5.py`

---

## User preferences

- Practical demo-ready build, not literature comparison
- Layman explanations for tool UX; technical depth for academic writing
- OWOICHO JNR / FUT Minna thesis format
- Do not commit unless explicitly asked
- Authorised lab targets only (DVWA/Juice Shop localhost)

---

## Prompt to paste in new agent

```
Continue the ShieldScan FYP project for Michael Victory Osisienimo (FUT Minna, Cyber Security Science).

Read @HANDOFF.md in /home/victory/Projects/shieldscan/ for full context.

Project path: /home/victory/Projects/shieldscan/

Prior work: ShieldScan v3.0 (5-phase built-in scanner + OWASP ZAP + AI reports), thesis ch 1-5, 12-slide presentation, Docker lab with DVWA.

[Describe your next task here]
```
