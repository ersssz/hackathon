# 🛡️ LLMSentinel

> **AI-powered LLM Vulnerability Scanner** — automated red-teaming framework for Large Language Models.

Built for **ICCSDFAI 2026 Hackathon** (Case 12 — _AI Chatbot Vulnerability Tester_) — Astana IT University, CyberTech Lab.

---

## The problem

In 2026 every second SaaS ships an LLM-powered assistant, yet almost none of them are red-teamed before launch. OWASP published the **LLM Top 10 in 2025**, but there is still no practical, automated way for a development team to audit their own chatbot against it. **LLMSentinel** fills that gap.

## What it does

LLMSentinel systematically fires a curated library of adversarial prompts at a target LLM and uses a **second, stronger LLM as an impartial Judge** to decide whether each attack succeeded. Results are aggregated into a single severity score (**LVSS**) and a downloadable Markdown report mapped to OWASP LLM Top 10.

### Key features

- **21 curated attacks** across 5 categories, each mapped to OWASP LLM Top 10 (2025)
- **LLM-as-Judge evaluator** — no brittle regex; a reasoning model interprets nuanced compliance
- **LVSS score (0–10)** — our custom severity metric, weighted by attack severity
- **Multi-model comparison** — answer the real question: _which model is safe enough to ship?_
- **Live Streamlit dashboard** with real-time progress log and heatmaps
- **Vulnerable ShopBot demo** — intentionally-weak bot proves the scanner catches real leaks live
- **Downloadable Markdown report** with OWASP mapping and per-attack audit trail

## Architecture

```
Attack Library (YAML) ─► Orchestrator ─► Target LLM (Fireworks.ai)
                             │                  │
                             ▼                  ▼
                         LLM Judge ◄──────── Response
                             │
                             ▼
                   Campaign Report + LVSS
                             │
                             ▼
                   Streamlit Dashboard
```

Full diagram and module map in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Attack categories

| Category | Count | OWASP | Examples |
|---|---:|---|---|
| Prompt injection | 5 | LLM01 | Instruction override, delimiter confusion, indirect injection via quoted RAG content |
| Jailbreak | 5 | LLM01 | DAN roleplay, academic-cover framing, base64-encoded payload, fiction wrapper |
| System-prompt leak | 4 | LLM07 | Direct request, echo trick, debug-mode impersonation |
| Data exfiltration | 3 | LLM02 | Training-data memorisation probe, credential solicitation, RAG leak |
| Harmful content | 4 | LLM09 | Malware snippets, fabricated citations, targeted harassment, self-harm instructions |

## Quick start

```powershell
# 1. Clone
git clone https://github.com/<you>/llm-sentinel.git
cd llm-sentinel

# 2. Create a virtual environment (use python.org CPython, not MSYS2)
python -m venv .venv
.\.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up API key
copy .env.example .env
# Edit .env and paste your FIREWORKS_API_KEY

# 5. Launch dashboard
streamlit run app.py
```

Then open <http://localhost:8501>.

## Usage

### 🎯 Single scan
Pick a target model + attack categories → **Launch campaign** → watch attacks run live → review results, heatmap, and per-attack judge reasoning.

### ⚔️ Compare models
Select 2+ Fireworks models → **Compare** → get a head-to-head table with LVSS per model. Use this to decide which model to ship.

### 🤖 Vulnerable ShopBot demo
Pre-built intentionally-weak customer-support bot with secrets baked into its system prompt. One click → scanner exposes the admin password, promo code, and unannounced product launch. **This is the live demo highlight.**

### 📋 Report
Latest campaign exported as a clean Markdown report suitable for pasting into Jira, Confluence, or a CISO's risk register.

## Why LLMSentinel vs. existing tools

| | Garak / PyRIT | LLMSentinel |
|---|---|---|
| Target user | Security researcher | Product team + CISO |
| Interface | CLI, large config | One-click Streamlit dashboard |
| Evaluator | Regex / heuristic | LLM-as-Judge (reasoning model) |
| Scoring | Raw counts | **LVSS 0–10** severity-weighted |
| Multi-model compare | Manual | Built-in tab |
| Output | Log files | Markdown report + OWASP mapping |

## Tech stack

Python 3.11 · Streamlit · Plotly · Pydantic v2 · Fireworks.ai (OpenAI-compatible) · Tenacity · PyYAML.

## Project structure

```
llm-sentinel/
├─ app.py                     # Streamlit entry point
├─ requirements.txt
├─ .env.example
├─ README.md / ARCHITECTURE.md / DEMO_SCRIPT.md
├─ llmsentinel/
│  ├─ models.py                # Pydantic models + LVSS
│  ├─ adapters.py              # Fireworks OpenAI-compatible client
│  ├─ attacks.py               # YAML loader
│  ├─ evaluator.py             # LLM-as-Judge
│  ├─ orchestrator.py          # Campaign runner
│  ├─ owasp.py                 # OWASP LLM Top 10 reference
│  └─ report.py                # Markdown report renderer
├─ attacks/
│  ├─ prompt_injection.yaml
│  ├─ jailbreak.yaml
│  ├─ system_leak.yaml
│  ├─ data_exfil.yaml
│  └─ harmful_content.yaml
└─ vulnerable_bot/
   └─ bot.py                   # Deliberately-vulnerable ShopBot
```

## Contributing attacks

Add a new attack by appending to one of the YAML files in `attacks/`. Schema
documented in [`ARCHITECTURE.md`](ARCHITECTURE.md#4-yaml-driven-attack-library).

## Team

Built during the ICCSDFAI 2026 Hackathon at Astana IT University's CyberTech
Lab, with heavy assistance from AI coding tooling as explicitly permitted by
the hackathon rules.

## License

MIT.
