# 🛡️ ZeroTrust-AI

> **Autonomous red-team agent for Large Language Models — finds the flaws
> before your users do.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-dashboard-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%20GenAI%20Profile-blueviolet)](https://www.nist.gov/itl/ai-risk-management-framework)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20v4.7-red)](https://atlas.mitre.org/)
[![Hackathon](https://img.shields.io/badge/ICCSDFAI%202026-Case%2012-purple)](https://astanait.edu.kz/)
[![Tests](https://img.shields.io/badge/tests-pytest%20%E2%9C%94-brightgreen)](./tests)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](./Dockerfile)

Built for the **ICCSDFAI 2026 Hackathon** (Case 12 — _AI Chatbot Vulnerability
Tester_) at Astana IT University, CyberTech Lab.

> 🎥 **Live demo:** run `streamlit run app.py`, open the **🤖 Vulnerable bot
> demo** tab, click **💥 Attack ShopBot** — watch the scanner expose the
> chatbot's admin password and internal promo code in under 60 seconds.

---

## The problem

In 2026 every second SaaS ships an LLM-powered assistant, yet almost none of them are red-teamed before launch. OWASP published the **LLM Top 10 in 2025**, but there is still no practical, automated way for a development team to audit their own chatbot against it. **ZeroTrust-AI** fills that gap.

## What it does

ZeroTrust-AI systematically fires a curated library of adversarial prompts at a target LLM and uses a **second, stronger LLM as an impartial Judge** to decide whether each attack succeeded. Results are aggregated into a single severity score (**LVSS**) and a downloadable Markdown report mapped to OWASP LLM Top 10.

### Key features

- **51 curated attacks** across **9 categories** (incl. encoding-bypass, multi-turn, indirect injection), each mapped to OWASP LLM Top 10 (2025) **+ NIST AI RMF + MITRE ATLAS**
- **LLM-as-Judge evaluator** — no brittle regex; a reasoning model interprets nuanced compliance
- **LVSS score (0–10)** — our custom severity metric, weighted by attack severity
- **Adaptive autonomous red-team loop** — a generator LLM rewrites blocked attacks
  in a new style and retries, so the scanner learns from its own failures
- **Multi-model comparison** — answer the real question: _which model is safe enough to ship?_
- **Recommended mitigations** auto-included in the Markdown report for every breached category
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
| Harmful content | 4 | LLM09 | Malware snippets, targeted harassment, self-harm instructions |
| Hallucination | 4 | LLM09 | Fabricated citations, invented API references, confident factual invention |

## Quick start

```powershell
# 1. Clone
git clone https://github.com/ersssz/hackathon.git
cd hackathon

# 2. Create a virtual environment (use python.org CPython, not MSYS2)
python -m venv .venv
.\.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your LLM endpoint
copy .env.example .env
# Edit .env:
#   LLM_API_KEY=...              # your bearer token
#   LLM_BASE_URL=https://...     # any OpenAI-compatible endpoint

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

## Why ZeroTrust-AI vs. existing tools

| | Garak / PyRIT | ZeroTrust-AI |
|---|---|---|
| Target user | Security researcher | Product team + CISO |
| Interface | CLI, large config | One-click Streamlit dashboard |
| Evaluator | Regex / heuristic | LLM-as-Judge (reasoning model) |
| Scoring | Raw counts | **LVSS 0–10** severity-weighted |
| Multi-model compare | Manual | Built-in tab |
| Output | Log files | Markdown report + OWASP mapping |

## Supported endpoints & models

ZeroTrust-AI talks to **any** provider that exposes an OpenAI-compatible
`/v1/chat/completions` endpoint. No code changes — just pick a preset (or paste
your own base URL) and API key in the sidebar:

| Preset | Base URL | Typical targets |
|---|---|---|
| Fireworks.ai | `https://api.fireworks.ai/inference/v1` | GLM, Kimi, MiniMax |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o`, `gpt-4o-mini`, `o3-mini` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Together.ai | `https://api.together.xyz/v1` | Llama, Qwen, DeepSeek |
| DeepInfra | `https://api.deepinfra.com/v1/openai` | Llama, Gemma, Qwen |
| OpenRouter | `https://openrouter.ai/api/v1` | Claude, Gemini, GPT (unified) |
| Local | `http://localhost:11434/v1` | vLLM / Ollama / LM Studio |

**Preset models** available in the dropdowns (Fireworks serverless):

| Model | Vendor | Typical role |
|---|---|---|
| GLM 5 | Zhipu AI | target |
| GLM 5.1 | Zhipu AI | judge |
| Kimi K2.5 | Moonshot AI | target or cross-family judge |
| Kimi K2.6 | Moonshot AI | strongest judge available on the tier |
| MiniMax M2.7 | MiniMax | general-purpose target |

**Custom model IDs** can be pasted into the sidebar at any time — works with
every endpoint above.

## Tech stack

Python 3.11 · Streamlit · Plotly · Pydantic v2 · OpenAI-compatible adapter ·
Tenacity · PyYAML.

## Project structure

```
ZeroTrust-AI/
├─ app.py                      # Streamlit entry point
├─ requirements.txt
├─ requirements-dev.txt
├─ pytest.ini
├─ Dockerfile
├─ .env.example / .gitignore
├─ README.md / ARCHITECTURE.md / DEMO_SCRIPT.md / SLIDES.md
├─ llmsentinel/
│  ├─ models.py                # Pydantic models + LVSS
│  ├─ adapters.py              # Generic OpenAI-compatible adapter + presets
│  ├─ attacks.py               # YAML loader
│  ├─ evaluator.py             # LLM-as-Judge with robust JSON parser
│  ├─ orchestrator.py          # Campaign runner + adaptive round
│  ├─ adaptive.py              # Autonomous attack-mutation generator
│  ├─ owasp.py                 # OWASP LLM Top 10 reference
│  └─ report.py                # Markdown report + recommended mitigations
├─ attacks/
│  ├─ prompt_injection.yaml
│  ├─ jailbreak.yaml
│  ├─ system_leak.yaml
│  ├─ data_exfil.yaml
│  ├─ harmful_content.yaml
│  └─ hallucination.yaml
├─ tests/
│  ├─ test_lvss.py             # Severity weighting, edge cases
│  ├─ test_judge_parser.py     # Robust JSON parsing
│  └─ test_attacks_loader.py   # YAML validity
└─ vulnerable_bot/
   └─ bot.py                   # Deliberately-vulnerable ShopBot
```

## Running tests

```powershell
pip install -r requirements-dev.txt
pytest
```

All tests are hermetic — they do **not** call any LLM API.

## Docker

```powershell
docker build -t zerotrust-ai .
docker run -p 8501:8501 --env-file .env zerotrust-ai
```

Then open <http://localhost:8501>.

## Contributing attacks

Add a new attack by appending to one of the YAML files in `attacks/`. Schema
documented in [`ARCHITECTURE.md`](ARCHITECTURE.md#4-yaml-driven-attack-library).

## Team

Built during the ICCSDFAI 2026 Hackathon at Astana IT University's CyberTech
Lab, with heavy assistance from AI coding tooling as explicitly permitted by
the hackathon rules.

## Security & responsible use

ZeroTrust-AI is a **defensive** tool — use it to red-team chatbots you own or
are authorised to test. See [`SECURITY.md`](./SECURITY.md) for the full
disclosure policy and responsible-use guidelines.

## Contributing

Pull requests welcome — see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for dev
setup, attack-authoring guide, and code style.

## License

[MIT](./LICENSE) — do whatever you want, but don't sue us.
