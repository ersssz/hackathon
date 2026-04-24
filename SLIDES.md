# LLMSentinel — Slide deck (copy into Google Slides)

**8 slides total.** Copy each block into a separate Google Slides page. Use a
dark theme, one headline per slide, big typography, minimal text.

---

## Slide 1 — Title

# 🛡️ LLMSentinel

### AI-powered LLM Vulnerability Scanner

**Case 12 · ICCSDFAI 2026 Hackathon**

*Team name · Astana IT University*

---

## Slide 2 — The problem

## The problem nobody is solving

- In 2026, every second SaaS ships an **LLM assistant**
- OWASP **LLM Top 10** standardised in 2025
- Yet there is **no practical, automated audit tool** for deployed chatbots
- Teams ship, then hope

---

## Slide 3 — Our solution

## LLMSentinel

One-click LLM red-teaming for product teams.

- **21 adversarial attacks** across 5 categories
- Mapped to **OWASP LLM Top 10 (2025)**
- **LLM-as-Judge** evaluator (not regex)
- Single-number **LVSS severity score (0–10)**
- Side-by-side model comparison
- Markdown report for Jira / CISO

---

## Slide 4 — Architecture

## How it works

```
Attack Library (YAML) ─► Orchestrator ─► Target LLM
                             │                │
                             ▼                ▼
                         LLM Judge ◄── Response
                             │
                             ▼
                  Campaign Report + LVSS
                             │
                             ▼
                     Streamlit Dashboard
```

---

## Slide 5 — Key innovations

## Three things nobody else has

### 1. LLM-as-Judge
A reasoning model (Llama 70B) decides success/failure — understands paraphrased
compliance, partial obedience, obfuscation.

### 2. LVSS score
Severity-weighted 0–10 metric. One number your PM understands.

### 3. Multi-model comparative mode
Actionable answer: *"ship model B, not model A"*.

---

## Slide 6 — Live demo

## **LIVE DEMO**

> Attacking our intentionally-vulnerable
> **ShopBot** chatbot.
>
> Watch the scanner expose its admin password,
> internal promo code, and unannounced
> product launch — live.

*(Switch to the Streamlit tab and run.)*

---

## Slide 7 — Results & impact

## What a CISO gets in 60 seconds

- ✅ OWASP LLM Top 10 coverage report
- ✅ Breach rate per category
- ✅ LVSS severity score for each candidate model
- ✅ Per-attack audit trail with Judge reasoning
- ✅ Markdown export → Jira / Confluence / risk register

Audit runtime: **~60 seconds, ~$0.02 per model.**

---

## Slide 8 — Close

## Thank you

**GitHub:** `github.com/<team>/llm-sentinel`

**Stack:** Python · Streamlit · Fireworks.ai · Pydantic

Built during ICCSDFAI 2026 Hackathon with AI assistance, as permitted by the rules.

### Questions?
