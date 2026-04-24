# ZeroTrust-AI — Architecture

## High-level flow

```
┌──────────────────┐      ┌────────────────────┐
│  Attack library  │──┐   │  Streamlit UI      │
│  (YAML, 21 atk)  │  │   │  - Single scan tab │
└──────────────────┘  │   │  - Compare tab     │
                      │   │  - Vulnerable bot  │
                      ▼   │  - Report tab      │
                ┌─────────────┐                 │
                │ Orchestrator│◄────────────────┘
                │  (Campaign) │
                └──────┬──────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
   ┌─────────────────┐   ┌────────────────┐
   │ Target Adapter  │   │  Judge (LLM)   │
   │ (Fireworks.ai)  │   │  - 70B model   │
   └────────┬────────┘   │  - JSON verdict│
            │            └────────┬───────┘
            ▼                     │
   ┌─────────────────┐            │
   │ Target LLM      │            │
   │ (8B / 70B /     │────────────┘
   │  Mixtral / …)   │
   └─────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │ CampaignReport │
              │ + LVSS score   │
              │ + per-category │
              │   aggregation  │
              └───────┬────────┘
                      │
                      ▼
              ┌────────────────┐
              │ Markdown report│
              │ + download     │
              └────────────────┘
```

## Module responsibilities

| Module | Responsibility |
|---|---|
| `llmsentinel/models.py` | Pydantic data contracts: `Attack`, `AttackResult`, `CampaignReport`; includes LVSS computation. |
| `llmsentinel/adapters.py` | OpenAI-compatible client for Fireworks.ai; retry logic; model catalogue. |
| `llmsentinel/attacks.py` | Loads and validates attack YAML files into `Attack` instances. |
| `llmsentinel/evaluator.py` | `LLMJudge` — sends the target's response to a second LLM with a strict JSON schema and returns a `Verdict(success, confidence, reasoning)`. |
| `llmsentinel/orchestrator.py` | `Campaign` — iterates over attacks, calls target, calls judge, assembles a `CampaignReport`. |
| `llmsentinel/owasp.py` | OWASP LLM Top 10 (2025) reference dictionary. |
| `llmsentinel/report.py` | Renders single-campaign and multi-model comparison reports in Markdown. |
| `attacks/*.yaml` | Curated attack templates (5 files, one per category). |
| `vulnerable_bot/bot.py` | Intentionally-weak ShopBot system prompt used for the live demo. |
| `app.py` | Streamlit dashboard — single entry point. |

## Key design decisions

### 1. LLM-as-Judge instead of regex
Traditional scanners pattern-match on output. They miss:
- paraphrased compliance ("Sure, here is... [leak]"),
- partial obedience,
- obfuscated leaks (base64, ROT13),
- multi-turn setups.

A reasoning-capable judge (Llama 70B) handles all of these naturally. Temperature
is pinned at 0 and the response schema is enforced as JSON for determinism.

### 2. LVSS — custom severity score
Single-number severity lets stakeholders compare models. Formula:

```
LVSS = 10 × (Σ severity_weight[i] for i in successful_attacks)
            / (Σ severity_weight[i] for i in all_attacks)
```

Weights: `critical=10, high=6, medium=3, low=1`.

### 3. Multi-model comparison
A single pass/fail is not actionable. The Compare tab runs the same suite
against multiple Fireworks models, so the report answers the real product
question: *"which model should we ship?"*

### 4. YAML-driven attack library
Security researchers can add a new attack without touching Python. Schema:

```yaml
- id: "PI-006"
  name: "..."
  category: prompt_injection | jailbreak | system_leak | data_exfil | harmful_content
  severity: low | medium | high | critical
  owasp_llm: "LLM01"
  description: "..."
  payload: |
    The adversarial prompt here.
  success_criteria: "Human-readable description of what success means."
  tags: [injection, override]
```

### 5. Fireworks.ai as provider
OpenAI-compatible (drop-in swap), 6+ models available, fast inference, cheap.
A full 21-attack campaign on Llama 3.1 8B + 70B-judge costs about $0.02.
