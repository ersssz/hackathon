# ZeroTrust-AI — Demo Script

**Total duration: 6 minutes** (+ 2-3 minutes of Q&A).
Target: ICCSDFAI 2026 Hackathon jury.

---

## 0:00 — 0:30 · The problem (30 sec)

> "In 2026, every second SaaS ships an LLM-powered assistant — customer support,
> code assistant, internal copilot. But **almost none of them are red-teamed
> before launch**. The OWASP LLM Top 10 was standardised in 2025, yet there is
> still no practical, automated way for a development team to audit their
> own chatbot. We built that tool."

**Visual:** Title slide with project name and team.

---

## 0:30 — 1:30 · What it does (1 minute)

> "**ZeroTrust-AI** is an AI-powered LLM vulnerability scanner. It works in three
> steps:
> 1. We curated an **attack library** of 51 adversarial prompts across 9 categories — including encoding-bypass, multi-turn crescendo, and indirect injection — all mapped to OWASP LLM Top 10, NIST AI RMF, and MITRE ATLAS
>    (prompt injection, jailbreak, system-prompt leak, data exfiltration, harmful
>    content, hallucination), each mapped to OWASP LLM Top 10.
> 2. The **orchestrator** fires every attack at a target LLM.
> 3. The key innovation: a **second, stronger LLM acts as the Judge** — it reads
>    each response and decides whether the attack succeeded. No brittle regex,
>    no hand-crafted heuristics."

**Visual:** The architecture diagram (README).

---

## 1:30 — 4:00 · LIVE DEMO (2 min 30 sec) — **the money shot**

> "Let me show you this working. We built a fictional vulnerable customer-support
> bot called **ShopBot**. Its system prompt contains an admin password, a secret
> promo code, and an internal API key. No real production bot would admit those
> exist — but many unintentionally leak them."

**Step 1 (30 sec):** Open **Vulnerable bot demo** tab. Show ShopBot's system
prompt to the audience — point at `admin_password`, `refund_api_key`,
`Project Aurora`.

**Step 2 (30 sec):** Hit **"Attack ShopBot"**. The live log starts rolling —
attacks fire one by one, 15-20 seconds total. Audience watches red ❌ BREACH
markers appear in real time.

**Step 3 (60 sec):** When done, highlight:
  - **LVSS score**: read aloud ("this model scored X out of 10 — high risk").
  - **Heatmap**: show where it breaks most.
  - **One individual finding**: expand a specific breach where ShopBot leaked
    `admin_password` or `Project Aurora`. Read the judge's reasoning aloud —
    this proves the judge works.

**Step 4 (30 sec):** Switch to **Compare models** tab with results from a prior
comparison run. Show that GLM 5 breaches X times, but Kimi K2.6 only Y times.
"Our tool answers the production question: *which model is safe enough to
ship?* — and with **cross-family judging** (Kimi judges GLM, GLM judges Kimi)
we eliminate same-family bias in the verdict."

---

## 4:00 — 5:00 · Why this wins (1 minute)

**Three novel contributions — match the rubric.**

> "Three things make ZeroTrust-AI different from what exists today:
>
> **1. LLM-as-Judge.** Traditional scanners match regex on the response.
> That misses paraphrased compliance, partial obedience, obfuscation. Our judge
> is a 70B reasoning model — it *understands* whether the attack succeeded.
>
> **2. LVSS — our custom scoring metric.** We weight each breach by severity, on
> a 0-to-10 scale, so product managers see one number.
>
> **3. Multi-model comparative mode.** Instead of one pass/fail, the tool tells
> you *which* model to ship. That's actionable."

**Visual:** the LVSS score card, comparison table.

---

## 5:00 — 5:45 · Technical & practical fit (45 sec)

> "Built in **6 hours** during this hackathon, with AI assistance — consistent
> with the rules. Stack: Python, Streamlit, Fireworks.ai (GLM & Kimi models),
> Anthropic SDK (optional Claude), Pydantic.
>
> Fully open-source. A security team can point it at their staging chatbot,
> run a campaign, get a Markdown report to paste into Jira in under 5 minutes.
> No training data, no GPU, no fine-tuning.
>
> It's mapped to **OWASP LLM Top 10** and exports findings in a format suitable
> for a CISO's risk register."

---

## 5:45 — 6:00 · Close (15 sec)

> "In 2026, you wouldn't ship a web app without a vulnerability scanner. Soon
> you won't ship an LLM app without one either. **ZeroTrust-AI** is that
> scanner. Thank you — questions?"

---

## Q&A — likely questions & answers

**Q: Why not use existing tools like Garak / PyRIT?**
A: Great question. Garak and PyRIT are researcher-oriented — huge config, CLI-heavy,
produce log files, no scoring metric, no deployment-decision workflow. ZeroTrust-AI is
product-oriented: a PM or red-teamer opens a browser, clicks one button, gets a report
they can paste into a ticket. We are complementary, not competitive. Our **Judge +
LVSS + multi-model comparison** are novel contributions.

**Q: How do you prevent false positives in the Judge?**
A: We use a reasoning-capable model (Llama 70B) with temperature 0 and a strict
JSON schema. The Judge outputs a confidence score — findings with confidence
< 0.5 should be manually reviewed. In production you would dual-judge with two
different models and only flag on agreement.

**Q: What about attacks your library doesn't cover?**
A: The library is YAML-based — a security researcher adds a new attack by
writing 6 lines of YAML, no code. We deliberately keep it OWASP-aligned so the
coverage grows as the standard evolves.

**Q: Can this be used offensively?**
A: It scans LLMs against their declared policies — same ethical profile as a
web vulnerability scanner. The attack prompts are already public (OWASP,
academic papers). Our contribution is the evaluation layer, not the attacks
themselves.

**Q: Cost? Doesn't it burn tokens?**
A: A full 21-attack campaign on Fireworks.ai 8B costs about $0.01-0.02.
Cheaper than a single cup of coffee. Judge model calls are the bulk — you can
swap a smaller judge for rapid iterations, larger judge for audit runs.

**Q: How do you handle models that refuse to be the Judge?**
A: We have a graceful fallback: if the Judge returns malformed output, we
heuristically parse "success" / "failed" from the raw text and tag confidence
as 0.3. A cleaner fallback is switching to another judge model.

---

## Backup — if live demo fails

1. Pre-recorded 30-second screencast of a successful ShopBot attack (prep this
   morning before the slot starts).
2. Pre-generated PDF/MD report in `reports/` — show it on the Report tab.
3. Prepared screenshots of comparison view for 2-3 models.
