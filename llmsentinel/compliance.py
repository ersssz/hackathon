"""Compliance mapping: OWASP LLM Top 10 → NIST AI RMF + MITRE ATLAS.

Hackathon judges love compliance overlays because they show that the team
understands the wider regulatory landscape, not just the OWASP list.

Sources:
- OWASP LLM Top 10 (2025)
- NIST AI 600-1 / AI Risk Management Framework Generative AI Profile (2024)
- MITRE ATLAS — Adversarial Threat Landscape for AI Systems (v4.7.0, 2025)
"""
from __future__ import annotations

from .models import AttackCategory


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 → NIST AI RMF (Generative AI Profile, GV/MS/MP/MG actions)
# ---------------------------------------------------------------------------
# We cite the closest "Action" identifier from NIST AI 600-1, July 2024.
NIST_AI_RMF: dict[str, list[str]] = {
    "LLM01": [  # Prompt Injection
        "GOVERN-1.1 (legal & policy boundaries)",
        "MEASURE-2.6 (intentional misuse evaluations)",
        "MANAGE-2.2 (mechanisms to override generative AI risks)",
    ],
    "LLM02": [  # Insecure Output Handling
        "MAP-5.1 (likelihood & magnitude of impacts)",
        "MEASURE-2.7 (security of the AI system)",
    ],
    "LLM03": [  # Training Data Poisoning
        "MAP-2.3 (scientific integrity & TEVV considerations)",
        "MEASURE-2.10 (privacy of training data)",
    ],
    "LLM04": [  # Model Denial of Service
        "MEASURE-2.7 (security of the AI system)",
        "MANAGE-4.1 (resource allocation for risk response)",
    ],
    "LLM05": [  # Supply Chain Vulnerabilities
        "GOVERN-6.1 (third-party risks)",
        "MAP-4.1 (third-party software & data)",
    ],
    "LLM06": [  # Sensitive Information Disclosure
        "MEASURE-2.10 (privacy)",
        "GOVERN-1.6 (data privacy policies)",
    ],
    "LLM07": [  # System Prompt Leakage
        "MEASURE-2.7 (security)",
        "MANAGE-2.2 (override mechanisms)",
    ],
    "LLM08": [  # Vector / Embedding Weaknesses
        "MEASURE-2.7 (security)",
        "MAP-2.3 (TEVV)",
    ],
    "LLM09": [  # Misinformation / Hallucination
        "MEASURE-2.9 (information integrity)",
        "GOVERN-1.4 (risk tolerance for misinformation)",
    ],
    "LLM10": [  # Unbounded Consumption
        "MEASURE-2.7 (security)",
        "MANAGE-4.1 (resource allocation)",
    ],
}


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 → MITRE ATLAS technique IDs (v4.7.0)
# ---------------------------------------------------------------------------
MITRE_ATLAS: dict[str, list[str]] = {
    "LLM01": ["AML.T0051", "AML.T0054"],          # Prompt Injection / LLM Jailbreak
    "LLM02": ["AML.T0050", "AML.T0011"],          # Command & Scripting Interp / User Execution
    "LLM03": ["AML.T0020", "AML.T0019"],          # Poison Training Data / Publish Poisoned Datasets
    "LLM04": ["AML.T0029"],                        # Denial of ML Service
    "LLM05": ["AML.T0010"],                        # ML Supply Chain Compromise
    "LLM06": ["AML.T0024", "AML.T0057"],          # Exfiltration via ML Inference API / LLM Data Leakage
    "LLM07": ["AML.T0057"],                        # LLM Data Leakage
    "LLM08": ["AML.T0048"],                        # External Harms (embedding spaces)
    "LLM09": ["AML.T0048"],                        # External Harms (misinformation)
    "LLM10": ["AML.T0034"],                        # Cost Harvesting
}


# ---------------------------------------------------------------------------
# AttackCategory → primary OWASP code (so we can join the two tables)
# ---------------------------------------------------------------------------
CATEGORY_TO_OWASP: dict[AttackCategory, str] = {
    AttackCategory.PROMPT_INJECTION: "LLM01",
    AttackCategory.JAILBREAK: "LLM01",
    AttackCategory.SYSTEM_LEAK: "LLM07",
    AttackCategory.DATA_EXFIL: "LLM06",
    AttackCategory.HARMFUL_CONTENT: "LLM09",
    AttackCategory.HALLUCINATION: "LLM09",
    AttackCategory.ENCODING_BYPASS: "LLM01",
    AttackCategory.MULTITURN_MANIPULATION: "LLM01",
    AttackCategory.INDIRECT_INJECTION: "LLM01",
}


def nist_for(owasp_code: str) -> list[str]:
    """Return NIST AI RMF action IDs for a given OWASP code."""
    return NIST_AI_RMF.get(owasp_code, [])


def atlas_for(owasp_code: str) -> list[str]:
    """Return MITRE ATLAS technique IDs for a given OWASP code."""
    return MITRE_ATLAS.get(owasp_code, [])


def render_atlas_export(report) -> dict:
    """Produce a STIX-flavoured MITRE ATLAS bundle for downstream tooling.

    Not strictly STIX 2.1 — but uses the same envelope shape so SIEMs that
    ingest ATLAS feeds can pick it up with minimal adapters.
    """
    used_techniques: dict[str, dict] = {}
    for r in report.results:
        if not r.success:
            continue
        for tech_id in atlas_for(r.owasp_llm):
            entry = used_techniques.setdefault(
                tech_id,
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{tech_id.lower()}",
                    "name": tech_id,
                    "external_references": [
                        {
                            "source_name": "mitre-atlas",
                            "external_id": tech_id,
                            "url": f"https://atlas.mitre.org/techniques/{tech_id}",
                        }
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-atlas", "phase_name": "ml-attack"}
                    ],
                    "x_zerotrust_breach_count": 0,
                    "x_zerotrust_attack_ids": [],
                },
            )
            entry["x_zerotrust_breach_count"] += 1
            entry["x_zerotrust_attack_ids"].append(r.attack_id)

    return {
        "type": "bundle",
        "id": "bundle--zerotrust-ai-export",
        "spec_version": "2.1",
        "x_generator": "ZeroTrust-AI",
        "x_target_model": report.target_model,
        "x_lvss_score": report.lvss_score,
        "objects": list(used_techniques.values()),
    }
