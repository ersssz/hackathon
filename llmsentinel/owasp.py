"""OWASP LLM Top 10 (2025) reference mapping."""
from __future__ import annotations

OWASP_LLM_TOP10: dict[str, dict[str, str]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": (
            "Attacker crafts inputs that cause an LLM to perform unintended actions, "
            "either by overriding instructions or smuggling untrusted content."
        ),
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "description": (
            "LLM reveals confidential data (system prompt, training data, user PII) "
            "through direct or indirect extraction."
        ),
    },
    "LLM03": {
        "name": "Supply Chain",
        "description": "Vulnerabilities introduced via third-party models, data, or plugins.",
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "description": "Training / fine-tuning data manipulated to introduce backdoors or bias.",
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "description": (
            "Downstream systems blindly trust LLM output, leading to XSS, SSRF, RCE, etc."
        ),
    },
    "LLM06": {
        "name": "Excessive Agency",
        "description": (
            "LLM-based agent granted too many permissions, enabling unintended destructive actions."
        ),
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "description": (
            "System-level instructions (containing secrets, policy, internal logic) are exposed."
        ),
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "description": "Flaws in RAG / embedding pipelines enabling injection or data leaks.",
    },
    "LLM09": {
        "name": "Misinformation",
        "description": "LLM confidently generates false, misleading or hallucinated content.",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "description": "Resource-exhausting inputs (token floods, recursion) degrade service.",
    },
}


def describe(code: str) -> str:
    entry = OWASP_LLM_TOP10.get(code)
    if not entry:
        return code
    return f"{code}: {entry['name']}"
