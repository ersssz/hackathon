"""Pydantic data models used across LLMSentinel."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_LEAK = "system_leak"
    DATA_EXFIL = "data_exfil"
    HARMFUL_CONTENT = "harmful_content"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Attack(BaseModel):
    """Single attack template."""

    id: str
    name: str
    category: AttackCategory
    severity: Severity
    owasp_llm: str = Field(description="OWASP LLM Top 10 id, e.g. LLM01")
    description: str
    payload: str = Field(description="The actual adversarial prompt")
    success_criteria: str = Field(
        description="Human-readable description of what 'successful attack' means"
    )
    tags: list[str] = Field(default_factory=list)


class AttackResult(BaseModel):
    """Result of executing a single attack against a model."""

    attack_id: str
    attack_name: str
    category: AttackCategory
    severity: Severity
    owasp_llm: str
    target_model: str
    payload: str
    response: str
    success: bool = Field(description="Did the attack succeed?")
    confidence: float = Field(ge=0.0, le=1.0, description="Judge confidence")
    judge_reasoning: str = Field(description="Why the judge decided as it did")
    latency_ms: int
    timestamp: datetime = Field(default_factory=datetime.now)
    error: Optional[str] = None


class CampaignReport(BaseModel):
    """Aggregated results of a single campaign."""

    target_model: str
    judge_model: str
    started_at: datetime
    finished_at: datetime
    total_attacks: int
    successful_attacks: int
    success_rate: float
    results: list[AttackResult]

    @property
    def lvss_score(self) -> float:
        """LLM Vulnerability Severity Score (0-10) - our custom metric."""
        if not self.results:
            return 0.0
        weights = {
            Severity.LOW: 1.0,
            Severity.MEDIUM: 3.0,
            Severity.HIGH: 6.0,
            Severity.CRITICAL: 10.0,
        }
        max_possible = sum(weights[r.severity] for r in self.results)
        actual = sum(weights[r.severity] for r in self.results if r.success)
        if max_possible == 0:
            return 0.0
        return round(10.0 * actual / max_possible, 2)

    def category_stats(self) -> dict[str, dict[str, Any]]:
        """Per-category aggregate stats."""
        stats: dict[str, dict[str, Any]] = {}
        for cat in AttackCategory:
            items = [r for r in self.results if r.category == cat]
            if not items:
                continue
            succ = [r for r in items if r.success]
            stats[cat.value] = {
                "total": len(items),
                "success": len(succ),
                "rate": round(len(succ) / len(items), 3),
            }
        return stats
