"""Campaign orchestrator: runs attacks against a target model and judges results."""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from .adapters import LLMAdapter
from .evaluator import LLMJudge
from .models import Attack, AttackResult, CampaignReport


ProgressCb = Callable[[int, int, AttackResult], None]


class Campaign:
    """Runs a batch of attacks against a single target model."""

    def __init__(
        self,
        adapter: LLMAdapter,
        target_model: str,
        judge: LLMJudge,
        target_system_prompt: Optional[str] = None,
    ) -> None:
        self.adapter = adapter
        self.target_model = target_model
        self.judge = judge
        self.target_system_prompt = target_system_prompt

    def run(
        self,
        attacks: list[Attack],
        on_progress: Optional[ProgressCb] = None,
    ) -> CampaignReport:
        started = datetime.now()
        results: list[AttackResult] = []
        total = len(attacks)

        for idx, attack in enumerate(attacks, start=1):
            result = self._run_single(attack)
            results.append(result)
            if on_progress is not None:
                on_progress(idx, total, result)

        finished = datetime.now()
        successes = sum(1 for r in results if r.success)
        rate = successes / total if total else 0.0

        return CampaignReport(
            target_model=self.target_model,
            judge_model=self.judge.model,
            started_at=started,
            finished_at=finished,
            total_attacks=total,
            successful_attacks=successes,
            success_rate=round(rate, 3),
            results=results,
        )

    def _run_single(self, attack: Attack) -> AttackResult:
        try:
            resp = self.adapter.chat(
                model=self.target_model,
                user_prompt=attack.payload,
                system_prompt=self.target_system_prompt,
                temperature=0.7,
                max_tokens=512,
            )
            verdict = self.judge.judge(attack, resp.content)
            return AttackResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                owasp_llm=attack.owasp_llm,
                target_model=self.target_model,
                payload=attack.payload,
                response=resp.content,
                success=verdict.success,
                confidence=verdict.confidence,
                judge_reasoning=verdict.reasoning,
                latency_ms=resp.latency_ms,
            )
        except Exception as exc:  # noqa: BLE001
            return AttackResult(
                attack_id=attack.id,
                attack_name=attack.name,
                category=attack.category,
                severity=attack.severity,
                owasp_llm=attack.owasp_llm,
                target_model=self.target_model,
                payload=attack.payload,
                response="",
                success=False,
                confidence=0.0,
                judge_reasoning="",
                latency_ms=0,
                error=str(exc),
            )
