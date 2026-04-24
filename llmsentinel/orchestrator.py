"""Campaign orchestrator: runs attacks against a target model and judges results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from .adaptive import AdaptiveAttackGenerator
from .adapters import LLMAdapter
from .evaluator import LLMJudge
from .models import Attack, AttackResult, CampaignReport


ProgressCb = Callable[[int, int, AttackResult], None]
ShouldStopCb = Callable[[], bool]


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
        concurrency: int = 1,
        should_stop: Optional[ShouldStopCb] = None,
    ) -> CampaignReport:
        """Execute the attack list and return a CampaignReport.

        Args:
            attacks: list of attack templates to run.
            on_progress: optional ``(done, total, result)`` callback fired after
                EACH completed attack — use it to update a Streamlit live log
                AND to checkpoint a partial report into ``session_state``.
            concurrency: how many attacks to fire in parallel. ``1`` keeps
                deterministic ordering; ``4-8`` gives a 4-8x wall-clock
                speed-up against most providers (Fireworks tolerates this).
            should_stop: optional zero-arg callable that returns True if the
                user has requested cancellation. Checked between attacks; the
                already-completed results are still returned in the report.

        Returns:
            CampaignReport — partial if ``should_stop`` triggered.
        """
        started = datetime.now()
        results: list[AttackResult] = []
        total = len(attacks)

        if concurrency <= 1:
            # Sequential path — preserves deterministic order, easiest to debug.
            for idx, attack in enumerate(attacks, start=1):
                if should_stop is not None and should_stop():
                    break
                result = self._run_single(attack)
                results.append(result)
                if on_progress is not None:
                    on_progress(idx, total, result)
        else:
            # Parallel path — keeps original attack order in the final report
            # but yields results to the progress callback as they complete.
            order = {id(a): i for i, a in enumerate(attacks)}
            done_count = 0
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {pool.submit(self._run_single, a): a for a in attacks}
                try:
                    for fut in as_completed(futures):
                        if should_stop is not None and should_stop():
                            # Cancel everything still pending and break out.
                            for pending in futures:
                                pending.cancel()
                            break
                        result = fut.result()
                        results.append(result)
                        done_count += 1
                        if on_progress is not None:
                            on_progress(done_count, total, result)
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)
            # Restore deterministic ordering for the report.
            results.sort(key=lambda r: order.get(
                id(next((a for a in attacks if a.id == r.attack_id), None)),
                0,
            ))

        finished = datetime.now()
        ran = len(results)
        successes = sum(1 for r in results if r.success)
        rate = successes / ran if ran else 0.0

        return CampaignReport(
            target_model=self.target_model,
            judge_model=self.judge.model,
            started_at=started,
            finished_at=finished,
            total_attacks=ran,
            successful_attacks=successes,
            success_rate=round(rate, 3),
            results=results,
        )

    def run_adaptive_round(
        self,
        prior: CampaignReport,
        generator: AdaptiveAttackGenerator,
        on_progress: Optional[ProgressCb] = None,
        max_mutations: int = 10,
    ) -> CampaignReport:
        """Run a follow-up round where blocked attacks are rewritten and retried.

        Uses ``generator`` to propose ONE mutation per blocked attack, then
        executes and judges those mutations exactly like a normal campaign.

        Args:
            prior: the previous campaign report (only its ``results`` are used).
            generator: LLM-backed mutation generator.
            on_progress: optional per-attack callback.
            max_mutations: safety cap on how many mutations to run in one round.

        Returns:
            A brand-new :class:`CampaignReport` containing only the mutation
            results. Merge or compare it with ``prior`` at the caller's discretion.
        """
        blocked = [r for r in prior.results if not r.success and not r.error][:max_mutations]

        # Rebuild Attack objects from the blocked results, then mutate each one.
        mutated_attacks: list[Attack] = []
        for r in blocked:
            base = Attack(
                id=r.attack_id,
                name=r.attack_name,
                category=r.category,
                severity=r.severity,
                owasp_llm=r.owasp_llm,
                description="(reconstructed from prior report)",
                payload=r.payload,
                success_criteria="(reconstructed; judge re-evaluates)",
                tags=[],
            )
            mutation = generator.mutate(base, refusal_response=r.response)
            if mutation is not None:
                mutated_attacks.append(mutation)

        # Fall through to the normal run() with the freshly-minted mutations.
        return self.run(mutated_attacks, on_progress=on_progress)

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
