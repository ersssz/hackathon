"""Unit tests for the YAML attack library loader.

Ensures that every shipped attack file is well-formed and parseable, so a
badly-formatted YAML can't quietly disappear at runtime.
"""
from __future__ import annotations

from llmsentinel.attacks import DEFAULT_ATTACKS_DIR, load_attacks
from llmsentinel.models import AttackCategory


class TestAttackLibrary:
    def test_all_yaml_files_parse(self) -> None:
        # Will raise on malformed YAML or missing required fields.
        attacks = load_attacks()
        assert len(attacks) > 0

    def test_at_least_six_categories_present(self) -> None:
        attacks = load_attacks()
        cats = {a.category for a in attacks}
        # ZeroTrust-AI ships with six categories as of v1.
        assert AttackCategory.PROMPT_INJECTION in cats
        assert AttackCategory.JAILBREAK in cats
        assert AttackCategory.SYSTEM_LEAK in cats
        assert AttackCategory.DATA_EXFIL in cats
        assert AttackCategory.HARMFUL_CONTENT in cats
        assert AttackCategory.HALLUCINATION in cats

    def test_owasp_codes_follow_llm_schema(self) -> None:
        attacks = load_attacks()
        for a in attacks:
            assert a.owasp_llm.startswith("LLM"), f"{a.id}: bad OWASP code {a.owasp_llm!r}"

    def test_severity_ordering_in_loader(self) -> None:
        attacks = load_attacks()
        # Loader sorts by severity descending: critical -> high -> medium -> low.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sevs = [order[a.severity.value] for a in attacks]
        assert sevs == sorted(sevs), "Attacks should be severity-sorted"

    def test_filter_by_category(self) -> None:
        only_hallucination = load_attacks(categories=[AttackCategory.HALLUCINATION])
        assert all(a.category is AttackCategory.HALLUCINATION for a in only_hallucination)
        assert len(only_hallucination) >= 4  # ships with 4 hallucination attacks

    def test_attacks_dir_exists(self) -> None:
        assert DEFAULT_ATTACKS_DIR.exists()
        assert DEFAULT_ATTACKS_DIR.is_dir()
