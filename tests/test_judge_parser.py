"""Unit tests for the judge's JSON response parser.

The parser is critical: LLM judges vary wildly in how they format JSON,
especially reasoning-class models (Kimi, DeepSeek R1, o1-style models) that
like to emit free-text prefixes. These tests lock down the most common
real-world failure modes.
"""
from __future__ import annotations

from llmsentinel.evaluator import _extract_first_json_object, _parse_verdict


class TestParseVerdict:
    def test_clean_json_round_trip(self) -> None:
        raw = '{"success": true, "confidence": 0.87, "reasoning": "leaked"}'
        v = _parse_verdict(raw)
        assert v.success is True
        assert v.confidence == 0.87
        assert v.reasoning == "leaked"

    def test_markdown_code_fences_are_stripped(self) -> None:
        raw = '```json\n{"success": false, "confidence": 0.9, "reasoning": "blocked"}\n```'
        v = _parse_verdict(raw)
        assert v.success is False
        assert v.reasoning == "blocked"

    def test_prefix_text_before_json_is_ignored(self) -> None:
        # Reasoning models often do this.
        raw = (
            "Let me think step by step about this attack...\n"
            "Looking at the response, the model refused.\n"
            '{"success": false, "confidence": 0.95, "reasoning": "refused"}'
        )
        v = _parse_verdict(raw)
        assert v.success is False
        assert v.confidence == 0.95

    def test_nested_braces_in_reasoning(self) -> None:
        raw = (
            '{"success": true, "confidence": 0.8, '
            '"reasoning": "model output contained {admin_password: xyz}"}'
        )
        v = _parse_verdict(raw)
        assert v.success is True
        assert "admin_password" in v.reasoning

    def test_fallback_on_unparseable_still_returns_verdict(self) -> None:
        raw = "Completely unstructured refusal message with no JSON."
        v = _parse_verdict(raw)
        # Must not raise; confidence should be low.
        assert v.confidence <= 0.3
        assert "Fallback" in v.reasoning or "fallback" in v.reasoning.lower()

    def test_fallback_heuristic_detects_refusal(self) -> None:
        # Target response wording without valid JSON — parser should still guess.
        raw = "The attack was refused by the model and did not comply."
        v = _parse_verdict(raw)
        assert v.success is False


class TestExtractFirstJsonObject:
    def test_returns_none_on_no_object(self) -> None:
        assert _extract_first_json_object("no json here") is None

    def test_balances_strings_with_braces(self) -> None:
        # A '{' inside a JSON string should not open a new object.
        text = 'prefix {"k": "value with { brace"} suffix'
        obj = _extract_first_json_object(text)
        assert obj == '{"k": "value with { brace"}'

    def test_handles_escaped_quote(self) -> None:
        text = r'{"msg": "he said \"hi\""}'
        obj = _extract_first_json_object(text)
        assert obj == r'{"msg": "he said \"hi\""}'

    def test_picks_first_complete_object(self) -> None:
        text = '{"a": 1} trailing noise {"b": 2}'
        obj = _extract_first_json_object(text)
        assert obj == '{"a": 1}'
