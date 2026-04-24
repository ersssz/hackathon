"""LLM adapters — generic OpenAI-compatible + native Anthropic.

ZeroTrust-AI speaks to **any** provider that exposes an OpenAI-compatible
``/v1/chat/completions`` endpoint. That covers Fireworks.ai, OpenAI,
Groq, Together.ai, DeepInfra, OpenRouter, vLLM, LM Studio, Ollama, etc.

All adapters expose the same duck-typed interface:

    adapter.chat(model, user_prompt, system_prompt=None, temperature=..., max_tokens=...)
      -> ChatResponse
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional, Protocol

from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential


# Known OpenAI-compatible endpoints. Users can always override with "Custom".
ENDPOINT_PRESETS: dict[str, str] = {
    "Fireworks.ai": "https://api.fireworks.ai/inference/v1",
    "OpenAI": "https://api.openai.com/v1",
    "Groq": "https://api.groq.com/openai/v1",
    "Together.ai": "https://api.together.xyz/v1",
    "DeepInfra": "https://api.deepinfra.com/v1/openai",
    "OpenRouter": "https://openrouter.ai/api/v1",
    "Local (Ollama/LM Studio)": "http://localhost:11434/v1",
    "Custom": "",
}

# Back-compat alias used by a few call-sites.
FIREWORKS_BASE_URL = ENDPOINT_PRESETS["Fireworks.ai"]


@dataclass
class ChatResponse:
    content: str
    latency_ms: int
    model: str


class LLMAdapter(Protocol):
    """Structural type that every provider adapter must satisfy."""

    def chat(
        self,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> ChatResponse: ...


class OpenAICompatAdapter:
    """Generic client for any OpenAI-compatible ``/v1/chat/completions`` endpoint.

    Works with Fireworks, OpenAI, Groq, Together, DeepInfra, OpenRouter, vLLM,
    Ollama, LM Studio, and any other service that speaks the OpenAI wire format.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = FIREWORKS_BASE_URL,
        timeout: float = 60.0,
    ) -> None:
        key = api_key or os.getenv("LLM_API_KEY") or os.getenv("FIREWORKS_API_KEY")
        if not key:
            raise ValueError(
                "API key missing. Set it in the sidebar, or set LLM_API_KEY in .env."
            )
        if not base_url:
            raise ValueError(
                "Base URL missing. Pick a preset in the sidebar or paste a custom one."
            )
        self.client = OpenAI(api_key=key, base_url=base_url, timeout=timeout)
        self.base_url = base_url

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=6),
        reraise=True,
    )
    def chat(
        self,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> ChatResponse:
        """Send a chat-completion request and return response + wall-clock latency."""
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        start = time.perf_counter()
        resp = self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        latency_ms = int((time.perf_counter() - start) * 1000)
        content = resp.choices[0].message.content or ""
        return ChatResponse(content=content, latency_ms=latency_ms, model=model)


# Back-compat alias — older imports of ``FireworksAdapter`` keep working.
class FireworksAdapter(OpenAICompatAdapter):
    """Back-compat: Fireworks-preset of :class:`OpenAICompatAdapter`.

    Identical behaviour to the parent; exists purely so older code that does
    ``from llmsentinel.adapters import FireworksAdapter`` keeps working.
    """


class AnthropicAdapter:
    """Native Anthropic Messages API client."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Put it in .env or pass api_key explicitly."
            )
        # Imported lazily so users without the anthropic SDK can still use Fireworks.
        import anthropic  # noqa: WPS433  (local import)

        self.client = anthropic.Anthropic(api_key=key, timeout=timeout)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=6),
        reraise=True,
    )
    def chat(
        self,
        model: str,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> ChatResponse:
        """Send a Claude Messages API request and return response with latency."""
        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        start = time.perf_counter()
        resp = self.client.messages.create(**kwargs)
        latency_ms = int((time.perf_counter() - start) * 1000)

        # Claude returns a list of content blocks; concatenate text blocks.
        parts = []
        for block in resp.content:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
        content = "".join(parts)
        return ChatResponse(content=content, latency_ms=latency_ms, model=model)


# Text/chat models available on Fireworks' serverless tier (as of 2026-04).
# This list reflects what our team's API key can actually invoke. If Fireworks
# adds more serverless models, either extend this map or paste the slug into the
# UI's "Custom model ID" field.
FIREWORKS_MODELS = {
    # ---- Zhipu GLM — Claude/GPT-4-class open-weights reasoning model.
    "GLM 5.1": "accounts/fireworks/models/glm-5p1",
    # ---- Moonshot Kimi — long-context reasoning, strong on red-teaming bench.
    "Kimi K2.6": "accounts/fireworks/models/kimi-k2p6",
    # ---- Alibaba Qwen — strong multilingual + vision LLMs.
    "Qwen3.6 Plus":       "accounts/fireworks/models/qwen3p6-plus",
    "Qwen3.5 122B A10B":  "accounts/fireworks/models/qwen3p5-122b-a10b",
    # ---- Google Gemma 4 — open instruction-tuned models, vision-capable.
    "Gemma 4 31B IT":         "accounts/fireworks/models/gemma-4-31b-it",
    "Gemma 4 31B IT NVFP4":   "accounts/fireworks/models/gemma-4-31b-it-nvfp4",
    "Gemma 4 26B A4B IT":     "accounts/fireworks/models/gemma-4-26b-a4b-it",
    # ---- MiniMax — large MoE, general-purpose chat.
    "MiniMax M2.7": "accounts/fireworks/models/minimax-m2p7",
}
# Slugs above were confirmed against the team's Fireworks account on 2026-04-24.
# To use any other model, paste its slug into the sidebar's "Custom model ID"
# field — it overrides this preset map without code changes.

# Popular Anthropic models. Use the latest Claude 4.x line.
ANTHROPIC_MODELS = {
    "Claude Opus 4.7": "claude-opus-4-7",
    "Claude Opus 4.5": "claude-opus-4-5",
    "Claude Sonnet 4.5": "claude-sonnet-4-5",
    "Claude Sonnet 4": "claude-sonnet-4-0",
    "Claude Haiku 4": "claude-haiku-4-0",
    "Claude 3.5 Sonnet": "claude-3-5-sonnet-latest",
    "Claude 3.5 Haiku": "claude-3-5-haiku-latest",
}


def build_adapter(
    api_key: str,
    base_url: str = FIREWORKS_BASE_URL,
    *,
    timeout: float = 60.0,
) -> LLMAdapter:
    """Return a generic OpenAI-compatible adapter for ``base_url``.

    Args:
        api_key: the bearer token for the endpoint (Fireworks, OpenAI, Groq, …).
        base_url: endpoint root, e.g. ``https://api.fireworks.ai/inference/v1``.
            Use an entry from :data:`ENDPOINT_PRESETS` or your own URL.
        timeout: per-request timeout in seconds.

    Returns:
        An :class:`OpenAICompatAdapter` ready to call ``.chat(...)``.
    """
    return OpenAICompatAdapter(api_key=api_key, base_url=base_url, timeout=timeout)
