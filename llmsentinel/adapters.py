"""LLM adapters. OpenAI-compatible providers (Fireworks.ai, OpenAI, etc.)."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential


FIREWORKS_BASE_URL = "https://api.fireworks.ai/inference/v1"


@dataclass
class ChatResponse:
    content: str
    latency_ms: int
    model: str


class FireworksAdapter:
    """OpenAI-compatible client for Fireworks.ai."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = FIREWORKS_BASE_URL,
        timeout: float = 60.0,
    ) -> None:
        key = api_key or os.getenv("FIREWORKS_API_KEY")
        if not key:
            raise ValueError(
                "FIREWORKS_API_KEY not set. Put it in .env or pass api_key explicitly."
            )
        self.client = OpenAI(api_key=key, base_url=base_url, timeout=timeout)

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
        """Send a chat completion request and return response with latency."""
        messages = []
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


# Popular Fireworks models for side-by-side comparison
FIREWORKS_MODELS = {
    "Llama 3.1 8B": "accounts/fireworks/models/llama-v3p1-8b-instruct",
    "Llama 3.1 70B": "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "Llama 3.3 70B": "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "Mixtral 8x7B": "accounts/fireworks/models/mixtral-8x7b-instruct",
    "Qwen 2.5 72B": "accounts/fireworks/models/qwen2p5-72b-instruct",
    "DeepSeek V3": "accounts/fireworks/models/deepseek-v3",
}
