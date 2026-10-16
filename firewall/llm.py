"""Thin wrapper around an OpenAI-compatible chat endpoint that returns JSON verdicts.

Configured from the environment:
    FIREWALL_API_KEY   (falls back to NEBIUS_API_KEY)
    FIREWALL_BASE_URL  (defaults to Nebius Token Factory)
    FIREWALL_MODEL     (required; check IDs with scripts/list_models.py)
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"


class LLMError(RuntimeError):
    pass


class LLM:
    def __init__(self, client, model: str, max_tokens: int = 400, timeout: float = 30.0,
                 max_calls: int | None = None):
        self._client = client
        self.model = model
        self._max_tokens = max_tokens
        self._timeout = timeout
        # Hard cap on calls for the lifetime of the process, so a public demo can't
        # spend the whole credit balance. Once reached, the firewall falls back to rules.
        self.max_calls = max_calls
        self._lock = threading.Lock()
        self.attempts = 0
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @classmethod
    def from_env(cls) -> "LLM | None":
        """Build from env vars, or return None so the firewall runs heuristics-only."""
        key = os.environ.get("FIREWALL_API_KEY") or os.environ.get("NEBIUS_API_KEY")
        model = os.environ.get("FIREWALL_MODEL")
        if not (key and model):
            return None
        from openai import OpenAI

        base_url = os.environ.get("FIREWALL_BASE_URL", DEFAULT_BASE_URL)
        cap = os.environ.get("FIREWALL_MAX_LLM_CALLS")
        return cls(OpenAI(base_url=base_url, api_key=key), model, max_calls=int(cap) if cap else None)

    def judge(self, system: str, user: str) -> dict:
        """Run one judgement call and parse the JSON object it returns."""
        with self._lock:
            if self.max_calls is not None and self.attempts >= self.max_calls:
                raise LLMError(f"LLM call budget of {self.max_calls} exhausted")
            self.attempts += 1
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                max_tokens=self._max_tokens,
                temperature=0,
                timeout=self._timeout,
            )
        except Exception as e:  # network, auth, rate limit: caller falls back to heuristics
            raise LLMError(f"LLM call failed: {e}") from e

        with self._lock:
            self.calls += 1
            usage = getattr(resp, "usage", None)
            if usage is not None:
                self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
                self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0

        return parse_json_object(resp.choices[0].message.content or "")


def parse_json_object(text: str) -> dict:
    """Extract the first JSON object from a model reply (tolerates fences and <think> blocks)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError(f"no JSON object in reply: {text[:200]!r}")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as e:
        raise LLMError(f"bad JSON in reply: {e}") from e


def fence(label: str, text: str) -> str:
    """Wrap untrusted text in a random delimiter so it can't close the block itself."""
    tag = secrets.token_hex(4)
    return f"<<{label}-{tag}>>\n{text}\n<</{label}-{tag}>>"
