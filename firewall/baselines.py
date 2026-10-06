"""Reference setups the firewall agent is compared against.

- AllowAll:            no checks at all. Useful for testing the harness end to end.
- MetadataFilter:      Baseline 1. Only looks at index metadata, never reads text.
- MetadataPlusGuard:   Baseline 2. Baseline 1 plus a per-chunk Llama Guard call.
"""

from __future__ import annotations

import os

from .interface import Chunk, IdentityState, User, Verdict


class AllowAll:
    name = "allow_all"

    def inspect(self, query, user, chunks, idp_state=None):
        return [Verdict(c.id, "allow", c.text, "no checks") for c in chunks]


class MetadataFilter:
    """Baseline 1: how most RAG stacks do it today.

    Trusts the ACL tags stored in the index and ignores the live identity
    provider, so stale permissions, injection, PII and poisoning all pass.
    """

    name = "baseline1_metadata"

    def inspect(self, query, user, chunks, idp_state=None):
        return [self._check(user, c) for c in chunks]

    @staticmethod
    def _check(user: User, chunk: Chunk) -> Verdict:
        if chunk.acl and not set(chunk.acl) & set(user.roles):
            return Verdict(chunk.id, "block", None, "user has none of the chunk's ACL roles")
        if user.clearance < chunk.min_clearance:
            return Verdict(chunk.id, "block", None, "clearance below chunk minimum")
        return Verdict(chunk.id, "allow", chunk.text, "metadata ok")


class MetadataPlusGuard:
    """Baseline 2: Baseline 1, then Llama Guard on each surviving chunk.

    Calls an OpenAI-compatible endpoint (Nebius Token Factory). Configure with
    NEBIUS_API_KEY, NEBIUS_BASE_URL and LLAMA_GUARD_MODEL in .env.
    """

    name = "baseline2_metadata_llamaguard"

    def __init__(self, client=None, model: str | None = None):
        self._meta = MetadataFilter()
        self._model = model or os.environ.get("LLAMA_GUARD_MODEL")
        self._client = client
        if self._client is None:
            base_url = os.environ.get("NEBIUS_BASE_URL")
            if not (base_url and self._model and os.environ.get("NEBIUS_API_KEY")):
                raise RuntimeError(
                    "Baseline 2 needs NEBIUS_API_KEY, NEBIUS_BASE_URL and LLAMA_GUARD_MODEL set"
                )
            from openai import OpenAI  # imported lazily so Baseline 1 needs no deps

            self._client = OpenAI(base_url=base_url, api_key=os.environ["NEBIUS_API_KEY"])

    def inspect(self, query, user, chunks, idp_state=None):
        verdicts = self._meta.inspect(query, user, chunks, idp_state)
        for v in verdicts:
            if v.action == "allow" and self._is_unsafe(v.text or ""):
                v.action, v.text, v.reason = "block", None, "Llama Guard: unsafe"
        return verdicts

    def _is_unsafe(self, text: str) -> bool:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": text}],
            max_tokens=10,
            temperature=0,
        )
        # Llama Guard replies "safe" or "unsafe\n<category>".
        return resp.choices[0].message.content.strip().lower().startswith("unsafe")
