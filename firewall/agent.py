"""The retrieval firewall agent (Person A). Not implemented yet.

Same interface as the baselines, so the harness can run it as soon as it lands.
"""

from __future__ import annotations

from .interface import Chunk, IdentityState, User, Verdict


class RetrievalFirewall:
    name = "retrieval_firewall"

    def inspect(
        self,
        query: str,
        user: User,
        chunks: list[Chunk],
        idp_state: dict[str, IdentityState] | None = None,
    ) -> list[Verdict]:
        raise NotImplementedError("Firewall agent not built yet; use AllowAll to test the harness")
