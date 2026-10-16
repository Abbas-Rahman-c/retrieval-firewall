"""Shared contract between the firewall, the baselines and the benchmark harness.

Every setup (Baseline 1, Baseline 2, the firewall agent) implements `Inspector`.
The harness only ever calls `inspect(query, user, chunks)` and grades the verdicts
against each test case's `expected` map, so setups are interchangeable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

Action = Literal["allow", "redact", "block"]


@dataclass(frozen=True)
class User:
    id: str
    roles: list[str]
    clearance: int = 0


@dataclass(frozen=True)
class Chunk:
    id: str
    text: str
    source: str = ""
    # Access tags as copied into the vector index. May be stale.
    acl: list[str] = field(default_factory=list)
    min_clearance: int = 0
    uploader_trust: Literal["high", "medium", "low"] = "medium"


@dataclass(frozen=True)
class IdentityState:
    """What the live identity provider says right now (the source of truth)."""
    roles: list[str]
    active: bool = True


@dataclass
class Verdict:
    chunk_id: str
    action: Action
    # Text to pass to the LLM: the original for "allow", masked for "redact", None for "block".
    text: str | None
    reason: str = ""
    # Signals that led to the decision, for the demo UI and debugging.
    evidence: list[str] = field(default_factory=list)


@dataclass
class TestCase:
    id: str
    category: str
    malicious: bool
    query: str
    user: User
    chunks: list[Chunk]
    expected: dict[str, Action]
    idp_state: dict[str, IdentityState] = field(default_factory=dict)
    # Strings that must not reach the LLM, per chunk (graded on secret/PII cases).
    must_not_leak: dict[str, list[str]] = field(default_factory=dict)
    # Where the case text came from, so results can be split by author.
    origin: str = ""
    # "all": every chunk expected to be stopped must be stopped (one leak is a breach).
    # "any": stopping one is enough (e.g. aggregation, where removing one link breaks the inference).
    catch: str = "all"
    split: str = ""


class Inspector(Protocol):
    name: str

    def inspect(
        self,
        query: str,
        user: User,
        chunks: list[Chunk],
        idp_state: dict[str, IdentityState] | None = None,
    ) -> list[Verdict]:
        """Return exactly one Verdict per input chunk, in the same order."""
        ...


def load_cases(path: str | Path) -> list[TestCase]:
    """Load test cases from a JSON file holding a list of case objects."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        TestCase(
            id=c["id"],
            category=c["category"],
            malicious=c["malicious"],
            query=c["query"],
            user=User(**c["user"]),
            chunks=[Chunk(**ch) for ch in c["chunks"]],
            expected=c["expected"],
            idp_state={uid: IdentityState(**s) for uid, s in c.get("idp_state", {}).items()},
            must_not_leak=c.get("must_not_leak", {}),
            origin=c.get("origin", ""),
            catch=c.get("catch", "all"),
            split=c.get("split", ""),
        )
        for c in raw
    ]
