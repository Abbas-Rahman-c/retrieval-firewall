"""Gate for the aggregation judge: only pay for an LLM call when chunks could combine.

The gate fires when at least two chunks mention the same entity and the set
touches something sensitive. The judgement itself is done by the LLM.
"""

from __future__ import annotations

import re
from collections import defaultdict

_SENSITIVE = re.compile(
    r"\b(?:salar(?:y|ies)|compensation|payroll|bonus|pay (?:scale|grade|band)|master keys?|vault|password|"
    r"credentials?|diagnos\w+|medical|health|disciplinary|termination|layoffs?|acquisition|merger|"
    r"clearance|classified|confidential|home address|ssn|social security|criminal|performance review)\b",
    re.IGNORECASE,
)
_ID_ENTITY = re.compile(r"\b(?:employee|emp|user|staff|customer|patient|account|badge)\s*(?:id|#|no\.?|number)?\s*[:#]?\s*(\d{2,})\b",
                        re.IGNORECASE)
_LEVEL_ENTITY = re.compile(r"\b(?:level|grade|band|tier|scale)\s*(\w+)\b", re.IGNORECASE)
_PROPER_NOUN = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b")
_STOP_PHRASES = {"Chunk A", "Chunk B", "Chunk C", "User Clearance", "Project Manager"}


def _entities(text: str) -> set[str]:
    ents = {f"id:{m.group(1)}" for m in _ID_ENTITY.finditer(text)}
    ents |= {f"level:{m.group(1).lower()}" for m in _LEVEL_ENTITY.finditer(text)}
    ents |= {f"name:{m.group(1).lower()}" for m in _PROPER_NOUN.finditer(text) if m.group(1) not in _STOP_PHRASES}
    return ents


def aggregation_risk(texts: dict[str, str]) -> tuple[bool, list[str]]:
    """Return (should_judge, evidence) for a set of chunk texts keyed by chunk id."""
    if len(texts) < 2:
        return False, []
    sensitive_ids = [cid for cid, t in texts.items() if _SENSITIVE.search(t)]
    if not sensitive_ids:
        return False, []

    seen: dict[str, set[str]] = defaultdict(set)
    for cid, t in texts.items():
        for e in _entities(t):
            seen[e].add(cid)
    shared = sorted(e for e, ids in seen.items() if len(ids) >= 2)
    if not shared:
        return False, []
    return True, [f"shared entities: {', '.join(shared[:5])}", f"sensitive chunks: {', '.join(sensitive_ids)}"]
