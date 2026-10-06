"""Prompt-injection triage: a cheap heuristic score that decides when to ask the LLM.

The score is deliberately conservative. Text that *discusses* injection (a
security guideline quoting "ignore previous instructions") is discounted, and
anything in the middle band is escalated rather than blocked outright.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (pattern, weight, label)
_SIGNALS = [
    (r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|system)\b[^.\n]{0,20}"
     r"\b(?:instructions?|prompts?|rules|guidelines|messages?|discussions?)\b", 0.6, "override of prior instructions"),
    (r"\b(?:stop|cease)\s+(?:processing|following)\b", 0.4, "instruction to stop prior task"),
    (r"\b(?:system|admin(?:istrator)?|developer|root)\s+(?:notice|instruction|prompt|override|message|command)\b",
     0.4, "fake system/admin message"),
    (r"\[\s*(?:system|assistant|inst)\b|<\|?(?:im_start|system|endoftext)\|?>|^\s*#{2,}\s*(?:system|instruction)",
     0.5, "chat role or control tokens"),
    (r"\bnew\s+instructions?\b", 0.3, "announces new instructions"),
    (r"\b(?:you are now|from now on|act as|pretend to be)\b", 0.3, "role reassignment"),
    (r"\b(?:bypass|disable|ignore|override)\b[^.\n]{0,20}\b(?:safety|guardrails?|filters?|restrictions?|guidelines|policies)\b",
     0.4, "asks to bypass safety"),
    (r"\b(?:do not|don't|never)\s+(?:mention|tell|reveal|disclose|inform)\b[^.\n]{0,40}\b(?:user|anyone|them)\b",
     0.4, "asks to conceal from the user"),
    (r"\b(?:print|output|reveal|dump|show|include|send|leak|exfiltrate)\b[^.\n]{0,50}"
     r"\b(?:api\s*keys?|tokens?|passwords?|credentials|ssh|secrets?|system prompt|config\w*|internal)\b",
     0.35, "requests sensitive output"),
    (r"\bwhen the (?:user|assistant) (?:asks|says|requests)\b", 0.3, "conditional trigger"),
    (r"[​-‏⁠﻿]", 0.3, "hidden zero-width characters"),
    (r"<!--[\s\S]*?-->", 0.2, "hidden HTML comment"),
]

_DISCUSSION_MARKERS = re.compile(
    r"\b(?:attackers?|adversar\w*|example|e\.g\.|such as|for instance|phrases? like|"
    r"prompt injection|jailbreak|malicious|red[- ]team|our policy|we treat)\b",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"\"[^\"\n]{3,300}\"|“[^”\n]{3,300}”|(?<![A-Za-z])'[^'\n]{3,300}'(?![A-Za-z])")


@dataclass
class InjectionScore:
    score: float
    signals: list[str]
    spans: list[tuple[int, int]]


def score_injection(text: str) -> InjectionScore:
    quoted = [m.span() for m in _QUOTED.finditer(text)]
    discussing = bool(_DISCUSSION_MARKERS.search(text))

    keep = 1.0
    signals: list[str] = []
    spans: list[tuple[int, int]] = []
    for pat, weight, label in _SIGNALS:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if not m:
            continue
        inside_quote = any(a <= m.start() and m.end() <= b for a, b in quoted)
        if discussing and inside_quote:
            weight *= 0.3
            label += " (quoted in discussion)"
        keep *= 1 - weight
        signals.append(label)
        spans.append(m.span())
    return InjectionScore(round(1 - keep, 3), signals, spans)
