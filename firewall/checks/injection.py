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
    # Attempts to cancel or replace the instructions the model is following.
    (r"\b(?:ignore|disregard|forget|override|bypass|skip|halt|terminate|reset|suspend|cancel)\b[^.\n]{0,40}"
     r"\b(?:previous|prior|above|earlier|original|current|all|existing|system|safety|security)\b[^.\n]{0,25}"
     r"\b(?:instructions?|prompts?|rules|guidelines|messages?|discussions?|context|filters?|boundar(?:y|ies)|"
     r"restrictions?|polic(?:y|ies)|directives?|constraints?|guardrails?|processing)\b", 0.6, "override of prior instructions"),
    (r"\b(?:stop|cease|halt)\s+(?:processing|following)\b", 0.4, "instruction to stop prior task"),
    (r"\btreat\b[^.\n]{0,40}\bas\b[^.\n]{0,20}\b(?:prompt|instruction|command|system message)\b", 0.5,
     "asks for text to be treated as instructions"),
    # Text speaking to the model rather than to a human reader.
    (r"\b(?:attention|note to|message to|dear|hey)\s+(?:the\s+|all\s+|any\s+)?(?:llm|ai|assistant|language model|chatbot|agent|model)s?\b|"
     r"\bif you are an?\s+(?:ai|llm|language model|assistant|chatbot|bot)\b|"
     r"\b(?:ai|llm)\s+(?:agents?|assistants?|models?)\s+(?:reading|summari[sz]ing|processing|parsing)\b|"
     r"^\s*(?:assistant|ai|system)\s*:|\.\s+(?:assistant|ai)\s*:\s", 0.5, "addresses the AI directly"),
    # Fake authority headers.
    (r"\b(?:system|admin(?:istrator)?|developer|root|security)\s+(?:notice|instruction|prompt|override|message|command|"
     r"update|error|debug|alert|protocol|note|routine)\b|\b(?:instruction change|override (?:instructions|warning|protocol)|"
     r"critical (?:alert|error)|important directive|emergency patch|operational change notice)\b",
     0.35, "fake system/admin message"),
    (r"\[\s*(?:system|assistant|inst)\b|<\|?(?:im_start|system|endoftext)\|?>|^\s*#{2,}\s*(?:system|instruction)",
     0.5, "chat role or control tokens"),
    (r"\bnew\s+instructions?\b", 0.3, "announces new instructions"),
    (r"\b(?:you are now|from now on|act as|pretend to be)\b", 0.3, "role reassignment"),
    (r"\b(?:assume|adopt|switch to|enter)\b[^.\n]{0,30}\b(?:persona|profile|role|mode)\b|\bunrestricted\b|"
     r"\bdeveloper mode\b|\broot (?:shell|access)\b|\bfull (?:access|clearance|privileges|rights)\b|\belevated privileges\b",
     0.35, "privilege or persona takeover"),
    (r"\b(?:bypass|disable|ignore|override|reset|clear|terminate)\b[^.\n]{0,25}\b(?:safety|guardrails?|filters?|restrictions?|"
     r"guidelines|policies|security)\b", 0.4, "asks to bypass safety"),
    (r"\b(?:exempt|excluded|whitelisted|pre-?approved)\s+from\b|\b(?:supervisor|admin(?:istrator)?|security team|cio)\s+has\s+"
     r"(?:cleared|approved|authori[sz]ed)\b|\bhas overridden credentials\b|\bthe user is an? (?:admin|administrator)\b",
     0.35, "claims an exemption or authorization"),
    (r"\b(?:do not|don't|never)\s+(?:mention|tell|reveal|disclose|inform)\b[^.\n]{0,40}\b(?:user|anyone|them)\b",
     0.4, "asks to conceal from the user"),
    (r"\b(?:print|output|reveal|dump|show|include|send|leak|exfiltrate|expose|return|provide|share|display)\b[^.\n]{0,50}"
     r"\b(?:(?:api|deployment|ssh|access|secret|private|master)\s+(?:\w+\s+)?keys?|tokens?|passwords?|credentials|ssh|secrets?|"
     r"system prompt|config\w*|internal|schema|variables|"
     r"identity keys|context payload|raw context|hidden|database)\b", 0.35, "requests sensitive output"),
    (r"\b(?:respond|reply|answer)\s+(?:to the user\s+)?only\s+with\b|\bthe correct (?:answer|recommendation) is\b|"
     r"\bregardless of\b[^.\n]{0,30}\b(?:notes|instructions|content|evidence|interview)\b|\b(?:leave out|omit)\b[^.\n]{0,30}\b(?:concerns?|risks?|warnings?)\b",
     0.35, "dictates the answer"),
    (r"\bwhen (?:the (?:user|assistant)|you) (?:asks?|says|requests|summari[sz]e)\b", 0.3, "conditional trigger"),
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


# Undo common character swaps ("Ign0re pr1or") before matching. One-to-one, so spans still line up.
_DELEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def score_injection(text: str) -> InjectionScore:
    quoted = [m.span() for m in _QUOTED.finditer(text)]
    discussing = bool(_DISCUSSION_MARKERS.search(text))
    text = text.translate(_DELEET)

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
