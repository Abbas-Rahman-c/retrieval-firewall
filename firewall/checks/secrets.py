"""Deterministic secret and PII detection with in-place redaction.

Secrets are always redacted. PII is redacted unless the user holds a role
listed in the policy's `pii_allowed_roles` (e.g. HR reading HR records).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    kind: str  # e.g. "secret:slack_token", "pii:ssn"
    start: int
    end: int

    @property
    def is_secret(self) -> bool:
        return self.kind.startswith("secret:")


# Well-known credential formats.
_SECRET_FORMATS = {
    "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "slack_token": r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    "openai_style_key": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    "connection_string": r"\b[a-z+]+://[^\s:/@]+:[^\s@]+@[^\s]+",
}

# A credential introduced in context ("password: x", "combination word: y", "token = z").
_SECRET_KEYWORDS = (
    r"pass(?:word|phrase|code)?|pwd|secret|api[\s_-]?key|access[\s_-]?key|token|"
    r"credential|combination|pin(?:\s*code)?|private[\s_-]?key|auth[\s_-]?code"
)
_CONTEXTUAL_SECRET = re.compile(
    rf"\b(?:{_SECRET_KEYWORDS})\b[^\n:=]{{0,30}}?(?:[:=]|\bis\b)\s*['\"`]?(?P<val>[^\s'\"`,;]{{6,}})",
    re.IGNORECASE,
)

_PII_FORMATS = {
    "ssn": r"\b\d{3}-\d{2}-[\dX]{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone": r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)",
    "card_number": r"\b(?:\d[ -]?){13,19}\b",
}

# Labelled PII fields: redact the value up to the end of the line.
_PII_LABELS = re.compile(
    r"\b(?:home\s+address|address|date\s+of\s+birth|dob|passport(?:\s+(?:no|number))?|"
    r"social\s+security(?:\s+number)?|driver'?s?\s+licen[cs]e(?:\s+number)?|personal\s+(?:email|phone))"
    r"\s*:\s*(?P<val>[^\n]+)",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits][::-1]
    total = sum(n if i % 2 == 0 else (n * 2 - 9 if n * 2 > 9 else n * 2) for i, n in enumerate(nums))
    return total % 10 == 0


def _looks_like_secret(value: str) -> bool:
    """Filter contextual matches so 'password: required' or 'token: see docs' don't count."""
    if value.lower() in {"required", "optional", "none", "null", "redacted", "[redacted]", "hidden"}:
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    has_sym = any(c in "_-!@#$%^&*." for c in value)
    if has_alpha and (has_digit or has_sym):
        return True
    # Long random-looking strings without digits still count.
    counts = {c: value.count(c) for c in set(value)}
    entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
    return len(value) >= 16 and entropy > 3.5


def find_sensitive(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for kind, pat in _SECRET_FORMATS.items():
        hits += [Hit(f"secret:{kind}", m.start(), m.end()) for m in re.finditer(pat, text)]
    for m in _CONTEXTUAL_SECRET.finditer(text):
        if _looks_like_secret(m.group("val")):
            hits.append(Hit("secret:contextual", m.start("val"), m.end("val")))
    for kind, pat in _PII_FORMATS.items():
        for m in re.finditer(pat, text):
            if kind == "card_number":
                digits = re.sub(r"\D", "", m.group())
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
            hits.append(Hit(f"pii:{kind}", m.start(), m.end()))
    for m in _PII_LABELS.finditer(text):
        hits.append(Hit("pii:labelled_field", m.start("val"), m.end("val")))
    return _merge(hits)


def _merge(hits: list[Hit]) -> list[Hit]:
    """Drop overlapping hits, preferring secrets and longer spans."""
    hits.sort(key=lambda h: (h.start, -(h.end - h.start), not h.is_secret))
    out: list[Hit] = []
    for h in hits:
        if out and h.start < out[-1].end:
            prev = out[-1]
            if h.end > prev.end:
                out[-1] = Hit(prev.kind if prev.is_secret or not h.is_secret else h.kind, prev.start, h.end)
            continue
        out.append(h)
    return out


def redact(text: str, hits: list[Hit]) -> str:
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        label = h.kind.split(":", 1)[1].upper()
        text = text[: h.start] + f"[REDACTED:{label}]" + text[h.end :]
    return text
