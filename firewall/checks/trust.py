"""Poisoned-document triage: risky operational claims weighed against source trust."""

from __future__ import annotations

import re
from dataclasses import dataclass

_RISKY_CLAIMS = [
    (r"\b(?:disable|turn off|deactivate|bypass|skip|remove)\b[^.\n]{0,30}\b(?:mfa|2fa|multi[- ]factor|two[- ]factor|"
     r"antivirus|firewall|verification|encryption|vpn|sso|security checks?|code review)\b",
     0.5, "tells readers to weaken a security control"),
    (r"\b(?:route|send|tunnel|proxy)\b[^.\n]{0,30}\b(?:traffic|requests|connections)\b[^.\n]{0,30}\b(?:through|via)\b",
     0.35, "redirects traffic through an intermediary"),
    (r"\b(?:moved|migrated|relocated|changed)\b[^.\n]{0,25}\bto\b\s+\S+\.\w{2,}", 0.5, "claims a service moved to a new address"),
    (r"\bnew\s+(?:server|portal|login|address|url|domain|endpoint|payment details|bank account)\b", 0.35,
     "announces a new address or account"),
    (r"\b(?:send|email|share|submit|enter)\b[^.\n]{0,30}\b(?:passwords?|credentials|otp|one[- ]time code|"
     r"verification code|card details)\b", 0.5, "asks readers for credentials"),
    (r"\bunauthenticated\b|\bno login required\b", 0.3, "points to an unauthenticated endpoint"),
]
_AUTHORITY = re.compile(r"\b(?:official notice|mandatory|effective immediately|all (?:staff|employees|engineers) must|"
                        r"by order of|required for all)\b", re.IGNORECASE)
_URLISH = re.compile(r"https?://([^\s/:]+)|\b((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b|\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|xyz|ru|info|biz|co|app))\b",
                     re.IGNORECASE)


@dataclass
class TrustScore:
    risk: float
    signals: list[str]


def score_poisoning(text: str, trusted_domains: frozenset[str] = frozenset()) -> TrustScore:
    keep = 1.0
    signals: list[str] = []
    for pat, weight, label in _RISKY_CLAIMS:
        if re.search(pat, text, re.IGNORECASE):
            keep *= 1 - weight
            signals.append(label)
    if _AUTHORITY.search(text):
        keep *= 0.85
        signals.append("authoritative framing")
    for m in _URLISH.finditer(text):
        host = next(g for g in m.groups() if g).lower()
        if not any(host == d or host.endswith("." + d) for d in trusted_domains):
            keep *= 0.8
            signals.append(f"untrusted destination {host}")
            break
    return TrustScore(round(1 - keep, 3), signals)
