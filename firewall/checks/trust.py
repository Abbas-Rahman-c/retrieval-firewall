"""Poisoned-document triage: risky operational claims weighed against source trust."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .injection import _QUOTED

_RISKY_CLAIMS = [
    (r"\b(?:disable|turn off|deactivate|bypass|skip|remove)\b[^.\n]{0,30}\b(?:mfa|2fa|multi[- ]factor|two[- ]factor|"
     r"antivirus|firewall|verification|encryption|vpn|sso|security checks?|code review)\b",
     0.5, "tells readers to weaken a security control"),
    (r"\b(?:route|send|tunnel|proxy)\b[^.\n]{0,30}\b(?:traffic|requests|connections)\b[^.\n]{0,30}\b(?:through|via)\b",
     0.35, "redirects traffic through an intermediary"),
    (r"\b(?:moved|migrated|relocated|changed)\b[^.\n]{0,25}\bto\b\s+\S+\.\w{2,}", 0.5, "claims a service moved to a new address"),
    (r"\bnew\s+(?:server|portal|login|address|url|domain|endpoint|payment details|bank account)\b", 0.35,
     "announces a new address or account"),
    (r"\b(?:send|email|share|submit|enter|post|paste|upload|forward)\b[^.\n]{0,40}\b(?:passwords?|credentials|otp|"
     r"one[- ]time code|verification code|card details|private keys?|ssh keys?|api keys?|secrets?)\b",
     0.5, "asks readers to share credentials"),
    (r"\bunauthenticated\b|\bno login required\b", 0.3, "points to an unauthenticated endpoint"),
    # Business-email-compromise style payment redirection.
    (r"\b(?:bank|payment|wire|account|remittance)\s+(?:details|information|instructions)\b[^.\n]{0,40}\b(?:changed|updated|new)\b|"
     r"\b(?:send|transfer|wire|pay|route)\b[^.\n]{0,40}\b(?:payments?|funds|money|invoices?)\b[^.\n]{0,40}\b(?:new|different|updated)\s+account\b",
     0.5, "redirects payments to a new account"),
    (r"\bset (?:your|the) password to\b|\b(?:same|shared|default|common) (?:password|credentials)\b",
     0.5, "prescribes a weak or shared password"),
    # Moving internal data to places it should not go.
    (r"\b(?:paste|upload|forward|send|copy|share|email)\b[^.\n]{0,40}\b(?:customer|production|client|personal|internal|"
     r"security|confidential)\b[^.\n]{0,30}\b(?:data|records|digest|files|information|emails?|reports?)\b[^.\n]{0,40}"
     r"\b(?:public|personal|external|third[- ]party|chatbot|private email|outside)\b", 0.5, "moves internal data outside"),
    (r"\b(?:skip|bypass|ignore|waive)\b[^.\n]{0,25}\b(?:review|approval|sign[- ]off|testing|change management)\b",
     0.45, "tells readers to skip a control process"),
    (r"\b(?:install|download|pull)\b[^.\n]{0,40}\bfrom\b[^.\n]{0,25}\b(?:mirror|unofficial|external|personal)\b",
     0.4, "points to an unofficial software source"),
]
_AUTHORITY = re.compile(r"\b(?:official notice|mandatory|effective immediately|all (?:staff|employees|engineers) must|"
                        r"by order of|required for all)\b", re.IGNORECASE)
# Security-awareness material quotes scams to teach people to spot them.
_DISCUSSION = re.compile(r"\b(?:phishing|scam|fraud(?:ulent)?|training|how to (?:spot|report)|examples? (?:like|of)|such as|"
                         r"emails? like|we (?:will )?never ask|never asks?|red[- ]team|awareness)\b", re.IGNORECASE)
_URLISH = re.compile(r"https?://([^\s/:]+)|\b((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b|\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|xyz|ru|info|biz|co|app))\b",
                     re.IGNORECASE)


@dataclass
class TrustScore:
    risk: float
    signals: list[str]


def score_poisoning(text: str, trusted_domains: frozenset[str] = frozenset()) -> TrustScore:
    keep = 1.0
    signals: list[str] = []
    quoted = [m.span() for m in _QUOTED.finditer(text)]
    discussing = bool(_DISCUSSION.search(text))
    for pat, weight, label in _RISKY_CLAIMS:
        m = re.search(pat, text, re.IGNORECASE)
        if not m:
            continue
        if discussing and any(a <= m.start() and m.end() <= b for a, b in quoted):
            weight *= 0.3
            label += " (quoted in awareness material)"
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
