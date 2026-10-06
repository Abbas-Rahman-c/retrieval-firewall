"""In-memory workspace: users, a mock identity provider and a keyword retriever.

The retriever behaves like a typical RAG index: it filters chunks by the ACL
tags and user roles *as copied into the index*, then ranks by BM25. It never
consults the live identity provider, which is exactly the gap the firewall closes.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from firewall import Chunk, IdentityState, User

DATA_PATH = Path(__file__).with_name("data.json")
_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = {"the", "a", "an", "of", "to", "in", "and", "or", "is", "are", "on", "for", "what", "how", "do",
              "does", "i", "my", "say", "about", "who", "should", "did", "with", "at", "this", "that", "it"}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]


@dataclass
class Hit:
    chunk: Chunk
    score: float


class Workspace:
    def __init__(self, path: Path = DATA_PATH):
        data = json.loads(path.read_text(encoding="utf-8"))
        self.users = {u["id"]: User(u["id"], u["roles"], u["clearance"]) for u in data["users"]}
        self.user_names = {u["id"]: u["name"] for u in data["users"]}
        self.idp = {uid: IdentityState(**s) for uid, s in data["identity_provider"].items()}
        self.chunks = [Chunk(**c) for c in data["chunks"]]
        self.sample_queries = data.get("sample_queries", [])

        self._tf = [Counter(_tokens(c.text)) for c in self.chunks]
        self._len = [sum(tf.values()) for tf in self._tf]
        self._avg_len = sum(self._len) / max(len(self._len), 1)
        df = Counter(t for tf in self._tf for t in tf)
        n = len(self.chunks)
        self._idf = {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}

    def retrieve(self, user: User, query: str, top_k: int = 5) -> list[Hit]:
        """BM25 over chunks the index says this user can read (index-copy roles, not live ones)."""
        k1, b = 1.5, 0.75
        terms = _tokens(query)
        hits = []
        for i, c in enumerate(self.chunks):
            if c.acl and not set(c.acl) & set(user.roles):
                continue
            tf = self._tf[i]
            norm = k1 * (1 - b + b * self._len[i] / self._avg_len)
            score = sum(self._idf.get(t, 0) * tf[t] * (k1 + 1) / (tf[t] + norm) for t in terms if t in tf)
            if score > 0:
                hits.append(Hit(c, round(score, 3)))
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]
