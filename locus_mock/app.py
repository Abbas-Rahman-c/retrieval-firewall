"""Mock RAG workspace API with the retrieval firewall in front of it, plus the demo site.

Run:  uvicorn locus_mock.app:app --reload --port 8000
Site: http://localhost:8000      Docs: http://localhost:8000/docs
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from firewall import AllowAll, MetadataFilter, MetadataPlusGuard, RetrievalFirewall

from .store import Workspace

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

Mode = Literal["none", "baseline1", "baseline2", "firewall"]

app = FastAPI(title="Mock RAG workspace + Retrieval Firewall", version="0.1.0")
workspace = Workspace()
_inspectors: dict[str, object] = {}

# Public-deploy guards. Modes that spend credits can be switched off with ALLOWED_MODES.
ALLOWED_MODES = {m.strip() for m in os.environ.get("ALLOWED_MODES", "none,baseline1,baseline2,firewall").split(",")}
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "40"))
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def client_ip(request: Request) -> str:
    """Best guess at the visitor's IP.

    Render sits behind Cloudflare, which sets CF-Connecting-IP to the real client and overwrites any
    value the client sends, so it can't be spoofed there. The last X-Forwarded-For hop is a Cloudflare
    edge that changes per request, so it is only a fallback for other hosts.
    """
    for header in ("cf-connecting-ip", "true-client-ip"):
        if value := request.headers.get(header):
            return value.strip()
    if forwarded := request.headers.get("x-forwarded-for"):
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request) -> None:
    """Sliding one-minute window per client IP on the endpoints that do work."""
    if RATE_LIMIT_PER_MIN <= 0:
        return
    ip = client_ip(request)
    now = time.monotonic()
    with _hits_lock:
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MIN:
            raise HTTPException(429, "Too many requests, try again in a minute.")
        q.append(now)
        if len(_hits) > 10_000:  # drop idle clients so memory stays bounded
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                del _hits[k]


def get_inspector(mode: Mode):
    if mode not in ALLOWED_MODES:
        raise HTTPException(403, f"mode {mode!r} is disabled on this deployment")
    if mode not in _inspectors:
        if mode == "none":
            _inspectors[mode] = AllowAll()
        elif mode == "baseline1":
            _inspectors[mode] = MetadataFilter()
        elif mode == "baseline2":
            try:
                _inspectors[mode] = MetadataPlusGuard()
            except RuntimeError as e:
                raise HTTPException(503, str(e))
        else:
            _inspectors[mode] = RetrievalFirewall()
    return _inspectors[mode]


class AskRequest(BaseModel):
    user_id: str
    query: str = Field(min_length=1, max_length=2000)
    mode: Mode = "firewall"
    top_k: int = Field(5, ge=1, le=20)


@app.get("/health")
def health():
    fw = get_inspector("firewall")
    return {"ok": True, "firewall_mode": "llm" if fw.llm else "heuristic-only", "chunks": len(workspace.chunks)}


@app.get("/users")
def users():
    return [
        {**asdict(u), "name": workspace.user_names[u.id], "live": asdict(workspace.idp[u.id]) if u.id in workspace.idp else None}
        for u in workspace.users.values()
    ]


@app.get("/samples")
def samples():
    return workspace.sample_queries


@app.get("/idp/{user_id}")
def identity(user_id: str):
    """The live identity provider: the source of truth the firewall re-checks against."""
    if user_id not in workspace.idp:
        raise HTTPException(404, "unknown user")
    return asdict(workspace.idp[user_id])


@app.post("/retrieve", dependencies=[Depends(rate_limit)])
def retrieve(req: AskRequest):
    """Raw retrieval exactly as the RAG index returns it, before any firewall."""
    user = _user(req.user_id)
    return [{**asdict(h.chunk), "score": h.score} for h in workspace.retrieve(user, req.query, req.top_k)]


@app.post("/ask", dependencies=[Depends(rate_limit)])
def ask(req: AskRequest):
    """Retrieve, run the chosen inspector, and return what the LLM would be allowed to see."""
    user = _user(req.user_id)
    hits = workspace.retrieve(user, req.query, req.top_k)
    chunks = [h.chunk for h in hits]
    inspector = get_inspector(req.mode)

    started = time.perf_counter()
    verdicts = inspector.inspect(req.query, user, chunks, workspace.idp)
    latency_ms = round((time.perf_counter() - started) * 1000, 1)

    return {
        "user": {**asdict(user), "name": workspace.user_names[user.id]},
        "query": req.query,
        "mode": req.mode,
        "retrieved": [{**asdict(h.chunk), "score": h.score} for h in hits],
        "verdicts": [asdict(v) for v in verdicts],
        "context": [v.text for v in verdicts if v.action != "block"],
        "trace": getattr(inspector, "last_trace", []),
        "stats": {**getattr(inspector, "last_stats", {}), "latency_ms": latency_ms},
    }


@app.get("/results")
def results():
    """Latest benchmark results written by benchmark/run.py."""
    path = ROOT / "results.json"
    if not path.exists():
        raise HTTPException(404, "no results yet; run python benchmark/run.py")
    return json.loads(path.read_text(encoding="utf-8"))


def _user(user_id: str):
    if user_id not in workspace.users:
        raise HTTPException(404, f"unknown user {user_id!r}")
    return workspace.users[user_id]


# The demo site. Mounted last so the API routes above take precedence.
app.mount("/", StaticFiles(directory=ROOT / "web", html=True), name="web")
