"""The retrieval firewall agent.

Every request goes through three stages:

1. Triage (every chunk, no LLM): live permission re-check, injection score,
   poisoning score. Permission failures are blocked immediately.
2. Investigation (only flagged chunks, LLM): the agent ranks the risky chunks,
   spends its per-request LLM budget on the most suspicious ones, and falls
   back to heuristic rules for the rest or when the LLM is unavailable.
3. Release: secrets/PII are redacted from what survives, then an aggregation
   judge looks at the surviving set as a whole when the chunks could combine.

Every decision is recorded in `last_trace` so the demo can show why.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import prompts
from .checks.aggregation import aggregation_risk
from .checks.injection import InjectionScore, score_injection
from .checks.permissions import check_permission
from .checks.secrets import find_sensitive, redact
from .checks.trust import TrustScore, score_poisoning
from .interface import Action, Chunk, IdentityState, User, Verdict
from .llm import LLM, LLMError, fence

INJECTION_PLACEHOLDER = "[REMOVED:INJECTED_INSTRUCTION]"


@dataclass(frozen=True)
class Policy:
    fail_closed_identity: bool = True
    # Injection score bands: >= block_at is blocked outright, >= escalate_at goes to the LLM.
    injection_block_at: float = 0.75
    injection_escalate_at: float = 0.3
    injection_offline_block_at: float = 0.5
    # Poisoning risk bands (high-trust sources are never flagged for poisoning).
    poison_escalate_at: float = 0.35
    poison_offline_block_at: float = 0.5
    llm_min_confidence: float = 0.6
    pii_allowed_roles: frozenset[str] = frozenset({"hr"})
    trusted_domains: frozenset[str] = frozenset()
    # Users at or above this clearance may combine anything they can read.
    aggregation_exempt_clearance: int = 3
    # Without an LLM to judge, withhold sensitive chunks that link to others.
    aggregation_fail_closed: bool = True
    max_llm_calls: int = 6
    # With a judge available, also screen chunks from non-high-trust sources that the rules scored zero.
    llm_screen_untrusted: bool = True
    # With a judge available, check every multi-chunk set for aggregation, not only what the rule gate flags.
    llm_always_judge_aggregation: bool = True


@dataclass
class _ChunkState:
    chunk: Chunk
    action: Action = "allow"
    text: str | None = None
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    injection: InjectionScore | None = None
    poisoning: TrustScore | None = None

    def block(self, reason: str) -> None:
        self.action, self.text = "block", None
        self.reasons.append(reason)

    def verdict(self) -> Verdict:
        reason = "; ".join(self.reasons) or "passed all checks"
        return Verdict(self.chunk.id, self.action, self.text, reason, self.evidence)


class RetrievalFirewall:
    name = "retrieval_firewall"

    def __init__(self, llm: LLM | None = None, policy: Policy | None = None, use_env: bool = True):
        self.llm = llm if llm is not None else (LLM.from_env() if use_env else None)
        self.policy = policy or Policy()
        self.last_trace: list[dict] = []
        self.last_stats: dict = {}

    def inspect(
        self,
        query: str,
        user: User,
        chunks: list[Chunk],
        idp_state: dict[str, IdentityState] | None = None,
    ) -> list[Verdict]:
        started = time.perf_counter()
        calls_before = self.llm.calls if self.llm else 0
        self.last_trace = []
        self._budget = self.policy.max_llm_calls if self.llm else 0

        states = [_ChunkState(c, text=c.text) for c in chunks]
        live_roles = self._live_roles(user, idp_state)

        self._triage(user, states, idp_state)
        self._investigate(states)
        self._redact_sensitive(states, live_roles)
        self._judge_aggregation(query, user, states)

        self.last_stats = {
            "llm_calls": (self.llm.calls - calls_before) if self.llm else 0,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "mode": "llm" if self.llm else "heuristic-only",
        }
        return [s.verdict() for s in states]

    # Stage 1 ---------------------------------------------------------------

    def _triage(self, user: User, states: list[_ChunkState], idp_state) -> None:
        for s in states:
            denied = check_permission(user, s.chunk, idp_state, self.policy.fail_closed_identity)
            if denied:
                s.block(f"permission: {denied}")
                self._log("permission", s, denied)
                continue
            s.injection = score_injection(s.chunk.text)
            s.poisoning = score_poisoning(s.chunk.text, self.policy.trusted_domains)
            s.evidence += [f"injection: {x}" for x in s.injection.signals]
            s.evidence += [f"poisoning: {x}" for x in s.poisoning.signals]
            self._log("triage", s, f"injection={s.injection.score} poisoning={s.poisoning.risk} trust={s.chunk.uploader_trust}")

    # Stage 2 ---------------------------------------------------------------

    def _investigate(self, states: list[_ChunkState]) -> None:
        p = self.policy
        trusted = [s for s in states if s.action != "block" and s.chunk.uploader_trust == "high"]
        tasks: list[tuple[float, str, _ChunkState]] = []

        for s in states:
            if s.action == "block":
                continue
            inj = s.injection.score
            if inj >= p.injection_block_at:
                s.block(f"prompt injection (score {inj})")
                self._log("injection", s, "blocked on heuristic score")
                continue
            if inj >= p.injection_escalate_at:
                tasks.append((inj, "injection", s))

            elif self.llm and p.llm_screen_untrusted and s.chunk.uploader_trust != "high":
                tasks.append((0.0, "injection", s))  # rules saw nothing; let the judge read it anyway

            risk = s.poisoning.risk
            if s.chunk.uploader_trust != "high" and risk >= p.poison_escalate_at:
                # Low-trust sources are more suspicious for the same claims.
                weight = risk + (0.2 if s.chunk.uploader_trust == "low" else 0.0)
                tasks.append((weight, "poisoning", s))
            elif self.llm and p.llm_screen_untrusted and s.chunk.uploader_trust != "high":
                tasks.append((0.0, "poisoning", s))

        tasks.sort(key=lambda t: t[0], reverse=True)
        # Keep one call in reserve for the aggregation judge.
        n_llm = max(0, min(len(tasks), self._budget - 1)) if self.llm else 0
        self._budget -= n_llm
        with_llm, offline = tasks[:n_llm], tasks[n_llm:]

        for _, kind, s in offline:
            self._decide_offline(kind, s)

        if with_llm:
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda t: self._ask_llm(t[1], t[2], trusted), with_llm))
            for (_, kind, s), result in zip(with_llm, results):
                if s.action == "block":
                    continue
                if isinstance(result, LLMError):
                    self._log(kind, s, f"LLM unavailable ({result}); using heuristic rule")
                    self._decide_offline(kind, s)
                else:
                    self._apply_llm(kind, s, result)

    def _decide_offline(self, kind: str, s: _ChunkState) -> None:
        if s.action == "block":
            return
        p = self.policy
        if kind == "injection" and s.injection.score >= p.injection_offline_block_at:
            s.block(f"prompt injection (score {s.injection.score})")
        elif kind == "poisoning":
            if s.poisoning.risk >= self._poison_limit(s):
                s.block(f"likely poisoned document ({s.chunk.uploader_trust}-trust source, risk {s.poisoning.risk})")
        self._log(kind, s, f"heuristic decision: {s.action}")

    def _ask_llm(self, kind: str, s: _ChunkState, trusted: list[_ChunkState]):
        try:
            if kind == "injection":
                return self.llm.judge(prompts.INJECTION, fence("CHUNK", s.chunk.text))
            context = "\n\n".join(f"TRUSTED chunk {t.chunk.id}:\n{fence('TRUSTED', t.chunk.text)}"
                                  for t in trusted if t is not s) or "(no trusted chunks retrieved)"
            body = (f"CANDIDATE chunk {s.chunk.id} (source: {s.chunk.source or 'unknown'}, "
                    f"uploader trust: {s.chunk.uploader_trust}):\n{fence('CANDIDATE', s.chunk.text)}\n\n{context}")
            return self.llm.judge(prompts.POISONING, body)
        except LLMError as e:
            return e

    def _apply_llm(self, kind: str, s: _ChunkState, r: dict) -> None:
        confident = float(r.get("confidence", 0)) >= self.policy.llm_min_confidence
        reason = str(r.get("reason", "")).strip()
        if kind == "injection":
            if r.get("verdict") == "injection" and confident:
                span = str(r.get("injected_text", "")).strip()
                if span and span in s.text and len(span) < 0.6 * len(s.text):
                    s.text = s.text.replace(span, INJECTION_PLACEHOLDER)
                    s.action = "redact"
                    s.reasons.append(f"prompt injection removed: {reason}")
                else:
                    s.block(f"prompt injection: {reason}")
            elif s.injection.score >= self.policy.injection_offline_block_at:
                # Defense in depth: the judge can add a block, never veto a strong rule signal.
                s.block(f"prompt injection (score {s.injection.score}; judge disagreed: {reason})")
            else:
                s.evidence.append(f"LLM cleared injection signals: {reason}")
        else:
            if r.get("verdict") == "poisoned" and confident:
                s.block(f"likely poisoned document: {reason}")
            elif s.poisoning.risk >= self._poison_limit(s):
                s.block(f"likely poisoned document (risk {s.poisoning.risk}; judge disagreed: {reason})")
            else:
                s.evidence.append(f"LLM judged source legitimate: {reason}")
        self._log(kind, s, f"LLM verdict {r.get('verdict')} ({r.get('confidence')}): {reason}")

    # Stage 3 ---------------------------------------------------------------

    def _redact_sensitive(self, states: list[_ChunkState], live_roles: set[str]) -> None:
        pii_ok = bool(live_roles & self.policy.pii_allowed_roles)
        for s in states:
            if s.action == "block":
                continue
            hits = [h for h in find_sensitive(s.text) if h.is_secret or not pii_ok]
            if not hits:
                continue
            s.text = redact(s.text, hits)
            s.action = "redact"
            kinds = sorted({h.kind for h in hits})
            s.reasons.append(f"redacted {', '.join(kinds)}")
            self._log("secrets", s, f"redacted {len(hits)} span(s)")

    def _judge_aggregation(self, query: str, user: User, states: list[_ChunkState]) -> None:
        if user.clearance >= self.policy.aggregation_exempt_clearance:
            return
        visible = {s.chunk.id: s for s in states if s.action != "block"}
        risky, why, candidates = aggregation_risk({cid: s.text for cid, s in visible.items()})
        # The rule gate only spots shared IDs and names near sensitive words. With a judge available,
        # any multi-chunk answer to a low-clearance user is worth one call: inference rarely announces itself.
        judge_anyway = self.llm and self.policy.llm_always_judge_aggregation and len(visible) >= 2 and self._budget > 0
        if not (risky or judge_anyway):
            return
        if not self.llm or self._budget <= 0:
            if self.policy.aggregation_fail_closed:
                for cid in candidates:
                    visible[cid].block("aggregation risk: sensitive chunk links to others and no judge was available")
            else:
                for s in visible.values():
                    s.evidence.append("aggregation risk detected but not judged")
            self._log("aggregation", None, f"not judged (no LLM budget), fail_closed={self.policy.aggregation_fail_closed}: {'; '.join(why)}")
            return

        self._budget -= 1
        fenced = {cid: fence("CHUNK", s.text) for cid, s in visible.items()}
        listing = "\n\n".join(f"Chunk id: {cid}\n{block}" for cid, block in fenced.items())
        body = (f"User roles: {', '.join(user.roles) or 'none'}; clearance level {user.clearance} (0 = lowest).\n"
                f"Question: {fence('QUERY', query)}\n\n{listing}")
        try:
            r = self.llm.judge(prompts.AGGREGATION, body)
        except LLMError as e:
            self._log("aggregation", None, f"LLM unavailable ({e}); set released unjudged")
            return

        # Only act on a leak the judge itself rates as high sensitivity: related-but-harmless facts stay.
        if r.get("leak") is True and str(r.get("sensitivity", "high")).lower() == "high":
            withhold = [cid for cid in (self._resolve_chunk_id(x, fenced) for x in r.get("withhold", [])) if cid]
            # A leak with no usable ids: fall back to the rules' choice of linking sensitive chunks.
            fallback = [cid for cid in aggregation_risk({c: s.text for c, s in visible.items()})[2] if cid in visible]
            for cid in withhold or fallback or list(visible)[-1:]:
                visible[cid].block(f"aggregation: {r.get('reason', '')} (could infer: {r.get('inferred', '')})")
        self._log("aggregation", None, f"leak={r.get('leak')} withhold={r.get('withhold')}: {r.get('reason')}")

    # Helpers ---------------------------------------------------------------

    def _poison_limit(self, s: _ChunkState) -> float:
        p = self.policy
        return p.poison_escalate_at if s.chunk.uploader_trust == "low" else p.poison_offline_block_at

    @staticmethod
    def _resolve_chunk_id(value, fenced: dict[str, str]) -> str | None:
        """Map a model's reference back to a chunk id. Models sometimes echo the fence tag instead."""
        value = str(value).strip()
        if value in fenced:
            return value
        for cid, block in fenced.items():
            if value and value in block.split("\n", 1)[0]:
                return cid
        return None

    def _live_roles(self, user: User, idp_state) -> set[str]:
        live = (idp_state or {}).get(user.id)
        return set(live.roles) if live else set(user.roles)

    def _log(self, step: str, s: _ChunkState | None, detail: str) -> None:
        self.last_trace.append({"step": step, "chunk": s.chunk.id if s else None, "detail": detail})
