"""Sieve demo dashboard.

    streamlit run ui/app.py

Runs the firewall in-process against the mock workspace, so one deploy is the whole demo.
The Benchmark tab reads results.json written by benchmark/run.py.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

from firewall import MetadataFilter, RetrievalFirewall  # noqa: E402
from locus_mock.store import Workspace  # noqa: E402

load_dotenv(ROOT / ".env")
st.set_page_config(page_title="Sieve", page_icon="▪", layout="wide")

INK, CREAM, GREY, RED = "#0F1112", "#EEE9DE", "#80868B", "#FF4A3D"
ACTION = {
    "allow": ("✓", "ALLOW", "#4CC38A"),
    "redact": ("◐", "REDACT", "#E8A33D"),
    "block": ("✕", "BLOCK", RED),
}
CATEGORY_NAMES = {
    "injection": "Prompt injection",
    "secrets_pii": "Secrets & PII",
    "poisoning": "Poisoned documents",
    "stale_permissions": "Stale permissions",
    "aggregation": "Aggregation leaks",
}

st.markdown(
    f"""
<style>
  .block-container {{ padding-top: 4.2rem; max-width: 1240px; }}
  header[data-testid="stHeader"] {{ background: transparent; }}
  .brand {{ font-family: Bahnschrift, 'DIN Alternate', 'Segoe UI', sans-serif; font-weight: 600; font-size: 64px;
            letter-spacing: -1.5px; line-height: 1; color: {CREAM}; margin: 0; }}
  .brand .i {{ position: relative; display: inline-block; }}
  .brand .dot {{ position: absolute; left: 50%; top: -2px; width: 12px; height: 12px; background: {RED};
                 transform: translateX(-50%) rotate(-7deg); }}
  .tagline {{ font-family: Consolas, ui-monospace, monospace; color: {GREY}; font-size: 15px; margin: 10px 0 6px; }}
  .col-title {{ font-size: 13px; letter-spacing: 1.5px; text-transform: uppercase; color: {GREY}; margin: 4px 0 10px; }}
  .card {{ border: 1px solid #2A2F33; border-radius: 6px; padding: 12px 14px; margin-bottom: 10px; background: #15181A; }}
  .card.block {{ border-color: #4A2320; background: #1A1312; }}
  .card .meta {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; }}
  .card .src {{ font-family: Consolas, ui-monospace, monospace; font-size: 12px; color: {GREY}; overflow-wrap: anywhere; }}
  .badge {{ font-family: Consolas, ui-monospace, monospace; font-size: 11px; font-weight: 700; letter-spacing: 1px;
            padding: 2px 8px; border-radius: 3px; color: {INK}; white-space: nowrap; }}
  .card .body {{ font-size: 14px; line-height: 1.5; color: {CREAM}; white-space: pre-wrap; overflow-wrap: anywhere; }}
  .card.block .body {{ color: #6E5B58; text-decoration: line-through; }}
  .card .why {{ font-size: 12.5px; color: {GREY}; margin-top: 8px; }}
  .summary {{ font-size: 14px; color: {CREAM}; padding: 10px 0 2px; border-top: 1px solid #2A2F33; margin-top: 6px; }}
  .tile {{ border: 1px solid #2A2F33; border-radius: 6px; padding: 16px 18px; background: #15181A; height: 100%; }}
  .tile .label {{ font-size: 12px; letter-spacing: 1.2px; text-transform: uppercase; color: {GREY}; }}
  .tile .value {{ font-family: Bahnschrift, 'Segoe UI', sans-serif; font-size: 44px; font-weight: 600; color: {CREAM}; line-height: 1.1; margin-top: 6px; }}
  .tile .note {{ font-size: 13px; color: {GREY}; margin-top: 4px; }}
  .stage {{ border-left: 3px solid {RED}; padding: 4px 0 4px 14px; margin-bottom: 18px; }}
  .stage b {{ color: {CREAM}; }}
</style>
<div class="brand">s<span class="i">ı<span class="dot"></span></span>eve</div>
<div class="tagline">catches the bad chunks before your LLM reads them</div>
""",
    unsafe_allow_html=True,
)


@st.cache_resource
def load_workspace() -> Workspace:
    return Workspace()


@st.cache_resource
def load_inspectors():
    return MetadataFilter(), RetrievalFirewall()


def chunk_card(chunk, verdict) -> str:
    icon, label, color = ACTION[verdict.action]
    text = verdict.text if verdict.action != "block" else chunk.text
    why = "" if verdict.action == "allow" and verdict.reason in ("metadata ok", "passed all checks") else verdict.reason
    return f"""
<div class="card {verdict.action}">
  <div class="meta"><span class="src">{html.escape(chunk.source)} · trust: {chunk.uploader_trust}</span>
  <span class="badge" style="background:{color}">{icon} {label}</span></div>
  <div class="body">{html.escape(text or "")}</div>
  {f'<div class="why">{html.escape(why)}</div>' if why else ''}
</div>"""


def summary_line(verdicts) -> str:
    n = len(verdicts)
    shown = sum(v.action != "block" for v in verdicts)
    redacted = sum(v.action == "redact" for v in verdicts)
    extra = f", {redacted} redacted" if redacted else ""
    return f'<div class="summary">The LLM sees <b>{shown} of {n}</b> chunks{extra}.</div>'


ws = load_workspace()
baseline, sieve = load_inspectors()
tab_play, tab_bench, tab_how = st.tabs(["Playground", "Benchmark", "How it works"])

# Playground ---------------------------------------------------------------------------

with tab_play:
    samples = ws.sample_queries
    labels = [s["label"] for s in samples] + ["Custom question"]
    c1, c2 = st.columns([3, 2])
    with c1:
        choice = st.selectbox("Scenario", labels, index=1)
    sample = samples[labels.index(choice)] if choice != "Custom question" else None

    user_ids = list(ws.users)
    default_user = sample["user_id"] if sample else user_ids[0]
    with c2:
        uid = st.selectbox("Asking as", user_ids, index=user_ids.index(default_user),
                           format_func=lambda u: ws.user_names[u], key=f"user-{choice}")
    query = st.text_input("Question", value=sample["query"] if sample else "", key=f"q-{choice}",
                          placeholder="Ask the workspace something…")

    live = ws.idp.get(uid)
    st.caption(
        f"Index says roles: {', '.join(ws.users[uid].roles)} · clearance {ws.users[uid].clearance}  —  "
        f"identity provider says: {'active' if live and live.active else 'deactivated'}, roles: {', '.join(live.roles) if live and live.roles else 'none'}"
    )

    if query.strip():
        user = ws.users[uid]
        hits = ws.retrieve(user, query, top_k=5)
        chunks = [h.chunk for h in hits]
        if not chunks:
            st.info("Nothing in the workspace matched that question.")
        else:
            base_v = baseline.inspect(query, user, chunks, ws.idp)
            sieve_v = sieve.inspect(query, user, chunks, ws.idp)
            left, right = st.columns(2, gap="large")
            with left:
                st.markdown('<div class="col-title">Without Sieve · metadata filter</div>', unsafe_allow_html=True)
                st.markdown("".join(chunk_card(c, v) for c, v in zip(chunks, base_v)) + summary_line(base_v),
                            unsafe_allow_html=True)
            with right:
                st.markdown('<div class="col-title">With Sieve</div>', unsafe_allow_html=True)
                st.markdown("".join(chunk_card(c, v) for c, v in zip(chunks, sieve_v)) + summary_line(sieve_v),
                            unsafe_allow_html=True)
                stats = sieve.last_stats
                st.caption(f"{stats['latency_ms']} ms · {stats['llm_calls']} LLM calls · mode: {stats['mode']}")
                with st.expander("Why — Sieve's decision trace"):
                    st.dataframe(pd.DataFrame(sieve.last_trace), hide_index=True, use_container_width=True)

# Benchmark ----------------------------------------------------------------------------

with tab_bench:
    path = ROOT / "results.json"
    if not path.exists():
        st.info("No results yet. Run `python benchmark/run.py` to generate results.json.")
    else:
        res = json.loads(path.read_text(encoding="utf-8"))
        setups = res["setups"]
        fw, b1 = setups.get("firewall"), setups.get("baseline1")
        ds = res["dataset"]
        test_attacks = fw["test"]["attack_cases"] if fw else 0

        st.markdown(
            f"Held-out test split · {test_attacks} attacks and {fw['test']['benign_cases'] if fw else 0} benign cases "
            f"(of {ds['cases']} total) · run {res['generated_at'][:16].replace('T', ' ')} UTC on commit `{res['commit']}`"
        )
        if fw and b1:
            t1, t2, t3, t4 = st.columns(4)
            tiles = [
                (t1, "Attacks that got through", f"{fw['test']['attack_success_rate']:.0f}%", f"vs {b1['test']['attack_success_rate']:.0f}% with metadata filtering"),
                (t2, "False positives", f"{fw['test']['false_positive_rate']:.0f}%", "benign cases altered"),
                (t3, "Latency p50", f"{fw['test']['latency_ms']['p50']:.1f} ms", f"p95 {fw['test']['latency_ms']['p95']:.1f} ms"),
                (t4, "Mode", "LLM + rules" if fw["mode"] == "llm" else "Rules only", f"{fw['test']['llm_calls_per_request']} LLM calls per request"),
            ]
            for col, label, value, note in tiles:
                col.markdown(f'<div class="tile"><div class="label">{label}</div><div class="value">{value}</div>'
                             f'<div class="note">{note}</div></div>', unsafe_allow_html=True)

            st.markdown("#### Attacks stopped by Sieve, by type")
            rows = [{"Attack type": CATEGORY_NAMES.get(cat, cat), "Stopped (%)": round(100 - m["attack_success_rate"], 1),
                     "Cases": m["n"], "Metadata filter stopped (%)": round(100 - b1["test"]["by_category"][cat]["attack_success_rate"], 1)}
                    for cat, m in fw["test"]["by_category"].items()]
            df = pd.DataFrame(rows).sort_values("Stopped (%)", ascending=False)
            base = alt.Chart(df).encode(
                y=alt.Y("Attack type:N", sort=None, title=None, axis=alt.Axis(labelColor=CREAM, labelFontSize=13, ticks=False, domain=False, labelLimit=220)),
                x=alt.X("Stopped (%):Q", scale=alt.Scale(domain=[0, 100]), title=None,
                        axis=alt.Axis(labelColor=GREY, gridColor="#24282B", domain=False, ticks=False, values=[0, 25, 50, 75, 100])),
            )
            bars = base.mark_bar(color=CREAM, height=18, cornerRadiusEnd=4).encode(
                tooltip=[alt.Tooltip("Attack type:N"), alt.Tooltip("Stopped (%):Q"), alt.Tooltip("Cases:Q"),
                         alt.Tooltip("Metadata filter stopped (%):Q")])
            labels_ = base.mark_text(align="left", dx=6, color=CREAM, fontSize=13).encode(text=alt.Text("Stopped (%):Q", format=".0f"))
            chart = (bars + labels_).properties(height=230).configure_view(strokeWidth=0).configure(background="transparent")
            st.altair_chart(chart, use_container_width=True)
            st.caption("Metadata filtering stopped 0% in every category.")

            with st.expander("All setups, dev and test"):
                table = []
                for name, s in setups.items():
                    for sp in ("test", "dev"):
                        m = s["splits"].get(sp)
                        if m:
                            table.append({"Setup": s["label"], "Split": sp, "Attack success %": m["attack_success_rate"],
                                          "False positive %": m["false_positive_rate"], "Over-blocking %": m["over_blocking_rate"],
                                          "p50 ms": m["latency_ms"]["p50"], "p95 ms": m["latency_ms"]["p95"]})
                st.dataframe(pd.DataFrame(table), hide_index=True, use_container_width=True)
                for name, why in res.get("skipped", {}).items():
                    st.caption(f"Skipped {name}: {why}")
                st.caption("Missed on test: " + (", ".join(fw["test"]["missed_attacks"]) or "none"))

            st.markdown(
                "**How to read this.** Cases are split into *dev*, which the rules were tuned on, and a held-out *test* split, "
                "reported above. Half the cases reuse attack strings and questions written independently of the firewall. "
                "Without an LLM configured, Sieve runs on rules alone; the LLM judges handle what rules can't."
            )

# How it works -------------------------------------------------------------------------

with tab_how:
    st.markdown(
        """
<div class="stage"><b>1 · Triage — every chunk, no LLM.</b><br>
Re-checks access against the live identity provider (not the copy in the index), and scores each chunk for prompt
injection and document poisoning.</div>
<div class="stage"><b>2 · Investigate — only what looks risky.</b><br>
Ranks the suspicious chunks and spends a fixed LLM budget on the worst ones. Blatant attacks are blocked for free;
if the model is unavailable, rules decide.</div>
<div class="stage"><b>3 · Release — what the LLM may see.</b><br>
Redacts secrets always and personal data unless the user's role allows it. If the surviving chunks could combine into
something above the user's clearance, an aggregation judge withholds the fewest needed.</div>
<p style="color:#80868B">Every chunk leaves with a decision — allow, redact or block — and the reason for it.</p>
""",
        unsafe_allow_html=True,
    )
