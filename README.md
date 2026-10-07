# Sieve

![Sieve](docs/thumbnail.png)

**Catches the bad chunks before your LLM reads them.**

Sieve is a security agent that sits between a RAG retriever and the LLM. It inspects every retrieved chunk before the model sees it and blocks or redacts anything unsafe: prompt injection, aggregation leaks, stale permissions, secrets/PII and poisoned documents.

Built for the Nebius x NVIDIA hackathon (Agents track).

## Layout

| Folder | What lives there | Owner |
| --- | --- | --- |
| `firewall/` | The agent: checks, judge, policy rules, API | Person A |
| `locus_mock/` | Mock Locus AI retrieval API with fake data for the demo | Person A |
| `dataset/` | Red-team attack documents and queries, plus benign controls | Person B |
| `benchmark/` | Harness comparing baselines vs. the firewall | Person B |
| `ui/` | Streamlit demo | Person B |

## Setup

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt pytest   # bin/ instead of Scripts/ on macOS/Linux
cp .env.example .env   # fill in your keys
python scripts/list_models.py   # pick FIREWALL_MODEL from this list
python -m pytest -q
```

## How the firewall works

`RetrievalFirewall.inspect(query, user, chunks, idp_state)` returns one verdict (`allow` / `redact` / `block`) per chunk, in three stages:

1. **Triage, every chunk, no LLM:** re-check permissions against the live identity provider (stale access is blocked), and score each chunk for prompt injection and poisoning.
2. **Investigation, flagged chunks only:** the most suspicious chunks go to LLM judges within a per-request budget (`Policy.max_llm_calls`). Blatant injections are blocked without spending a call. If the LLM is unavailable, heuristic rules decide.
3. **Release:** secrets are always redacted, PII unless the user has an allowed role (e.g. HR). If the surviving chunks could combine into something above the user's clearance, an aggregation judge withholds the fewest chunks needed.

Without `FIREWALL_MODEL` set it runs heuristics-only.

## Mock workspace API (demo backend)

`locus_mock/` is a stand-in for a RAG workspace like Locus AI, built on fictional data in `locus_mock/data.json`: 5 users, a live identity provider, 14 chunks (benign docs plus every attack type) and 10 sample queries. Its retriever filters by the ACL copy in the index and never checks the identity provider, like most RAG stacks.

```bash
uvicorn locus_mock.app:app --reload --port 8000   # docs at http://localhost:8000/docs
```

| Endpoint | What it returns |
| --- | --- |
| `GET /users`, `GET /samples` | Demo users (with live identity state) and ready-made attack/benign queries |
| `GET /idp/{user_id}` | The live identity provider record |
| `POST /retrieve` | Raw retrieval, before any firewall |
| `POST /ask` | `{user_id, query, mode, top_k}` → retrieved chunks, per-chunk verdicts, the context the LLM may see, trace and stats. `mode` is `none`, `baseline1`, `baseline2` or `firewall` | `fw.last_trace` and `fw.last_stats` show what it did and why.

Never commit `.env` or real Locus AI data. This repo will be made public for submission.
