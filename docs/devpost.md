# Devpost submission text

**Name:** Sieve

**Tagline (≤200 chars):**
Your RAG trusts every chunk it retrieves. Sieve doesn't. An AI security agent that blocks injections, poisoned docs, stale access and leaked secrets before your LLM reads a word.

**Links:** demo https://sieve-cms2.onrender.com · code https://github.com/Abbas-Rahman-c/retrieval-firewall

---

## Inspiration
RAG systems trust whatever the retriever hands them. Most only check metadata, like tenant IDs and access tags copied into the index, and never read what a chunk actually says. A document with hidden instructions, a fake "official" notice, a former employee whose access still sits in the index, or a record full of credentials all go straight into the model's context. We build a RAG product ourselves and wanted a layer that actually reads.

## What it does
Sieve sits between the retriever and the LLM and gives every retrieved chunk a decision, allow, redact or block, with a reason:

1. **Permission re-check:** confirms access against the live identity provider, not the stale copy in the index.
2. **Injection scan:** catches instructions aimed at the model, and tells them apart from documents that only quote attacks.
3. **Secret and PII redaction:** redacts keys and personal data in place, so the rest of the document stays useful.
4. **Poisoning check:** weighs risky "authoritative" claims against the source's trust and against trusted documents in the same retrieval.
5. **Aggregation judge:** checks whether chunks that are harmless alone reveal something above the user's clearance together.

Every decision is recorded in a trace, so you can see exactly why a chunk was stopped.

## How it's an agent
Sieve doesn't send everything to an LLM. Cheap checks run on every chunk; the agent then ranks what looks risky and spends a fixed per-request LLM budget only on the worst cases, blocking blatant attacks for free and falling back to rules if the model is unavailable. A process-wide cap and per-visitor rate limit keep a public deployment from burning credits.

## How we built it
Python and FastAPI. Every setup, Sieve and the baselines, implements one `inspect()` interface, so they run through the same benchmark. A mock company workspace (users, a live identity provider, documents containing every attack type) powers the live demo, served together with a hand-built site from one deploy on Render. LLM judges use an OpenAI-compatible endpoint (Nebius Token Factory).

## Results
194 cases across five attack types plus benign controls, split into a dev set (used to tune the rules) and a held-out test set (reported). All numbers below are Sieve **on rules alone**; the LLM judges were not enabled for these runs.

| Held-out test set | Attacks that reached the LLM | Benign cases altered |
|---|---|---|
| Metadata filtering (typical RAG) | 100% | 0% |
| **Sieve, rules only** | **42%** | **12%** |
| Sieve, on 45 cases written independently by a teammate who never saw the firewall | 60% | 50% |

Sieve stops 100% of stale-permission attacks at under a millisecond per request. The independent set is the honest number: it shows where rules stop working, which is exactly what the LLM judges are for.

## Challenges
Blocking attacks is easy; not blocking legitimate content is hard. A security guideline that quotes "ignore previous instructions" must get through, and so must a password policy. We also learned how easily a benchmark flatters its authors: our own cases said 26%, independent ones said 60%. We kept the dev/test split and publish both.

## What's next
Enable the LLM judges (Nemotron on Nebius Token Factory) and measure them on the independent set, learn source trust over time, and integrate Sieve into our own RAG product.
