# Retrieval Firewall

A security agent that sits between a RAG retriever and the LLM. It inspects every retrieved chunk before the model sees it and blocks or redacts anything unsafe: prompt injection, aggregation leaks, stale permissions, secrets/PII and poisoned documents.

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
cp .env.example .env   # fill in your keys
```

Never commit `.env` or real Locus AI data. This repo will be made public for submission.
