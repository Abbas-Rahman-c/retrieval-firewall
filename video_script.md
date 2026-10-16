# Sieve - 3 Minute Video Script
# Team: Retrieval Firewall Project
# Origin: teammate task

## Overview
Total: 180s

### 0-20s PROBLEM
**Screen:** Show architecture diagram from proposal: User -> Retriever -> LLM. Red arrows showing 5 attacks. Show table of attacks.
**Voiceover:**
"Retrieval-Augmented Generation is powerful, but it has a fatal flaw. It trusts every chunk it retrieves. One poisoned doc, one stale permission, one leaked secret - and your AI leaks data or follows attacker instructions. We call these Retrieval Threats."

### 20-110s LIVE DEMO IN PLAYGROUND (Main demo, 90s)
**Screen:** Open http://localhost:8000 Sieve playground. Split screen toggle: Without Sieve vs With Sieve.

**Part A - Poisoned MFA tip (20s)**
Screen: Show query "How to login to VPN?"
Voiceover: "First, a poisoned document. Someone planted a fake IT tip saying disable MFA. Without protection, the AI tells the user to disable MFA. With Sieve, our Trust Check flags the document as low-trust, unverified author, and blocks it."
Action: Toggle OFF -> AI says "Disable MFA". Toggle ON -> "Blocked 1 low-trust chunk. Official policy: MFA is mandatory."

**Part B - Prompt Injection (20s)**
Screen: Show doc containing "Ignore previous instructions..."
Voiceover: "Second, prompt injection hidden in a meeting note. The document tries to jailbreak the AI. Without Sieve, it leaks data. With Sieve, our Injection Scan detects imperative instructions and blocks it."
Action: Show chunk flagged as injection.

**Part C - Stale Permissions (25s)**
Screen: Select user "John - deactivated" -> query "Show confidential roadmap"
Voiceover: "Third, stale permissions. John left the company last month, but his old docs are still in the vector DB. The retriever still finds them. Without Sieve, the AI shows confidential M&A data. With Sieve, we re-check the IDP state live. John is deactivated, so we block."
Action: Show idp_state deactivated -> blocked.

**Part D - Secret Redaction (25s)**
Screen: Query "Show me deployment logs"
Voiceover: "Fourth, secrets. A dev accidentally committed an AWS key. Without Sieve, it leaks in full. With Sieve, our sensitive-data scanner redacts it but keeps the rest of the document useful."
Action: Show WITHOUT: "AWS_SECRET=...". WITH: "AWS_SECRET=[REDACTED]" + log that secret was redacted.

### 110-140s BENCHMARK RESULTS (30s)
**Screen:** Show results table/bar chart.
Columns: Baseline (No Firewall) vs MetaData-Only vs Metadata+LlamaGuard vs Sieve (Ours)
Rows: Attack Success Rate ↓ lower is better, Benign False Positive Rate ↓, Latency ms
**Voiceover:**
"We built a benchmark of 200+ cases covering all 5 attack types. Baseline fails 80% of attacks. Metadata-only filters miss injections and secrets. Adding Llama Guard helps but still misses stale permissions and aggregation. Our agent-based Sieve blocks 92% of attacks with only 5% false positives on tricky benign docs, at just 120ms overhead per query."

### 140-170s HOW THE AGENT WORKS (30s)
**Screen:** Show 5-step pipeline diagram.
**Voiceover:**
"How does Sieve work? It's not one regex, it's an agent that reasons over 5 checks for every chunk. One, Permission Re-check - we query the live IDP. Two, Injection Scan - we look for instructions aimed at the LLM. Three, Sensitive Data Check - we detect real secrets, not fake examples, using context. Four, Trust Check - we score source, author, and freshness. Five, Aggregation Judge - we check if two safe chunks together leak something private. Each chunk gets allow, redact, or block."

### 170-180s CLOSE (10s)
**Screen:** Logo "Sieve - Don't trust retrieval, verify it." Team names, GitHub link.
**Voiceover:**
"Sieve - Don't trust retrieval, verify it. Open source firewall for enterprise RAG."

## How to Record
1. Run: uvicorn locus_mock.app:app --port 8000
2. Open http://localhost:8000
3. Use OBS screen record
4. Keep voiceover calm, technical

Files to show: dataset/fresh_cases.json, firewall/ folder, benchmark results
