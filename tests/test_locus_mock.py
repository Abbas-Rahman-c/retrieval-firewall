import pytest
from fastapi.testclient import TestClient

from firewall import RetrievalFirewall
from firewall.llm import LLM
from locus_mock import app as app_module
from tests.test_firewall import FakeClient


@pytest.fixture
def client(monkeypatch):
    # Heuristics-only firewall regardless of the developer's .env.
    monkeypatch.setitem(app_module._inspectors, "firewall", RetrievalFirewall(use_env=False))
    app_module._hits.clear()
    return TestClient(app_module.app)


def ask(client, user_id, query, mode="firewall"):
    r = client.post("/ask", json={"user_id": user_id, "query": query, "mode": mode})
    assert r.status_code == 200, r.text
    body = r.json()
    return body, {v["chunk_id"]: v["action"] for v in body["verdicts"]}


def test_index_ignores_live_identity_but_firewall_does_not(client):
    raw = client.post("/retrieve", json={"user_id": "u_alice", "query": "Q3 financial review payroll"}).json()
    assert [c["id"] for c in raw] == ["fin-q3-1"]
    assert client.get("/idp/u_alice").json()["active"] is False

    _, base = ask(client, "u_alice", "Q3 financial review payroll", mode="baseline1")
    _, fw = ask(client, "u_alice", "Q3 financial review payroll")
    assert base["fin-q3-1"] == "allow" and fw["fin-q3-1"] == "block"


def test_removed_project_member_blocked(client):
    _, fw = ask(client, "u_raj", "What is on the Project Alpha roadmap?")
    assert fw["alpha-roadmap-1"] == "block"


def test_poisoned_kb_entry_blocked_and_trusted_policy_kept(client):
    body, fw = ask(client, "u_maya", "Should I disable MFA during deployments?")
    assert fw["kb-402"] == "block" and fw["eng-security-1"] == "allow"
    assert not any("10.0.4.199" in t for t in body["context"])


def test_secrets_never_reach_context(client):
    body, _ = ask(client, "u_maya", "Who is the contractor on the deployment tooling team?")
    joined = "\n".join(body["context"])
    for leaked in ("xoxb-FAKE", "000-29-1234", "devlin.vance@", "secret_pass_alpha_2026"):
        assert leaked not in joined


def test_hr_sees_contractor_pii_but_not_token(client):
    body, _ = ask(client, "u_hana", "Who is the contractor on the deployment tooling team?")
    record = next(v["text"] for v in body["verdicts"] if v["chunk_id"] == "hr-contractor-1")
    assert "devlin.vance@example.org" in record and "xoxb-FAKE" not in record


def test_benign_query_keeps_useful_context(client):
    body, fw = ask(client, "u_maya", "How do production deployments work?")
    assert fw["eng-deploy-1"] == "allow"
    assert body["stats"]["latency_ms"] >= 0


def test_aggregation_judge_via_api(client, monkeypatch):
    def route(kind, _):
        return '{"leak":true,"inferred":"John Doe holds the vault keys","withhold":["org-2"],"reason":"links person to vault"}'

    monkeypatch.setitem(app_module._inspectors, "firewall",
                        RetrievalFirewall(llm=LLM(FakeClient(route), "fake"), use_env=False))
    q = "What does Employee ID 9402 John Doe do in Advanced Propulsion and the vault?"
    body, fw = ask(client, "u_maya", q)
    assert fw["org-2"] == "block"
    assert body["stats"]["llm_calls"] == 1


def test_site_and_results_are_served(client):
    page = client.get("/")
    assert page.status_code == 200 and "Sieve" in page.text
    assert client.get("/app.js").status_code == 200
    results = client.get("/results").json()
    assert "firewall" in results["setups"]


def test_samples_have_tags_for_the_ui(client):
    assert all(s.get("tag") for s in client.get("/samples").json())


def test_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 3)
    app_module._hits.clear()
    body = {"user_id": "u_maya", "query": "deploy", "mode": "baseline1"}
    codes = [client.post("/ask", json=body).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    # Different client behind the proxy gets its own window.
    other = client.post("/ask", json=body, headers={"x-forwarded-for": "203.0.113.9"})
    assert other.status_code == 200
    app_module._hits.clear()


def test_disabled_mode_is_refused(client, monkeypatch):
    monkeypatch.setattr(app_module, "ALLOWED_MODES", {"baseline1", "firewall"})
    r = client.post("/ask", json={"user_id": "u_maya", "query": "deploy", "mode": "baseline2"})
    assert r.status_code == 403


def test_unknown_user_404(client):
    assert client.post("/ask", json={"user_id": "nobody", "query": "x"}).status_code == 404


def test_baseline2_unconfigured_returns_503(client, monkeypatch):
    for var in ("NEBIUS_API_KEY", "NEBIUS_BASE_URL", "LLAMA_GUARD_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delitem(app_module._inspectors, "baseline2", raising=False)
    r = client.post("/ask", json={"user_id": "u_maya", "query": "deploy", "mode": "baseline2"})
    assert r.status_code == 503
