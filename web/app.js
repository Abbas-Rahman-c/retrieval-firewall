"use strict";

const $ = (s, el = document) => el.querySelector(s);
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

const api = {
  get: (p) => fetch(p).then((r) => (r.ok ? r.json() : Promise.reject(r))),
  post: (p, body) =>
    fetch(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => (r.ok ? r.json() : Promise.reject(r))),
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const sleep = (ms) => new Promise((r) => setTimeout(r, reduceMotion ? 0 : ms));

/* Nav border on scroll ------------------------------------------------------------- */
const nav = $(".nav");
addEventListener("scroll", () => nav.classList.toggle("scrolled", scrollY > 8), { passive: true });

/* Scroll reveal --------------------------------------------------------------------- */
const revealer = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    const siblings = [...e.target.parentElement.children].filter((n) => n.hasAttribute("data-reveal"));
    e.target.style.transitionDelay = `${Math.max(0, siblings.indexOf(e.target)) * 70}ms`;
    e.target.classList.add("in");
    revealer.unobserve(e.target);
  }
}, { threshold: 0.12 });
document.querySelectorAll("[data-reveal]").forEach((el) => revealer.observe(el));

/* Hero: chunks raining onto the sieve ----------------------------------------------- */
(function rain() {
  const canvas = $("#rain");
  const ctx = canvas.getContext("2d");
  const PITCH = 44, DASH = 32, GAP = PITCH - DASH, CLEAN = 6, BAD = 16;
  const CREAM = "#EEE9DE", RED = "#FF4A3D";
  let W = 0, H = 0, lineY = 0, offset = 0, running = true, last = 0;
  const drops = [], caught = [], flashes = [];

  function resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    lineY = Math.round(H * 0.58);
    offset = ((W / 2 - DASH - GAP / 2) % PITCH + PITCH) % PITCH; // a gap sits at the centre
  }
  const gapX = (k) => offset - PITCH + k * PITCH + DASH + GAP / 2;
  const columns = () => Math.ceil(W / PITCH) + 1;

  function spawn(bad) {
    let k = 1 + Math.floor(Math.random() * (columns() - 1));
    if (bad && caught.some((c) => c.k === k)) return;
    drops.push({ k, x: gapX(k), y: -20, vy: bad ? 70 + Math.random() * 40 : 90 + Math.random() * 90, bad, rot: (Math.random() - 0.5) * 0.5 });
  }

  function step(dt) {
    if (Math.random() < dt * Math.max(8, W / 90)) spawn(false);
    if (Math.random() < dt * Math.max(0.8, W / 900)) spawn(true);
    for (let i = drops.length - 1; i >= 0; i--) {
      const d = drops[i];
      d.vy += 60 * dt;
      d.y += d.vy * dt;
      if (d.bad && d.y + BAD / 2 >= lineY - 1.5) {
        drops.splice(i, 1);
        caught.push({ k: d.k, x: d.x, rot: (Math.random() - 0.5) * 0.35, age: 0, life: 3 + Math.random() * 3 });
        flashes.push({ x: d.x, t: 0 });
        continue;
      }
      if (d.y > H + 20) drops.splice(i, 1);
    }
    for (let i = caught.length - 1; i >= 0; i--) {
      caught[i].age += dt;
      if (caught[i].age > caught[i].life + 0.6) caught.splice(i, 1);
    }
    for (let i = flashes.length - 1; i >= 0; i--) {
      flashes[i].t += dt;
      if (flashes[i].t > 0.4) flashes.splice(i, 1);
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (const d of drops) {
      const fadeIn = Math.min(1, (d.y + 20) / (lineY * 0.7));
      const fadeOut = d.y > lineY ? Math.max(0, 1 - (d.y - lineY) / (H - lineY)) : 1;
      ctx.globalAlpha = (d.bad ? 0.35 + 0.65 * fadeIn : 0.2 + 0.8 * fadeIn) * fadeOut;
      ctx.fillStyle = d.bad ? RED : CREAM;
      const s = d.bad ? BAD : CLEAN;
      ctx.save(); ctx.translate(d.x, d.y); ctx.rotate(d.bad ? d.rot * (d.y / lineY) : 0);
      ctx.fillRect(-s / 2, -s / 2, s, s); ctx.restore();
    }
    ctx.globalAlpha = 1;
    ctx.fillStyle = CREAM;
    for (let k = 0; k < columns() + 1; k++) ctx.fillRect(offset - PITCH + k * PITCH, lineY, DASH, 3);
    for (const f of flashes) {
      ctx.globalAlpha = 1 - f.t / 0.4;
      ctx.fillStyle = RED;
      ctx.fillRect(f.x - 26, lineY, 52, 3);
    }
    for (const c of caught) {
      const settle = Math.min(1, c.age / 0.25);
      ctx.globalAlpha = c.age > c.life ? Math.max(0, 1 - (c.age - c.life) / 0.6) : 1;
      ctx.fillStyle = RED;
      ctx.save(); ctx.translate(c.x, lineY - BAD / 2 - 0.5 + (1 - settle) * -3); ctx.rotate(c.rot * settle);
      ctx.fillRect(-BAD / 2, -BAD / 2, BAD, BAD); ctx.restore();
    }
    ctx.globalAlpha = 1;
  }

  function frame(t) {
    if (!running) return;
    const dt = Math.min(0.05, (t - last) / 1000 || 0.016);
    last = t;
    step(dt); draw();
    requestAnimationFrame(frame);
  }

  resize();
  addEventListener("resize", resize);
  if (reduceMotion) {
    for (let i = 0; i < 400; i++) step(0.03);
    draw();
    return;
  }
  new IntersectionObserver(([e]) => {
    const was = running;
    running = e.isIntersecting;
    if (running && !was) { last = performance.now(); requestAnimationFrame(frame); }
  }).observe(canvas);
  requestAnimationFrame((t) => { last = t; frame(t); });
})();

/* Playground ------------------------------------------------------------------------ */
const state = { samples: [], users: [], active: -1, runId: 0 };
const BADGE = { allow: "✓ ALLOW", redact: "◐ REDACT", block: "✕ BLOCK" };
const QUIET = new Set(["metadata ok", "passed all checks", "no checks"]);

function richText(text) {
  return esc(text)
    .replace(/\[REMOVED:INJECTED_INSTRUCTION\]/g, '<span class="redacted">injected instruction removed</span>')
    .replace(/\[REDACTED:([A-Z_]+)\]/g, (_, k) => `<span class="redacted">${k.toLowerCase().replace(/_/g, " ")}</span>`);
}

function cardHTML(chunk, verdict, i, pending) {
  const action = pending ? "pending" : verdict.action;
  const text = !pending && verdict.action !== "block" ? richText(verdict.text) : esc(chunk.text);
  const why = !pending && !(verdict.action === "allow" && QUIET.has(verdict.reason)) ? esc(verdict.reason) : "";
  return `<div class="card ${action}" style="animation-delay:${i * 70}ms" data-id="${esc(chunk.id)}">
    <div class="meta"><span class="src">${esc(chunk.source)} · ${esc(chunk.uploader_trust)} trust</span>
    <span class="badge">${pending ? "SCANNING" : BADGE[verdict.action]}</span></div>
    <div class="body">${text}</div><div class="why">${why}</div></div>`;
}

function seesHTML(verdicts) {
  const shown = verdicts.filter((v) => v.action !== "block").length;
  const red = verdicts.filter((v) => v.action === "redact").length;
  return `The LLM sees <b>${shown} of ${verdicts.length}</b> chunks${red ? `, <b>${red}</b> redacted` : ""}.`;
}

function renderIdentity() {
  const u = state.users.find((x) => x.id === $("#user").value);
  if (!u) return;
  const live = u.live;
  const liveRoles = live && live.roles.length ? live.roles.join(", ") : "none";
  const stale = !live || !live.active || u.roles.some((r) => !live.roles.includes(r));
  $("#identity").innerHTML =
    `index says <b>${esc(u.roles.join(", "))}</b> · clearance ${u.clearance}<br>` +
    `identity provider says <b class="${stale ? "warn" : ""}">${live && live.active ? "active" : "deactivated"} · ${esc(liveRoles)}</b>`;
}

function selectScenario(i) {
  state.active = i;
  document.querySelectorAll(".scenarios button").forEach((b, j) => b.classList.toggle("active", i === j));
  const s = state.samples[i];
  $("#user").value = s.user_id;
  $("#query").value = s.query;
  renderIdentity();
  run();
}

async function run() {
  const query = $("#query").value.trim();
  const user_id = $("#user").value;
  if (!query) return;
  const id = ++state.runId;
  $("#stage-meta").textContent = "Retrieving…";

  let base, sieve;
  try {
    [base, sieve] = await Promise.all([
      api.post("/ask", { user_id, query, mode: "baseline1", top_k: 5 }),
      api.post("/ask", { user_id, query, mode: "firewall", top_k: 5 }),
    ]);
  } catch (err) {
    $("#stage-meta").textContent = err && err.status === 429
      ? "Easy there — too many runs this minute. Try again shortly."
      : "Could not reach the API.";
    return;
  }
  if (id !== state.runId) return;

  const chunks = sieve.retrieved;
  $("#stage-meta").textContent = chunks.length
    ? `Retrieved ${chunks.length} chunk${chunks.length > 1 ? "s" : ""} for ${sieve.user.name}`
    : "Nothing in the workspace matched.";
  $("#stage-mode").textContent = sieve.stats.mode === "llm" ? "rules + LLM judges" : "rules only";
  $("#sieve-stats").textContent = `${sieve.stats.latency_ms} ms · ${sieve.stats.llm_calls} LLM calls`;

  if (!chunks.length) {
    $("#lane-base").innerHTML = $("#lane-sieve").innerHTML = '<div class="empty">No chunks retrieved</div>';
    $("#sees-base").innerHTML = $("#sees-sieve").innerHTML = "";
    $("#trace").innerHTML = ""; $("#trace-count").textContent = "";
    return;
  }

  const byId = (vs) => Object.fromEntries(vs.map((v) => [v.chunk_id, v]));
  const bv = byId(base.verdicts), sv = byId(sieve.verdicts);
  $("#lane-base").innerHTML = chunks.map((c, i) => cardHTML(c, bv[c.id], i, false)).join("");
  $("#sees-base").innerHTML = seesHTML(base.verdicts);
  $("#lane-sieve").innerHTML = chunks.map((c, i) => cardHTML(c, null, i, true)).join("");
  $("#sees-sieve").innerHTML = "";
  $("#trace").innerHTML = ""; $("#trace-count").textContent = "";

  // The decisions are already made; reveal them one by one so the change is easy to follow.
  await sleep(450);
  for (const [i, c] of chunks.entries()) {
    if (id !== state.runId) return;
    const el = $(`#lane-sieve .card[data-id="${CSS.escape(c.id)}"]`);
    const tmp = document.createElement("div");
    tmp.innerHTML = cardHTML(c, sv[c.id], 0, false);
    const next = tmp.firstElementChild;
    next.style.animation = "none"; next.style.opacity = 1; next.style.transform = "none";
    next.classList.add("decided");
    el.replaceWith(next);
    await sleep(sv[c.id].action === "allow" ? 160 : 320);
  }
  $("#sees-sieve").innerHTML = seesHTML(sieve.verdicts);
  $("#trace").innerHTML = sieve.trace.map((t, i) =>
    `<li style="animation-delay:${i * 40}ms"><b>${esc(t.step)}</b>${t.chunk ? esc(t.chunk) + " · " : ""}${esc(t.detail)}</li>`).join("");
  $("#trace-count").textContent = `${sieve.trace.length} steps`;
}

async function initPlayground() {
  try {
    [state.samples, state.users] = await Promise.all([api.get("/samples"), api.get("/users")]);
  } catch {
    $("#stage-meta").textContent = "Could not reach the API.";
    return;
  }
  $("#scenarios").innerHTML = state.samples.map((s, i) =>
    `<li><button type="button" data-i="${i}"><span>${esc(s.label)}</span><span class="tag ${s.tag === "benign" ? "benign" : ""}">${esc(s.tag)}</span></button></li>`).join("");
  $("#scenarios").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (b) selectScenario(+b.dataset.i);
  });
  $("#user").innerHTML = state.users.map((u) => `<option value="${esc(u.id)}">${esc(u.name)}</option>`).join("");
  $("#user").addEventListener("change", () => { renderIdentity(); run(); });
  $("#ask-form").addEventListener("submit", (e) => { e.preventDefault(); run(); });
  $("#query").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); run(); }
  });
  $("#query").addEventListener("input", () => {
    state.active = -1;
    document.querySelectorAll(".scenarios button").forEach((b) => b.classList.remove("active"));
  });

  // Start the demo when the playground scrolls into view.
  new IntersectionObserver(([e], obs) => {
    if (e.isIntersecting) { selectScenario(1); obs.disconnect(); }
  }, { threshold: 0.25 }).observe($("#playground"));
}

/* Results ---------------------------------------------------------------------------- */
const NAMES = {
  stale_permissions: "Stale permissions", secrets_pii: "Secrets & PII", poisoning: "Poisoned documents",
  injection: "Prompt injection", aggregation: "Aggregation leaks",
};

function countUp(el, to, suffix, decimals = 0) {
  if (reduceMotion) { el.textContent = to.toFixed(decimals) + suffix; return; }
  const t0 = performance.now(), dur = 1400;
  const tick = (t) => {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 4);
    el.textContent = (to * e).toFixed(decimals) + suffix;
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function initResults() {
  let res;
  try { res = await api.get("/results"); } catch {
    $("#results-sub").textContent = "No benchmark results yet — run python benchmark/run.py.";
    return;
  }
  const fw = res.setups.firewall, b1 = res.setups.baseline1;
  if (!fw || !b1) return;
  const t = fw.test, bt = b1.test;

  $("#results-sub").textContent =
    `${t.attack_cases} attacks and ${t.benign_cases} benign cases from a held-out split the rules were never tuned on.`;
  $("#lat-cap").textContent = `p95 ${t.latency_ms.p95.toFixed(1)} ms · ${t.llm_calls_per_request} LLM calls per request`;

  const rows = Object.entries(t.by_category)
    .map(([k, m]) => ({ k, name: NAMES[k] || k, stopped: 100 - m.attack_success_rate, n: m.n }))
    .sort((a, b) => b.stopped - a.stopped);
  $("#bars").innerHTML = rows.map((r) => `
    <div class="bar-row" role="row">
      <span class="name" role="cell">${esc(r.name)}<span class="n">${r.n} test cases</span></span>
      <div class="bar-track" role="cell"><div class="bar-fill" data-w="${r.stopped}"></div></div>
      <span class="val" role="cell">${Math.round(r.stopped)}%</span>
      <span class="tip">${Math.round(r.stopped * r.n / 100)} of ${r.n} stopped · metadata filter: 0</span>
    </div>`).join("");

  const mode = fw.mode === "llm" ? "rules + LLM judges" : "rules only (LLM judges not enabled for this run)";
  $("#fineprint").innerHTML =
    `Sieve ran in <b>${mode}</b>. Dev split: ${fw.splits.dev.attack_success_rate}% of attacks got through. ` +
    `Roughly half the cases reuse attack strings and questions written independently of the firewall. ` +
    `${res.dataset.cases} cases total · run ${res.generated_at.slice(0, 10)} on commit <code>${esc(res.commit)}</code>.`;

  let shown = false;
  new IntersectionObserver(([e], obs) => {
    if (!e.isIntersecting || shown) return;
    shown = true; obs.disconnect();
    countUp($("#asr-sieve"), t.attack_success_rate, "%");
    countUp($("#asr-base"), bt.attack_success_rate, "%");
    countUp($("#fpr"), t.false_positive_rate, "%");
    countUp($("#lat"), t.latency_ms.p50, " ms", 1);
    document.querySelectorAll(".bar-fill").forEach((b, i) => setTimeout(() => (b.style.width = b.dataset.w + "%"), 200 + i * 120));
  }, { threshold: 0.3 }).observe($("#results"));
}

initPlayground();
initResults();
