"""Record the Sieve demo video with an AI voiceover.

    pip install edge-tts playwright imageio-ffmpeg
    uvicorn locus_mock.app:app --port 8000          # in another terminal (RATE_LIMIT_PER_MIN=0)
    python scripts/video/make_video.py              # writes out/sieve-demo.mp4

Each scene's narration is synthesized first, then the real site is driven in Edge and recorded,
holding every scene exactly as long as its voiceover. Numbers in the narration are read from
results.json, so the video always matches the benchmark.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent
OUT = ROOT / "out"
AUDIO = OUT / "audio"
SITE = "http://localhost:8000"
VOICE, RATE = "en-US-AndrewNeural", "+3%"
W, H = 1600, 900
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

res = json.loads((ROOT / "results.json").read_text(encoding="utf-8"))
fw, base = res["setups"]["firewall"]["test"], res["setups"]["baseline1"]["test"]
fresh = fw["by_origin"].get("teammate-fresh", {})
stopped = round(100 - fw["attack_success_rate"])
stale_stopped = round(100 - fw["by_category"]["stale_permissions"]["attack_success_rate"])
n_cases = res["dataset"]["cases"]

SCENES = [
    ("title", "This is Sieve. It catches the bad chunks before your LLM reads them."),
    ("problem", "Retrieval augmented generation trusts every chunk the retriever returns. Most RAG stacks only check "
                "metadata, like the access tags copied into the index. They never read what a chunk actually says. "
                "So a hidden instruction, a fake policy, a stale permission, or a leaked key goes straight into the model."),
    ("hero", "Sieve sits between the retriever and the LLM. Every chunk leaves with a decision: allow, redact, or block. "
             "And a reason."),
    ("poison", "Here is a real retrieval. Maya asks whether she should disable MFA during deployments. Without Sieve, "
               "a metadata filter lets everything through, including a low-trust community tip telling engineers to turn "
               "MFA off and route traffic through an unauthenticated proxy. With Sieve, that tip is blocked, and the "
               "official MFA policy still reaches the model."),
    ("injection", "This uploaded report hides an instruction to bypass safety and print the admin API token. "
                  "Sieve blocks it. A support ticket with a fake status banner is caught too."),
    ("pii", "A contractor record leaks a social security number, a personal email, an access token and a home address. "
            "Sieve redacts each one, and keeps the rest of the record useful."),
    ("stale", "Alice left the company yesterday. The index still says she is in finance, so the retriever happily "
              "returns the Q3 review. Sieve re-checks the live identity provider, sees the account is deactivated, "
              "and blocks it."),
    ("trace", "And every decision is traceable: what was checked, what it scored, and why."),
    ("results", f"We benchmarked it on {n_cases} cases across all five attack types, and report a held-out test split. "
                f"Metadata filtering lets {round(base['attack_success_rate'])} percent of attacks through. "
                f"Sieve, on rules alone, stops {stopped} percent, including {stale_stopped} percent of stale permission attacks, "
                f"in under a millisecond."),
    ("honest", f"Then a teammate wrote 45 new cases without ever looking at the firewall. On those, "
               f"{round(fresh.get('attack_success_rate', 0))} percent of attacks got through, and "
               f"{round(fresh.get('false_positive_rate', 0))} percent of the tricky benign documents were flagged. "
               f"We publish that number, because it shows exactly where rules end."),
    ("how", "That is what the agent's second stage is for. Cheap checks run on every chunk. Only the risky ones are "
            "escalated to LLM judges, within a fixed budget, falling back to rules if the model is unavailable. "
            "The judges are built and wired in. Running them on Nemotron is our next step."),
    ("close", "Sieve. Don't trust retrieval. Verify it."),
]

PAD_AFTER = 0.55  # breathing room between scenes
HOLD = {"close": 3.5}  # extra seconds to hold a scene after its voiceover ends


# 1. Voiceover ----------------------------------------------------------------------------

def duration(path: Path) -> float:
    out = subprocess.run([FFMPEG, "-i", str(path)], capture_output=True, text=True).stderr
    h, m, s = re.search(r"Duration: (\d+):(\d+):([\d.]+)", out).groups()
    return int(h) * 3600 + int(m) * 60 + float(s)


async def speak(text: str, path: Path, attempts: int = 5):
    """The free TTS service occasionally drops a request; retry with backoff."""
    for i in range(attempts):
        try:
            await edge_tts.Communicate(text, VOICE, rate=RATE).save(str(path))
            return
        except Exception as e:  # NoAudioReceived, websocket resets
            if i == attempts - 1:
                raise
            print(f"    retrying ({e.__class__.__name__})")
            await asyncio.sleep(2 * (i + 1))


async def synthesize() -> dict[str, float]:
    AUDIO.mkdir(parents=True, exist_ok=True)
    lengths = {}
    for name, text in SCENES:
        path = AUDIO / f"{name}.mp3"
        stamp = path.with_suffix(".txt")  # reuse a clip only if its exact text and voice are unchanged
        key = f"{VOICE}|{RATE}|{text}"
        if not (path.exists() and stamp.exists() and stamp.read_text(encoding="utf-8") == key):
            await speak(text, path)
            stamp.write_text(key, encoding="utf-8")
        lengths[name] = duration(path)
        print(f"  voice {name:<10} {lengths[name]:5.1f}s")
    return lengths


# 2. Screen recording ------------------------------------------------------------------------

CURSOR = """
(() => {
  if (window.__cursor) return;
  const c = document.createElement('div');
  c.style.cssText = 'position:fixed;left:0;top:0;width:18px;height:18px;border-radius:50%;pointer-events:none;z-index:99999;' +
    'background:rgba(238,233,222,.95);box-shadow:0 0 0 6px rgba(238,233,222,.18);transform:translate(-200px,-200px);' +
    'transition:transform .05s linear, box-shadow .2s;';
  const add = () => document.body && document.body.appendChild(c);
  document.readyState === 'loading' ? addEventListener('DOMContentLoaded', add) : add();
  addEventListener('mousemove', e => c.style.transform = `translate(${e.clientX - 9}px, ${e.clientY - 9}px)`);
  addEventListener('mousedown', () => c.style.boxShadow = '0 0 0 14px rgba(255,74,61,.35)');
  addEventListener('mouseup', () => setTimeout(() => c.style.boxShadow = '0 0 0 6px rgba(238,233,222,.18)', 180));
  window.__cursor = c;
})();
"""


class Director:
    def __init__(self, page):
        self.page = page
        self.mouse = (W * 0.7, H * 0.6)

    def scroll_to(self, selector: str, offset: int = 70):
        self.page.evaluate(
            """([s, o]) => { const el = document.querySelector(s);
                 window.scrollTo({ top: el.getBoundingClientRect().top + scrollY - o, behavior: 'smooth' }); }""",
            [selector, offset])
        time.sleep(1.1)

    def scroll_by(self, dy: int):
        self.page.evaluate("dy => window.scrollBy({ top: dy, behavior: 'smooth' })", dy)
        time.sleep(0.9)

    def move_to(self, selector: str):
        box = self.page.locator(selector).first.bounding_box()
        x, y = box["x"] + min(box["width"] / 2, 120), box["y"] + box["height"] / 2
        self.page.mouse.move(x, y, steps=28)
        self.mouse = (x, y)

    def click(self, selector: str):
        self.move_to(selector)
        time.sleep(0.25)
        self.page.mouse.down(); time.sleep(0.08); self.page.mouse.up()  # a real click at the cursor

    def scenario(self, index: int):
        self.click(f'#scenarios li:nth-child({index + 1}) button')


def run_scene(d: Director, name: str):
    p = d.page
    if name == "title":
        p.goto((HERE / "slides" / "title.html").as_uri())
    elif name == "problem":
        p.goto((HERE / "slides" / "problem.html").as_uri())
    elif name == "hero":
        p.goto(SITE)
        p.wait_for_load_state("networkidle")
    elif name == "poison":
        d.scroll_to("#playground .play", offset=24)  # scrolling in starts the first scenario
        time.sleep(9)
        d.move_to('#lane-sieve .card.block')
    elif name == "injection":
        d.scenario(2)
        time.sleep(5)
        d.scenario(3)
    elif name == "pii":
        d.scenario(4)
        time.sleep(3.5)
        d.move_to('#lane-sieve .card.redact')
    elif name == "stale":
        d.scenario(7)
        time.sleep(1.2)
        d.move_to('#identity')
        time.sleep(4.5)
        d.move_to('#lane-sieve .card.block')
    elif name == "trace":
        d.click('#trace-wrap summary')
        time.sleep(0.4)
        d.scroll_by(260)
    elif name == "results":
        d.scroll_to("#results", offset=40)
        time.sleep(5)
        d.scroll_to(".bars-wrap", offset=120)
    elif name == "honest":
        p.evaluate("""() => { const f = document.querySelector('#fineprint');
            f.style.transition = 'color .6s, background .6s'; f.style.color = '#EEE9DE';
            f.style.background = 'rgba(255,74,61,.10)'; f.style.padding = '12px 14px'; f.style.borderRadius = '8px'; }""")
        d.move_to('#fineprint')
    elif name == "how":
        d.scroll_to("#how", offset=60)
        for i in range(1, 4):
            time.sleep(2.2)
            d.move_to(f'.steps .step:nth-child({i})')
    elif name == "close":
        line = "Don&#39;t trust retrieval. <em>Verify it.</em>"
        p.goto((HERE / "slides" / "title.html").as_uri() + f"?line={line}&url=github.com/Abbas-Rahman-c/retrieval-firewall")


def record(lengths: dict[str, float]) -> tuple[Path, dict[str, float]]:
    OUT.mkdir(exist_ok=True)
    offsets = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(OUT / "raw"),
                                  record_video_size={"width": W, "height": H}, reduced_motion="no-preference")
        ctx.add_init_script(CURSOR)
        page = ctx.new_page()
        t0 = time.monotonic()
        d = Director(page)
        time.sleep(0.6)
        for name, _ in SCENES:
            start = time.monotonic()
            offsets[name] = start - t0
            run_scene(d, name)
            remaining = lengths[name] + PAD_AFTER + HOLD.get(name, 0) - (time.monotonic() - start)
            if remaining < 0:
                print(f"  ! scene {name} ran {-remaining:.1f}s past its voiceover")
            time.sleep(max(0.0, remaining))
            print(f"  shot  {name:<10} at {offsets[name]:6.1f}s")
        time.sleep(1.0)
        video = Path(page.video.path())
        ctx.close()
        browser.close()
    return video, offsets


# 3. Mix -----------------------------------------------------------------------------------

def mix(video: Path, offsets: dict[str, float], out: Path):
    names = [n for n, _ in SCENES]
    cmd = [FFMPEG, "-y", "-i", str(video)]
    for n in names:
        cmd += ["-i", str(AUDIO / f"{n}.mp3")]
    delays = "".join(f"[{i + 1}:a]adelay={int(offsets[n] * 1000)}:all=1[a{i}];" for i, n in enumerate(names))
    mixed = "".join(f"[a{i}]" for i in range(len(names))) + f"amix=inputs={len(names)}:normalize=0,apad[a]"  # pad so the video, not the voice, sets the length
    cmd += ["-filter_complex", "[0:v]scale=1920:1080:flags=lanczos[v];" + delays + mixed, "-map", "[v]", "-map", "[a]",
            "-c:v", "libx264", "-preset", "slow", "-crf", "18",
            "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k", "-shortest", str(out)]
    subprocess.run(cmd, check=True, capture_output=True)


def main():
    print("1/3 voiceover")
    lengths = asyncio.run(synthesize())
    total = sum(lengths.values()) + PAD_AFTER * len(lengths)
    print(f"    total narration {total:.0f}s")
    if total > 175:
        sys.exit("narration is over the 3-minute limit; shorten the script")
    print("2/3 recording")
    video, offsets = record(lengths)
    print("3/3 mixing")
    out = OUT / "sieve-demo.mp4"
    mix(video, offsets, out)
    print(f"done: {out} ({duration(out):.0f}s)")


if __name__ == "__main__":
    main()
