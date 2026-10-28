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
from urllib.parse import urlencode

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent
OUT = ROOT / "out"
AUDIO = OUT / "audio"
SITE = "http://localhost:8000"
VOICE, RATE = "en-US-AndrewNeural", "+3%"
TEAM = "Abbas Rahman · Humayun Arshad · Sunaina Babar"
W, H = 1600, 900
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

res = json.loads((ROOT / "results.json").read_text(encoding="utf-8"))
fw, base = res["setups"]["firewall"]["test"], res["setups"]["baseline1"]["test"]
rules = res["setups"].get("firewall_rules", {}).get("test", fw)
fresh = fw["by_origin"].get("teammate-fresh", {})
fresh_rules = rules["by_origin"].get("teammate-fresh", {})
n_cases = res["dataset"]["cases"]
pct = lambda x: f"{x:.0f}" if x >= 10 or x == int(x) else f"{x:.1f}".rstrip("0").rstrip(".")

SCENES = [
    ("title", "This is Sieve, a team project by Abbas Rahman, Humayun Arshad and Sunaina Babar. "
              "It catches the bad chunks before your LLM reads them."),
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
    ("results", f"We benchmarked it on {n_cases} cases across all five attack types, on a held-out test split. "
                f"Metadata filtering lets {pct(base['attack_success_rate'])} percent of attacks through. Sieve's rules alone let "
                f"{pct(rules['attack_success_rate'])} percent through. With its Nemotron judges running on Nebius Token Factory, "
                f"just {pct(fw['attack_success_rate'])} percent get through."),
    ("honest", f"We also had a teammate write 45 cases without ever seeing the firewall. On rules alone, "
               f"{pct(fresh_rules.get('attack_success_rate', 0))} percent of those attacks got through. With Nemotron, "
               f"{pct(fresh.get('attack_success_rate', 0))} percent. Its weak spot is still false positives on security "
               f"training material, and we say so."),
    ("how", "Here is how the agent works. Cheap rules check every chunk. Only the risky ones, and anything from an "
            "untrusted source, go to Nemotron 3 Nano, with its reasoning switched off for speed. The judge can add a "
            "block, but never overrule a strong rule signal. And if the model is down, the rules still decide."),
    ("close", "Sieve. Built together by Abbas, Humayun and Sunaina. Don't trust retrieval. Verify it."),
]

PAD_AFTER = 0.55  # breathing room between scenes
HOLD = {"title": 1.0, "close": 4.0}  # extra seconds to hold a scene after its voiceover ends


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
        p.goto((HERE / "slides" / "title.html").as_uri() + "?" + urlencode({"team": TEAM}))
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
        query = urlencode({"line": "Don't trust retrieval. <em>Verify it.</em>", "team": TEAM,
                           "url": "github.com/Abbas-Rahman-c/retrieval-firewall"})
        p.goto((HERE / "slides" / "title.html").as_uri() + "?" + query)


def record(lengths: dict[str, float]) -> tuple[Path, dict[str, float]]:
    OUT.mkdir(exist_ok=True)
    offsets = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(OUT / "raw"),
                                  record_video_size={"width": W, "height": H}, reduced_motion="no-preference")
        ctx.add_init_script(CURSOR)
        page = ctx.new_page()
        t_video = time.monotonic()  # the recording starts here; everything before t0 is trimmed in the mix
        # Warm the font cache so the first scene doesn't open on a blank screen, then start on a dark page.
        page.goto((HERE / "slides" / "title.html").as_uri())
        page.evaluate("document.fonts.ready")
        page.goto(SITE)
        page.wait_for_load_state("networkidle")
        page.evaluate("""async () => {
            const samples = await (await fetch('/samples')).json();
            for (const s of samples) for (const mode of ['baseline1', 'firewall'])
                await fetch('/ask', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                     body: JSON.stringify({user_id: s.user_id, query: s.query, mode, top_k: 5})});
        }""")
        page.set_content('<body style="margin:0;background:#0B0C0D"></body>')
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
        offsets["_end"] = time.monotonic() - t0
        offsets["_trim"] = t0 - t_video
        video = Path(page.video.path())
        ctx.close()
        browser.close()
    # Saved so the mix can be redone without re-recording: python make_video.py --mix-only
    (OUT / "take.json").write_text(json.dumps({"video": str(video), "offsets": offsets}, indent=1), encoding="utf-8")
    return video, offsets


# 3. Mix -----------------------------------------------------------------------------------

def mix(video: Path, offsets: dict[str, float], out: Path):
    names = [n for n, _ in SCENES]
    cmd = [FFMPEG, "-y", "-i", str(video)]
    for n in names:
        cmd += ["-i", str(AUDIO / f"{n}.mp3")]
    delays = "".join(f"[{i + 1}:a]adelay={int(offsets[n] * 1000)}:all=1[a{i}];" for i, n in enumerate(names))
    trim = offsets.get("_trim", 0.0)
    # Playwright drops the last frames when the browser closes, so end at the last real frame, not the wall clock.
    decoded = subprocess.run([FFMPEG, "-i", str(video), "-map", "0:v", "-f", "null", "-"], capture_output=True, text=True).stderr
    h, m, sec = re.findall(r"time=(\d+):(\d+):([\d.]+)", decoded)[-1]
    end = min(offsets["_end"], int(h) * 3600 + int(m) * 60 + float(sec) - trim - 0.05)
    # Pad the voice track to exactly the video's length: an unbounded apad never lets ffmpeg finish.
    mixed = "".join(f"[a{i}]" for i in range(len(names))) + f"amix=inputs={len(names)}:normalize=0,apad=whole_dur={end:.2f}[a]"
    # trim drops the recorded warm-up so picture and voice share time zero
    video_chain = f"[0:v]trim=start={trim:.3f},setpts=PTS-STARTPTS,scale=1920:1080:flags=lanczos[v];"
    cmd += ["-filter_complex", video_chain + delays + mixed, "-map", "[v]", "-map", "[a]",
            "-t", f"{end:.2f}", "-c:v", "libx264", "-preset", "slow", "-crf", "18",
            "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", str(out)]
    subprocess.run(cmd, check=True, capture_output=True, timeout=900)


def main():
    if "--mix-only" in sys.argv:
        take = json.loads((OUT / "take.json").read_text(encoding="utf-8"))
        out = OUT / "sieve-demo.mp4"
        mix(Path(take["video"]), take["offsets"], out)
        print(f"done: {out} ({duration(out):.0f}s)")
        return
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
