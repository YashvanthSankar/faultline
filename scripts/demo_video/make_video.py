"""Produce the Faultline demo video from REAL runs of the tool.

Scenes:
  card  - a title card (HTML rendered by headless Chrome)
  term  - a real macOS Terminal window running real commands, screen-recorded with ffmpeg
  web   - the real local dashboard driven by Playwright, recorded by the browser
Narration: macOS `say` (synthesized voice), one audio file per scene; each scene's
footage is recorded for at least as long as its narration.

    Requirements (macOS): ffmpeg, vhs (brew install vhs), playwright (pip install playwright && playwright install chromium).
    Start the dashboard first:  faultline web --port 8777 --no-browser
    Then:                       python scripts/demo_video/make_video.py
    Concatenate build/demo_video/S*.mp4 in order to get the final video.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(REPO, "build", "demo_video")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
VOICE = "Samantha"
RATE = "178"
W, H = 1920, 1080
# Terminal window in screen points; Retina scale 2 → crop in pixels
TB = (120, 80, 1220, 699)
CROP = f"crop={(TB[2]-TB[0])*2}:{(TB[3]-TB[1])*2}:{TB[0]*2}:{TB[1]*2},scale={W}:{H}:flags=lanczos"

SCENES: list[dict] = [
    dict(id="S00", kind="card", title="Faultline", sub="Is my network broken, or is someone breaking it?",
         foot="Team Moorthy Gang · Yashvanth S (CS24I1029) · IIITDM Kancheepuram Cybersecurity Hackathon",
         say="This is Faultline, by team Moorthy Gang. It answers one question: is my network broken, or is someone breaking it?"),
    dict(id="S01", kind="card", title="The problem",
         sub="An outage and an attack look the same to the person suffering them.",
         bullets=["Two devices sharing one IP address  ·  an attacker spoofing ARP", "A dead DNS server  ·  a hijacked DNS server",
                  "The answer is in a packet capture, and reading one takes an expert"],
         say=("When a small office network misbehaves, the real answer is in a packet capture, and reading one takes an expert. "
              "Worse, an outage and an attack look the same to the user. Two devices sharing an IP address, and an attacker "
              "spoofing ARP, both feel like flaky Wi-Fi. Faultline reads the capture and tells you which one it is, why, and what to do.")),
    dict(id="S02", kind="term", cmds=["faultline analyze samples/mitm_chain.pcap | head -40"],
         say=("Here is the command line tool on a capture from a small office. The verdict: under attack. A rogue DHCP server "
              "handed laptops a fake router and a fake DNS server. Faultline links three findings into one incident: the rogue "
              "server is the root cause, and the forged DNS answers and the leaked password are its consequences. It says what "
              "to fix first, with real commands.")),
    dict(id="S03", kind="term", cmds=["faultline analyze samples/lossy_link.pcap | head -40"],
         say=("A different capture. This time the verdict is faulty, with no sign of an attack. Five percent of packets are "
              "being lost, on both sides of the capture point, which points to congestion or a weak link rather than one bad "
              "cable. The explanation is written for a beginner, and the fix steps say how to confirm it.")),
    dict(id="S04", kind="web", action="landing",
         say=("The same engine runs in a local web dashboard. You can drop in a capture, or pick one of the labelled sample "
              "scenarios. Nothing leaves your computer.")),
    dict(id="S05", kind="web", action="report_mitm",
         say=("This is the full report for the man in the middle capture. The timeline shows when each problem happened, and "
              "the network map shows the rogue device next to the real router. Each finding explains what is happening, the "
              "likely cause and the fix, with a scoreboard of the evidence for attack, fault and misconfiguration. Every claim "
              "points to exact packet numbers, and you can download just those packets to open in Wireshark.")),
    dict(id="S06", kind="web", action="compare",
         say=("This is the core idea. Both captures show the same symptom: two devices claiming one IP address. On the left, "
              "Faultline concludes it is a misconfiguration, a printer and a laptop with the same address. On the right, it is "
              "ARP spoofing of the router. The difference is in the evidence, and the report shows it.")),
    dict(id="S07", kind="web", action="report_mixed",
         say=("When an outage and an attack happen at the same time, they are reported separately: a DNS outage, which is a "
              "fault, and an unrelated port scan, which is an attack.")),
    dict(id="S08", kind="term",
         cmds=["faultline analyze samples/malformed/bad_magic.pcap",
               "faultline analyze samples/malformed/zero_length.pcap",
               "faultline analyze samples/arp_spoofing.pcap --redact | head -14"],
         say=("Capture files are treated as hostile input. Broken or malicious files get a one line reason and never a crash; "
              "three thousand fuzzed captures produced zero crashes. With the redact option, every IP and MAC address is "
              "replaced before you share a report. And text inside packets is always displayed as plain text, so a capture "
              "full of script tags cannot attack whoever opens the report.")),
    dict(id="S09", kind="term",
         cmds=["faultline bench | tail -4", "python scripts/validate_public.py"],
         say=("Finally, the evidence that it works. On thirty seven labelled captures, Faultline detects all thirty two expected "
              "problems, classifies every one correctly, and raises no false alarms. On public real world captures from the "
              "Wireshark project, it gets twenty out of twenty two, including real Nmap scans, a Teardrop attack and a shell "
              "hidden on the DNS port. The two misses are stealth scans, and we list them as limitations.")),
    dict(id="S10", kind="card", title="Faultline", sub="github.com/YashvanthSankar/faultline",
         bullets=["Offline · Python 3.10+ · own parser and detectors", "37 labelled captures · 339 tests · 0 false alarms",
                  "Every result in this video can be reproduced from the repository"],
         foot="Narration: synthesized voice. All footage: the real tool on the bundled sample captures.",
         say="Faultline runs offline, needs only Python, and every result in this video can be reproduced from the repository. Thank you."),
]


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def duration(path: str) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                         capture_output=True, text=True, check=True).stdout
    return float(out.strip())


SARVAM_SPEAKER = os.environ.get("SARVAM_SPEAKER", "aditya")


def _sarvam(text: str, path: str) -> bool:
    """Narrate with Sarvam AI (bulbul:v3, Indian English) if SARVAM_API_KEY is set. The key is read
    from the environment only and is never written to disk."""
    key = os.environ.get("SARVAM_API_KEY")
    if not key:
        return False
    import base64
    import urllib.request
    body = json.dumps({"text": text, "language_code": "en-IN", "model": "bulbul:v3", "speaker": SARVAM_SPEAKER,
                       "pace": 1.0, "speech_sample_rate": 48000, "output_audio_codec": "wav"}).encode()
    req = urllib.request.Request("https://api.sarvam.ai/text-to-speech", data=body,
                                 headers={"api-subscription-key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.load(r)
    with open(path, "wb") as fh:
        fh.write(base64.b64decode("".join(data["audios"])))
    return True


def narrate(sc: dict) -> float:
    src = os.path.join(OUT, f"{sc['id']}_voice.wav")
    if not _sarvam(sc["say"], src):
        src = os.path.join(OUT, f"{sc['id']}.aiff")
        sh(["say", "-v", VOICE, "-r", RATE, "-o", src, sc["say"]])
    wav = os.path.join(OUT, f"{sc['id']}.wav")
    sh(["ffmpeg", "-loglevel", "error", "-y", "-i", src, "-af", "apad=pad_dur=0.6", "-ar", "48000", "-ac", "2", wav])
    return duration(wav)


# --------------------------------------------------------------------------- cards
CARD_CSS = """
body{margin:0;width:1920px;height:1080px;background:radial-gradient(1200px 700px at 20% 10%,#1d2a3f 0%,#0e141d 60%);
color:#e9edf3;font-family:-apple-system,"SF Pro Display","Helvetica Neue",sans-serif;display:flex;align-items:center}
.wrap{padding:0 160px;width:100%}
h1{font-size:120px;letter-spacing:-3px;margin:0 0 18px;font-weight:800}
h2{font-size:46px;font-weight:500;color:#c9d3df;margin:0 0 48px;max-width:1500px;line-height:1.25}
ul{list-style:none;padding:0;margin:0}
li{font-size:36px;color:#b7c3d1;margin:16px 0;padding-left:36px;position:relative}
li:before{content:"";position:absolute;left:0;top:18px;width:14px;height:14px;border-radius:3px;background:#f2b84b}
.foot{position:absolute;bottom:70px;left:160px;right:160px;font-size:26px;color:#8291a3}
.bar{width:140px;height:6px;background:#f05d5e;border-radius:3px;margin-bottom:40px}
"""


def card(sc: dict, dur: float) -> str:
    import html as HM
    lis = "".join(f"<li>{HM.escape(b)}</li>" for b in sc.get("bullets", []))
    doc = (f"<!doctype html><meta charset=utf-8><style>{CARD_CSS}</style><div class=wrap><div class=bar></div>"
           f"<h1>{HM.escape(sc['title'])}</h1><h2>{HM.escape(sc.get('sub',''))}</h2><ul>{lis}</ul></div>"
           f"<div class=foot>{HM.escape(sc.get('foot',''))}</div>")
    html_path = os.path.join(OUT, f"{sc['id']}.html")
    png = os.path.join(OUT, f"{sc['id']}.png")
    open(html_path, "w").write(doc)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": W, "height": H})
        pg.goto("file://" + html_path)
        pg.screenshot(path=png)
        b.close()
    mp4 = os.path.join(OUT, f"{sc['id']}_v.mp4")
    sh(["ffmpeg", "-loglevel", "error", "-y", "-loop", "1", "-i", png, "-t", f"{dur:.2f}", "-r", "30",
        "-vf", "fade=in:0:12", "-c:v", "libx264", "-pix_fmt", "yuv420p", mp4])
    return mp4


# --------------------------------------------------------------------------- terminal
TYPE_FN = ("t() { printf '\\e[1;32m$\\e[0m '; local s=\"$1\"; local i; for (( i=1; i<=${#s}; i++ )); do printf '%s' \"${s[i]}\"; "
           "sleep 0.028; done; echo; eval \"$s\"; echo; }")


def term_window() -> int:
    rc = os.path.join(HERE, "demo_rc.zsh")
    wid = subprocess.run(["osascript", "-e", f'''tell application "Terminal"
  do script "source {rc}"
  delay 1.2
  set w to front window
  set bounds of w to {{{TB[0]}, {TB[1]}, {TB[2]}, {TB[3]}}}
  return id of w
end tell'''], capture_output=True, text=True, check=True).stdout.strip()
    time.sleep(1.0)
    return int(wid)


def term_run(wid: int, line: str) -> None:
    esc = line.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(["osascript", "-e", f'tell application "Terminal" to do script "{esc}" in (selected tab of (window id {wid}))'],
                   check=True, capture_output=True)


def term_scene(sc: dict, dur: float, wid=None) -> str:
    """Record a real terminal session with VHS (headless terminal, real commands, rendered to video)."""
    raw = os.path.join(OUT, f"{sc['id']}_raw.mp4")
    speed = 0.035
    lines = [
        f'Output "{raw}"',
        'Set Shell "zsh"', "Set FontSize 21", f"Set Width {W}", f"Set Height {H}", "Set Padding 36",
        'Set Theme "Builtin Dark"', "Set TypingSpeed 35ms", "Set Framerate 30", "Set CursorBlink false",
        "Hide",
        f'Type "cd {REPO} && source .venv/bin/activate && export FORCE_COLOR=1 COLUMNS=150 && PS1=\'$ \' && clear"',
        "Enter", "Sleep 1.5s", "Show",
    ]
    per = dur / max(1, len(sc["cmds"]))
    for i, c in enumerate(sc["cmds"]):
        c2 = c.replace('"', '\\"')
        lines += [f'Type "{c2}"', "Sleep 300ms", "Enter"]
        rest = per - len(c) * speed - 0.3
        lines.append(f"Sleep {max(1.5, rest):.1f}s")
        if i < len(sc["cmds"]) - 1:
            lines += ["Hide", 'Type "clear"', "Enter", "Sleep 200ms", "Show"]
    tape = os.path.join(OUT, f"{sc['id']}.tape")
    open(tape, "w").write("\n".join(lines) + "\n")
    sh(["vhs", tape], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return raw


# --------------------------------------------------------------------------- web (Playwright)
def web_scene(sc: dict, dur: float, base: str) -> str:
    from web_actions import ACTIONS  # defined after the new UI lands
    from playwright.sync_api import sync_playwright

    vdir = os.path.join(OUT, f"{sc['id']}_web")
    os.makedirs(vdir, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1600, "height": 900}, record_video_dir=vdir,
                            record_video_size={"width": 1600, "height": 900}, color_scheme="dark")
        page = ctx.new_page()
        t0 = time.time()
        lead = ACTIONS[sc["action"]](page, base, dur)  # returns seconds of loading to trim from the start
        elapsed = time.time() - t0
        if elapsed < dur + lead:
            page.wait_for_timeout(int((dur + lead - elapsed) * 1000))
        ctx.close()
        b.close()
    webm = [f for f in os.listdir(vdir) if f.endswith(".webm")][0]
    raw = os.path.join(OUT, f"{sc['id']}_raw.mp4")
    sh(["ffmpeg", "-loglevel", "error", "-y", "-ss", f"{lead:.2f}", "-i", os.path.join(vdir, webm), "-t", f"{dur:.2f}",
        "-vf", f"scale={W}:{H}:flags=lanczos,fps=30", "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", raw])
    return raw


# --------------------------------------------------------------------------- assembly
def mux(sc: dict, video: str, dur: float) -> str:
    out = os.path.join(OUT, f"{sc['id']}.mp4")
    wav = os.path.join(OUT, f"{sc['id']}.wav")
    sh(["ffmpeg", "-loglevel", "error", "-y", "-i", video, "-i", wav,
        "-vf", f"scale={W}:{H},fps=30,tpad=stop_mode=clone:stop_duration=3,format=yuv420p",
        "-t", f"{dur:.2f}", "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-c:a", "aac", "-b:a", "160k", "-ar", "48000", out])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip-web", action="store_true")
    ap.add_argument("--base", default="http://127.0.0.1:8777")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    only = set(filter(None, a.only.split(",")))
    wid = None
    made = []
    for sc in SCENES:
        if only and sc["id"] not in only:
            continue
        if a.skip_web and sc["kind"] == "web":
            continue
        dur = narrate(sc)
        if sc["kind"] == "card":
            v = card(sc, dur)
        elif sc["kind"] == "term":
            v = term_scene(sc, dur)
        else:
            v = web_scene(sc, dur, a.base)
        made.append(mux(sc, v, dur))
        print(f"{sc['id']} {sc['kind']:<5} {dur:5.1f}s", flush=True)
    if wid is not None:
        subprocess.run(["osascript", "-e", f'tell application "Terminal" to close (every window whose id is {wid}) saving no'],
                       capture_output=True)
    json.dump(made, open(os.path.join(OUT, "made.json"), "w"))


if __name__ == "__main__":
    main()
