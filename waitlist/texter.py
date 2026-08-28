#!/usr/bin/env python3
"""waitlist texter — sends the real welcome text from Kody's own number via Messages.app.

Same mechanism hn-scout uses: an AppleScript `send` through Messages.app (iMessage, or SMS
relay through the paired iPhone). Polls the Apps Script feed for signups with a phone number
that have not been texted, sends one message each, and marks them texted.

Config (local only, never in a repo): ~/.wildhaven-waitlist.json
    {"endpoint": "https://script.google.com/macros/s/.../exec", "token": "<WAITLIST_TOKEN>"}

    python3 texter.py            # one pass (run it from launchd every 5 minutes)
    python3 texter.py --dry-run  # show who would be texted, send nothing
"""
import json, os, subprocess, sys, urllib.request, urllib.parse

CFG = os.path.expanduser("~/.wildhaven-waitlist.json")
MSG = ("{first} — you're on the RapterBox waitlist. This text is real: the same automation that runs "
       "Wildhaven Homes just sent it. When your spot opens, this number will tell you. — Kody")


def load_cfg():
    try:
        with open(CFG) as f:
            c = json.load(f)
        assert c.get("endpoint") and c.get("token")
        return c
    except Exception:
        sys.exit(f"config missing or incomplete: {CFG} needs endpoint + token")


def fetch_pending(c):
    url = c["endpoint"] + "?" + urllib.parse.urlencode({"token": c["token"], "pending": "1"})
    with urllib.request.urlopen(url, timeout=30) as r:
        d = json.load(r)
    if not d.get("ok"):
        sys.exit(f"feed refused: {d.get('error')}")
    return d.get("pending", [])


def send_text(phone, text):
    script = (
        'tell application "Messages"\n'
        '  set svc to 1st account whose service type = iMessage\n'
        f'  set theText to "{text.replace(chr(34), chr(39))}"\n'
        f'  send theText to participant "{phone}" of svc\n'
        'end tell'
    )
    subprocess.run(["/usr/bin/osascript", "-e", script], timeout=60, check=True)


def mark_texted(c, email):
    data = json.dumps({"token": c["token"], "texted": email}).encode()
    req = urllib.request.Request(c["endpoint"], data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=30).read()


def main():
    dry = "--dry-run" in sys.argv
    c = load_cfg()
    pending = fetch_pending(c)
    if not pending:
        print("nothing pending"); return 0
    for p in pending:
        first = str(p.get("name", "")).split()[0] if p.get("name") else "Hey"
        text = MSG.format(first=first)
        if dry:
            print(f"DRY: would text {p['phone']} ({p['email']}): {text[:60]}…"); continue
        send_text(p["phone"], text)
        mark_texted(c, p["email"])
        print(f"texted {p['phone']} ({p['email']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
