# The waitlist that writes back

Sign up on rapterbox.com and something real happens: an email from wildhavenhomesllc@gmail.com
lands in your inbox, and if you gave a phone number, a text arrives from Kody's own number.
That is the RapterBox story told by the product itself — the same automation that runs
Wildhaven Homes (real-estate follow-ups, the chasing, the remembering) is what welcomed you.

No PII lives in this repository. Signups go to a private Google Sheet in the Wildhaven Homes
Google account; the only thing here is the code.

## Turn it on (six clicks, once)

1. Signed in as **wildhavenhomesllc@gmail.com**, open https://script.google.com → **New project**.
2. Replace the editor contents with `waitlist/Code.gs` from this repo. Rename the project "RapterBox waitlist".
3. Project Settings (gear) → **Script properties** → add `WAITLIST_TOKEN` = any long random string
   (this is the texter's key; it never enters a repo).
4. **Deploy → New deployment → Web app** — *Execute as: Me* · *Who has access: Anyone* → Deploy.
   Approve the permissions prompt (Sheets + Gmail send, for this account only).
5. Copy the **Web app URL** (ends in `/exec`). Paste it into `waitlist-config.js` in this repo → push.
   From that moment every signup gets the real email.
6. Texts: on the Mac that stays on, create `~/.wildhaven-waitlist.json`:
   `{"endpoint": "<that /exec URL>", "token": "<WAITLIST_TOKEN>"}`, then
   render the launchd template with the absolute path of your checkout:

   ```bash
   sed "s#__RAPTERBOX_SITE_ROOT__#$(pwd)#g" \
     waitlist/com.wildhaven.waitlist-texter.plist \
     > ~/Library/LaunchAgents/com.wildhaven.waitlist-texter.plist
   launchctl load ~/Library/LaunchAgents/com.wildhaven.waitlist-texter.plist
   ```

   Every 5 minutes `texter.py` sends the welcome text through Messages.app to anyone who gave a
   phone number and hasn't been texted, then marks them. `python3 waitlist/texter.py --dry-run`
   shows who would be texted without sending.

## Dependability notes
- Email is serverless and always on (Google runs the script). Texts depend on the Mac being on —
  they are queued in the Sheet until it is, never lost.
- With `WAITLIST_ENDPOINT` empty, the form behaves exactly as before (Formspree).
- Duplicate emails are welcomed once; a second signup gets "already on the list".
