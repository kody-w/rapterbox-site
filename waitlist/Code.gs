/**
 * RapterBox waitlist — Google Apps Script web app (runs as wildhavenhomesllc@gmail.com).
 *
 * What it does, and only this:
 *   POST  {name, email, phone?, note?, source}  -> appends a row to a PRIVATE Sheet in this
 *         account's Drive, de-duplicates by email, and sends the confirmation email from the
 *         account this script runs as. Returns {ok:true, welcomed:true|false}.
 *   GET   ?token=<shared>&pending=1             -> the local texter's feed: signups with a phone
 *         number that have not been texted yet. Never exposed without the token.
 *   POST  {token, texted: <email>}              -> marks a signup as texted.
 *
 * No PII lives in any repository: the Sheet is private to the Google account; the token is a
 * Script Property (File > Project properties > Script properties: WAITLIST_TOKEN), never code.
 */

const SHEET_NAME = 'waitlist';

function sheet_() {
  const props = PropertiesService.getScriptProperties();
  let id = props.getProperty('WAITLIST_SHEET_ID');
  let ss = id ? SpreadsheetApp.openById(id) : null;
  if (!ss) {
    ss = SpreadsheetApp.create('RapterBox waitlist (private)');
    props.setProperty('WAITLIST_SHEET_ID', ss.getId());
  }
  let sh = ss.getSheetByName(SHEET_NAME);
  if (!sh) {
    sh = ss.insertSheet(SHEET_NAME);
    sh.appendRow(['ts', 'name', 'email', 'phone', 'note', 'source', 'emailed_at', 'texted_at']);
  }
  return sh;
}

function json_(obj, code) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

function normEmail_(e) { return String(e || '').trim().toLowerCase(); }
function normPhone_(p) {
  const digits = String(p || '').replace(/\D/g, '');
  if (!digits) return '';
  return digits.length === 10 ? '+1' + digits : (digits.length === 11 && digits[0] === '1' ? '+' + digits : '+' + digits);
}

function doPost(e) {
  let body = {};
  try { body = JSON.parse(e.postData.contents); } catch (_) { body = e.parameter || {}; }
  const props = PropertiesService.getScriptProperties();

  // texter callback
  if (body.token && body.texted) {
    if (body.token !== props.getProperty('WAITLIST_TOKEN')) return json_({ ok: false, error: 'bad token' });
    const sh = sheet_(); const rows = sh.getDataRange().getValues();
    for (let i = 1; i < rows.length; i++) {
      if (normEmail_(rows[i][2]) === normEmail_(body.texted)) { sh.getRange(i + 1, 8).setValue(new Date().toISOString()); }
    }
    return json_({ ok: true });
  }

  const name = String(body.name || '').trim().slice(0, 100);
  const email = normEmail_(body.email);
  const phone = normPhone_(body.phone);
  const note = String(body.note || '').trim().slice(0, 2000);
  const source = String(body.source || 'rapterbox.com').slice(0, 100);
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json_({ ok: false, error: 'name and a valid email are required' });

  const sh = sheet_();
  const rows = sh.getDataRange().getValues();
  const dup = rows.slice(1).some(r => normEmail_(r[2]) === email);
  if (dup) return json_({ ok: true, welcomed: false, note: 'already on the list' });

  sh.appendRow([new Date().toISOString(), name, email, phone, note, source, '', '']);

  const first = name.split(/\s+/)[0];
  const subject = 'You are on the RapterBox waitlist';
  const text =
`${first} —

You're on the list. This note is real: it was sent by the same automation that runs Wildhaven Homes.

That's the whole story of RapterBox. It started as real-estate automation — the chasing, the follow-ups, the "did anyone reply to that?" — and became a box that does the remembering and the chasing so the person doesn't have to. You just watched it work: you signed up, and a machine that never forgets wrote back.

What happens next: when your spot opens, you'll hear from this same address${phone ? ' (and by text at the number you gave)' : ''}. Reply to this email any time — a human reads it.

— Kody
Wildhaven Homes LLC · rapterbox.com`;

  GmailApp.sendEmail(email, subject, text, { name: 'Kody at Wildhaven Homes', replyTo: 'wildhavenhomesllc@gmail.com' });
  const last = sh.getLastRow(); sh.getRange(last, 7).setValue(new Date().toISOString());
  return json_({ ok: true, welcomed: true, text: !!phone });
}

function doGet(e) {
  const props = PropertiesService.getScriptProperties();
  const token = (e.parameter || {}).token || '';
  if (!token || token !== props.getProperty('WAITLIST_TOKEN')) return json_({ ok: false, error: 'bad token' });
  const sh = sheet_(); const rows = sh.getDataRange().getValues();
  const pending = rows.slice(1)
    .filter(r => r[3] && !r[7])
    .map(r => ({ name: r[1], email: r[2], phone: r[3], ts: r[0] }));
  return json_({ ok: true, pending });
}
