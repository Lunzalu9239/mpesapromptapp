const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rid = () => [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });
const PRICE = 10000, PERIOD = 30 * 864e5; // KES 100 in cents, 30 days
const AL = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const mkCode = n => [...crypto.getRandomValues(new Uint8Array(n))].map(x => AL[x % 32]).join('');
const dash = c => c ? c.match(/.{1,4}/g).join('-') : null;
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const sha = async s => b64(await crypto.subtle.digest('SHA-256', enc.encode(s)));

async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(salt), iterations: 100000 }, k, 256));
}
const aesKey = async env => crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc.encode(env.ENC_KEY)), 'AES-GCM', false, ['encrypt', 'decrypt']);
async function seal(env, o) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return b64(iv) + '.' + b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), enc.encode(JSON.stringify(o))));
}
async function unseal(env, s) {
  if (!s) return null;
  const [i, c] = s.split('.');
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(i) }, await aesKey(env), unb64(c))));
}

const withB = async (env, u) => { u.B = u.role === 'staff' ? await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(u.business_id).first() : u; return u.B ? u : null; };
async function authUser(req, env) {
  const m = /sid=([a-f0-9]+)/.exec(req.headers.get('cookie') || '');
  if (!m) return null;
  const u = await env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').bind(m[1], Date.now()).first();
  return u && withB(env, u);
}
async function hmac512(secret, text) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(text)))].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function settleSub(env, ref) {
  const r = await env.DB.prepare("UPDATE billing SET status='success',paid_at=? WHERE ref=? AND status!='success'").bind(Date.now(), ref).run();
  if (!r.meta.changes) return;
  const b = await env.DB.prepare('SELECT user_id FROM billing WHERE ref=?').bind(ref).first();
  await env.DB.prepare('UPDATE users SET access_until=MAX(COALESCE(access_until,0),?)+? WHERE id=?').bind(Date.now(), PERIOD, b.user_id).run();
}
async function startSession(env, uid) {
  const t = rid() + rid();
  await env.DB.prepare('INSERT INTO sessions VALUES(?,?,?)').bind(t, uid, Date.now() + 365 * 864e5).run();
  return { 'set-cookie': `sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000` };
}
function normPhone(p) {
  p = String(p || '').replace(/\D/g, '');
  if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1);
  else if (/^[17]\d{8}$/.test(p)) p = '254' + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
}
async function tg(env, chat, text) {
  if (!env.TELEGRAM_TOKEN || !chat) return;
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: chat, text }) }).catch(() => {});
}
// Nairobi day range (UTC+3)
const dayRange = t => { const s = Math.floor((t + 108e5) / 864e5) * 864e5 - 108e5; return [s, s + 864e5]; };
async function daySum(env, col, id, t) {
  const [a, b] = dayRange(t);
  return (await env.DB.prepare(`SELECT COALESCE(SUM(amount),0) s FROM tx WHERE ${col}=? AND status='success' AND created_at>=? AND created_at<?`).bind(id, a, b).first()).s;
}

// ---------- Daraja ----------
const base = s => s.env === 'live' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
async function darajaToken(s) {
  const r = await fetch(base(s) + '/oauth/v1/generate?grant_type=client_credentials', { headers: { Authorization: 'Basic ' + btoa(s.key + ':' + s.secret) } });
  if (!r.ok) throw new Error('Safaricom rejected the consumer key or secret');
  return (await r.json()).access_token;
}
const stamp = () => new Date().toISOString().replace(/\D/g, '').slice(0, 14);
async function stkPush(s, tx, origin) {
  const t = await darajaToken(s), ts = stamp(), till = s.type === 'till';
  const r = await fetch(base(s) + '/mpesa/stkpush/v1/processrequest', {
    method: 'POST', headers: { Authorization: 'Bearer ' + t, 'content-type': 'application/json' },
    body: JSON.stringify({ BusinessShortCode: s.shortcode, Password: btoa(s.shortcode + s.passkey + ts), Timestamp: ts,
      TransactionType: till ? 'CustomerBuyGoodsOnline' : 'CustomerPayBillOnline', Amount: tx.amount, PartyA: tx.phone,
      PartyB: till ? s.account : s.shortcode, PhoneNumber: tx.phone, CallBackURL: `${origin}/api/callback/${tx.cbkey}`,
      AccountReference: String(tx.ref || (till ? 'Payment' : s.account)).slice(0, 12), TransactionDesc: 'Payment' })
  });
  return r.json();
}
async function stkQuery(s, checkoutId) {
  const t = await darajaToken(s), ts = stamp();
  const r = await fetch(base(s) + '/mpesa/stkpushquery/v1/query', { method: 'POST', headers: { Authorization: 'Bearer ' + t, 'content-type': 'application/json' },
    body: JSON.stringify({ BusinessShortCode: s.shortcode, Password: btoa(s.shortcode + s.passkey + ts), Timestamp: ts, CheckoutRequestID: checkoutId }) });
  return r.json();
}
async function sendPrompt(env, u, phone, amount, ref, source, origin) {
  const B = u.B, s = await unseal(env, B.settings);
  if (!s || !B.verified) return { error: u.role === 'staff' ? 'The owner has not finished setting up payments yet.' : 'Add and verify your Daraja details in Profile first.' };
  if (!(B.access_until > Date.now())) return { error: u.role === 'staff' ? 'The business subscription has ended. Ask the owner to renew.' : 'Your free month has ended. Renew for KES 100 in Profile, Subscription.' };
  const id = rid().slice(0, 12), cbkey = rid();
  let d;
  try { d = await stkPush(s, { phone, amount, ref, cbkey }, origin); } catch { return { error: 'Could not reach Safaricom. Try again.' }; }
  if (d.ResponseCode !== '0') return { error: d.errorMessage || d.ResponseDescription || 'Safaricom rejected the request.' };
  await env.DB.prepare('INSERT INTO tx(id,user_id,business_id,phone,amount,ref,status,message,checkout_id,cbkey,source,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, u.id, B.id, phone, amount, ref || '', 'pending', 'Waiting for the customer to enter their PIN', d.CheckoutRequestID, cbkey, source, Date.now()).run();
  return { id };
}
const REASONS = { 1: 'Insufficient M-Pesa balance', 1032: 'Customer cancelled the prompt', 1037: 'Prompt timed out. Customer did not respond', 2001: 'Customer entered the wrong PIN', 1001: 'Customer has another transaction in progress' };
async function finish(env, tx, code, desc, meta) {
  const m = {}; (meta?.Item || []).forEach(i => m[i.Name] = i.Value);
  const status = code === 0 ? 'success' : code === 1032 ? 'cancelled' : 'failed';
  const msg = code === 0 ? 'Payment received' : REASONS[code] || desc || 'Payment failed';
  const r = await env.DB.prepare('UPDATE tx SET status=?,receipt=?,message=?,done_at=? WHERE id=? AND status=?').bind(status, m.MpesaReceiptNumber || null, msg, Date.now(), tx.id, 'pending').run();
  if (!r.meta.changes) return;
  const bid = tx.business_id || tx.user_id;
  const sender = await env.DB.prepare('SELECT email,tg_chat FROM users WHERE id=?').bind(tx.user_id).first();
  const owner = bid === tx.user_id ? sender : await env.DB.prepare('SELECT tg_chat FROM users WHERE id=?').bind(bid).first();
  const biz = await daySum(env, 'business_id', bid, tx.created_at);
  const mine = bid === tx.user_id ? biz : await daySum(env, 'user_id', tx.user_id, tx.created_at);
  const icon = { success: '✅ SUCCESSFUL', cancelled: '🚫 CANCELLED', failed: '❌ FAILED' }[status];
  const body = `${icon}\nKES ${tx.amount}\nPhone: ${tx.phone}\n${msg}${m.MpesaReceiptNumber ? '\nReceipt: ' + m.MpesaReceiptNumber : ''}`;
  await tg(env, sender?.tg_chat, body + `\nYour total today: KES ${mine}`);
  if (bid !== tx.user_id) await tg(env, owner?.tg_chat, body + `\nSent by: ${sender?.email}\nBusiness total today: KES ${biz}`);
}

// ---------- Telegram bot ----------
async function webhook(env, req, secret, origin) {
  if (secret !== env.TG_SECRET) return new Response('no', { status: 403 });
  const msg = (await req.json().catch(() => ({}))).message;
  if (!msg?.text) return json({ ok: true });
  const chat = String(msg.chat.id), text = msg.text.trim();
  const start = /^\/start\s+(\w+)/.exec(text);
  if (start) {
    const u = await env.DB.prepare('SELECT id FROM users WHERE tg_code=?').bind(start[1]).first();
    if (!u) await tg(env, chat, 'That link has expired. Tap Connect Telegram in the app again.');
    else { await env.DB.prepare('UPDATE users SET tg_chat=?,tg_code=NULL WHERE id=?').bind(chat, u.id).run();
      await tg(env, chat, 'Connected ✅\nSend a phone number and amount to prompt a customer.\nExample: 0712345678 500\nPaybill with account: 0712345678 500 ACC123'); }
    return json({ ok: true });
  }
  let u = await env.DB.prepare('SELECT * FROM users WHERE tg_chat=?').bind(chat).first();
  u = u && await withB(env, u);
  if (!u) { await tg(env, chat, 'Open the app, go to Profile and tap Connect Telegram first.'); return json({ ok: true }); }
  const m = /^(\S+)\s+(\d+)(?:\s+(.+))?$/.exec(text), ph = m && normPhone(m[1]);
  if (!m || !ph || +m[2] < 1) { await tg(env, chat, 'Send: phone amount\nExample: 0712345678 500'); return json({ ok: true }); }
  const r = await sendPrompt(env, u, ph, +m[2], m[3], 'telegram', origin);
  await tg(env, chat, r.error ? '❌ ' + r.error : `📲 Prompt sent to ${ph} for KES ${m[2]}. I will message you the result.`);
  return json({ ok: true });
}

// ---------- router ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname, M = req.method;
    try {
      if (p.startsWith('/api/callback/')) {
        const b = (await req.json().catch(() => ({}))).Body?.stkCallback;
        const tx = b && await env.DB.prepare('SELECT * FROM tx WHERE cbkey=?').bind(p.split('/').pop()).first();
        if (tx) await finish(env, tx, b.ResultCode, b.ResultDesc, b.CallbackMetadata);
        return json({ ResultCode: 0, ResultDesc: 'OK' });
      }
      if (p === '/api/paystack/webhook' && M === 'POST') {
        const raw = await req.text();
        if (!env.PAYSTACK_SECRET || await hmac512(env.PAYSTACK_SECRET, raw) !== req.headers.get('x-paystack-signature')) return new Response('bad signature', { status: 401 });
        const ev = JSON.parse(raw), d = ev.data || {};
        if (String(d.reference || '').startsWith('sub_')) {
          if (ev.event === 'charge.success' && d.currency === 'KES' && d.amount === PRICE) await settleSub(env, d.reference);
          else if (ev.event === 'charge.failed') await env.DB.prepare("UPDATE billing SET status='failed' WHERE ref=? AND status='pending'").bind(d.reference).run();
        }
        return json({ ok: true });
      }
      if (p.startsWith('/telegram/webhook/')) return webhook(env, req, p.split('/').pop(), url.origin);

      if (M === 'POST' && ['/api/register', '/api/login', '/api/reset'].includes(p)) {
        const b = await req.json(), em = String(b.email || '').trim().toLowerCase(), password = b.password;
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return json({ error: 'Enter a valid email address.' }, 400);
        if (p !== '/api/login') {
          if (!password || password.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400);
          if (password !== b.confirm) return json({ error: 'Passwords do not match.' }, 400);
        }
        if (p === '/api/register') {
          const inv = normCode(b.invite);
          const owner = inv ? await env.DB.prepare("SELECT id FROM users WHERE invite_code=? AND (role IS NULL OR role='owner')").bind(inv).first() : null;
          if (inv && !owner) return json({ error: 'That staff invite code is not valid.' }, 400);
          const salt = b64(crypto.getRandomValues(new Uint8Array(16))), rc = mkCode(16);
          try {
            const r = await env.DB.prepare('INSERT INTO users(email,pass_hash,salt,created_at,role,business_id,recovery_hash,access_until) VALUES(?,?,?,?,?,?,?,?)')
              .bind(em, await hashPw(password, salt), salt, Date.now(), owner ? 'staff' : 'owner', owner ? owner.id : null, await sha(rc), owner ? null : Date.now() + PERIOD).run();
            const id = r.meta.last_row_id;
            if (!owner) await env.DB.prepare('UPDATE users SET business_id=? WHERE id=?').bind(id, id).run();
            return json({ ok: true, recovery: dash(rc) }, 200, await startSession(env, id));
          } catch { return json({ error: 'That email is already registered. Sign in instead.' }, 409); }
        }
        const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(em).first();
        if (p === '/api/reset') {
          if (!u || !u.recovery_hash || await sha(normCode(b.code)) !== u.recovery_hash) return json({ error: 'The email or recovery code is wrong.' }, 400);
          const salt = b64(crypto.getRandomValues(new Uint8Array(16))), rc = mkCode(16);
          await env.DB.prepare('UPDATE users SET pass_hash=?,salt=?,recovery_hash=? WHERE id=?').bind(await hashPw(password, salt), salt, await sha(rc), u.id).run();
          await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(u.id).run();
          return json({ ok: true, recovery: dash(rc) });
        }
        if (!u || await hashPw(password || '', u.salt) !== u.pass_hash) return json({ error: 'Wrong email or password.' }, 401);
        return json({ ok: true }, 200, await startSession(env, u.id));
      }

      const u = await authUser(req, env);
      if (p === '/api/logout') {
        await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(/sid=([a-f0-9]+)/.exec(req.headers.get('cookie') || '')?.[1] || '').run();
        return json({ ok: true }, 200, { 'set-cookie': 'sid=; Path=/; Max-Age=0' });
      }
      if (!u) return json({ error: 'Not signed in' }, 401);
      const B = u.B, staff = u.role === 'staff', s = await unseal(env, B.settings);
      const col = staff ? 'user_id' : 'business_id', cid = staff ? u.id : B.id;

      if (p === '/api/billing/pay' && M === 'POST') {
        if (staff) return json({ error: 'Only the owner can pay for the subscription.' }, 403);
        if (!env.PAYSTACK_SECRET) return json({ error: 'Subscription payments are not set up yet.' }, 503);
        const ph = normPhone((await req.json()).phone);
        if (!ph) return json({ error: 'Enter a valid Safaricom number, e.g. 0712345678.' }, 400);
        const ref = 'sub_' + rid().slice(0, 16);
        const r = await fetch('https://api.paystack.co/charge', { method: 'POST', headers: { Authorization: 'Bearer ' + env.PAYSTACK_SECRET, 'content-type': 'application/json' },
          body: JSON.stringify({ email: u.email, amount: PRICE, currency: 'KES', reference: ref, mobile_money: { phone: '+' + ph, provider: 'mpesa' }, metadata: { user_id: u.id } }) });
        const d = await r.json().catch(() => ({}));
        if (!d.status) return json({ error: d.message || 'Could not start the payment.' }, 400);
        await env.DB.prepare('INSERT INTO billing(ref,user_id,amount,status,created_at) VALUES(?,?,?,?,?)').bind(ref, u.id, PRICE, 'pending', Date.now()).run();
        return json({ ref });
      }
      if (p.startsWith('/api/billing/status/')) {
        const ref = p.split('/').pop();
        let row = await env.DB.prepare('SELECT status FROM billing WHERE ref=? AND user_id=?').bind(ref, u.id).first();
        if (!row) return json({ error: 'Not found' }, 404);
        if (row.status === 'pending' && env.PAYSTACK_SECRET) {
          try {
            const v = await (await fetch('https://api.paystack.co/transaction/verify/' + ref, { headers: { Authorization: 'Bearer ' + env.PAYSTACK_SECRET } })).json();
            if (v.data?.status === 'success' && v.data.amount === PRICE && v.data.currency === 'KES') await settleSub(env, ref);
            else if (['failed', 'abandoned', 'reversed'].includes(v.data?.status)) await env.DB.prepare("UPDATE billing SET status='failed' WHERE ref=? AND status='pending'").bind(ref).run();
          } catch {}
          row = await env.DB.prepare('SELECT status FROM billing WHERE ref=?').bind(ref).first();
        }
        return json({ status: row.status });
      }
      if (p === '/api/me') {
        const bill = await env.DB.prepare("SELECT COUNT(*) n FROM billing WHERE user_id=? AND status='success'").bind(B.id).first();
        const [a, z] = dayRange(Date.now());
        const t = await env.DB.prepare(`SELECT COALESCE(SUM(amount),0) total,COUNT(*) n FROM tx WHERE ${col}=? AND status='success' AND created_at>=? AND created_at<?`).bind(cid, a, z).first();
        return json({ email: u.email, role: staff ? 'staff' : 'owner', verified: !!B.verified, telegram: !!u.tg_chat, today: t,
          billing: { until: B.access_until || 0, active: (B.access_until || 0) > Date.now(), paid: bill.n > 0 },
          settings: s ? (staff ? { type: s.type, account: s.account } : { env: s.env, type: s.type, shortcode: s.shortcode, account: s.account, saved: true }) : null });
      }

      if (p === '/api/settings' && M === 'PUT') {
        if (staff) return json({ error: 'Only the owner can change these details.' }, 403);
        const b = await req.json();
        const n = { env: b.env === 'live' ? 'live' : 'sandbox', type: b.type === 'till' ? 'till' : 'paybill', shortcode: String(b.shortcode || '').trim(), account: String(b.account || '').trim(),
          key: (b.key || s?.key || '').trim(), secret: (b.secret || s?.secret || '').trim(), passkey: (b.passkey || s?.passkey || '').trim() };
        if (!n.shortcode || !n.account || !n.key || !n.secret || !n.passkey) return json({ error: 'Fill in every field.' }, 400);
        let ok = 1, err = '';
        try { await darajaToken(n); } catch (e) { ok = 0; err = e.message; }
        await env.DB.prepare('UPDATE users SET settings=?,verified=? WHERE id=?').bind(await seal(env, n), ok, u.id).run();
        return ok ? json({ ok: true, verified: true }) : json({ error: err + '. Details saved, but not verified.', verified: false }, 400);
      }

      if (p === '/api/pay' && M === 'POST') {
        const { phone, amount, ref } = await req.json();
        const ph = normPhone(phone), amt = Math.floor(+amount);
        if (!ph) return json({ error: 'Enter a valid Safaricom number, e.g. 0712345678.' }, 400);
        if (!(amt >= 1 && amt <= 250000)) return json({ error: 'Enter an amount between 1 and 250,000.' }, 400);
        const r = await sendPrompt(env, u, ph, amt, ref, 'app', url.origin);
        return r.error ? json(r, 400) : json(r);
      }

      if (p.startsWith('/api/status/')) {
        let tx = await env.DB.prepare(`SELECT * FROM tx WHERE id=? AND ${col}=?`).bind(p.split('/').pop(), cid).first();
        if (!tx) return json({ error: 'Not found' }, 404);
        if (tx.status === 'pending' && Date.now() - tx.created_at > 25000 && s) {
          try { const d = await stkQuery(s, tx.checkout_id);
            if (d.ResultCode !== undefined) { await finish(env, tx, +d.ResultCode, d.ResultDesc, null); tx = await env.DB.prepare('SELECT * FROM tx WHERE id=?').bind(tx.id).first(); } } catch {}
        }
        return json({ ...tx, day_total: await daySum(env, col, cid, tx.created_at) });
      }

      if (p === '/api/history') {
        const { results } = await env.DB.prepare(`SELECT t.id,t.phone,t.amount,t.ref,t.status,t.receipt,t.message,t.created_at,t.done_at,x.email AS by FROM tx t LEFT JOIN users x ON x.id=t.user_id WHERE t.${col}=? ORDER BY t.created_at DESC LIMIT 2000`).bind(cid).all();
        const days = {};
        for (const t of results.reverse()) {
          const d = new Date(t.created_at + 108e5).toISOString().slice(0, 10);
          (days[d] ||= { date: d, total: 0, count: 0, ok: 0, cancelled: 0, failed: 0, tx: [] }).tx.push(t);
        }
        const out = Object.values(days).sort((a, b) => b.date.localeCompare(a.date));
        for (const g of out) {
          g.tx.sort((a, b) => (a.done_at || a.created_at) - (b.done_at || b.created_at));
          let run = 0;
          for (const t of g.tx) { g.count++; if (t.status === 'success') { run += t.amount; g.ok++; } else if (t.status === 'cancelled') g.cancelled++; else if (t.status === 'failed') g.failed++; t.running = run; }
          g.total = run; g.tx.reverse();
        }
        return json({ days: out });
      }

      if (p.startsWith('/api/staff')) {
        if (staff) return json({ error: 'Owner only' }, 403);
        if (p === '/api/staff') {
          const { results } = await env.DB.prepare("SELECT id,email FROM users WHERE business_id=? AND role='staff' ORDER BY email").bind(u.id).all();
          return json({ invite: dash(u.invite_code), staff: results });
        }
        if (p === '/api/staff/invite') {
          const c = mkCode(8); await env.DB.prepare('UPDATE users SET invite_code=? WHERE id=?').bind(c, u.id).run(); return json({ invite: dash(c) });
        }
        const { id } = await req.json();
        const st = await env.DB.prepare("SELECT id FROM users WHERE id=? AND business_id=? AND role='staff'").bind(id, u.id).first();
        if (!st) return json({ error: 'Staff member not found' }, 404);
        if (p === '/api/staff/remove') {
          await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run();
          await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run(); return json({ ok: true });
        }
        if (p === '/api/staff/reset') {
          const temp = mkCode(10), salt = b64(crypto.getRandomValues(new Uint8Array(16)));
          await env.DB.prepare('UPDATE users SET pass_hash=?,salt=? WHERE id=?').bind(await hashPw(temp, salt), salt, id).run();
          await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run(); return json({ temp });
        }
      }

      if (p === '/api/telegram/link' && M === 'POST') {
        const code = rid().slice(0, 16); await env.DB.prepare('UPDATE users SET tg_code=? WHERE id=?').bind(code, u.id).run();
        return json({ url: `https://t.me/${env.BOT_USERNAME}?start=${code}` });
      }
      if (p === '/api/telegram/unlink' && M === 'POST') { await env.DB.prepare('UPDATE users SET tg_chat=NULL WHERE id=?').bind(u.id).run(); return json({ ok: true }); }
      return json({ error: 'Not found' }, 404);
    } catch (e) { return json({ error: 'Server error' }, 500); }
  }
};
