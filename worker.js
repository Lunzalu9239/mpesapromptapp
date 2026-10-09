const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rid = () => [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });

// ---------- crypto ----------
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

// ---------- auth ----------
async function authUser(req, env) {
  const m = /sid=([a-f0-9]+)/.exec(req.headers.get('cookie') || '');
  if (!m) return null;
  return env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').bind(m[1], Date.now()).first();
}
async function startSession(env, uid) {
  const t = rid() + rid();
  await env.DB.prepare('INSERT INTO sessions VALUES(?,?,?)').bind(t, uid, Date.now() + 365 * 864e5).run();
  return { 'set-cookie': `sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000` };
}

// ---------- helpers ----------
function normPhone(p) {
  p = String(p || '').replace(/\D/g, '');
  if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1);
  else if (/^[17]\d{8}$/.test(p)) p = '254' + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
}
async function tg(env, chat, text) {
  if (!env.TELEGRAM_TOKEN || !chat) return;
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: chat, text })
  }).catch(() => {});
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
    body: JSON.stringify({
      BusinessShortCode: s.shortcode, Password: btoa(s.shortcode + s.passkey + ts), Timestamp: ts,
      TransactionType: till ? 'CustomerBuyGoodsOnline' : 'CustomerPayBillOnline',
      Amount: tx.amount, PartyA: tx.phone, PartyB: till ? s.account : s.shortcode, PhoneNumber: tx.phone,
      CallBackURL: `${origin}/api/callback/${tx.cbkey}`,
      AccountReference: String(tx.ref || (till ? 'Payment' : s.account)).slice(0, 12), TransactionDesc: 'Payment'
    })
  });
  return r.json();
}
async function stkQuery(s, checkoutId) {
  const t = await darajaToken(s), ts = stamp();
  const r = await fetch(base(s) + '/mpesa/stkpushquery/v1/query', {
    method: 'POST', headers: { Authorization: 'Bearer ' + t, 'content-type': 'application/json' },
    body: JSON.stringify({ BusinessShortCode: s.shortcode, Password: btoa(s.shortcode + s.passkey + ts), Timestamp: ts, CheckoutRequestID: checkoutId })
  });
  return r.json();
}

async function sendPrompt(env, u, phone, amount, ref, source, origin) {
  const s = await unseal(env, u.settings);
  if (!s || !u.verified) return { error: 'Add and verify your Daraja details in Profile first.' };
  const id = rid().slice(0, 12), cbkey = rid();
  let d;
  try { d = await stkPush(s, { phone, amount, ref, cbkey }, origin); } catch { return { error: 'Could not reach Safaricom. Try again.' }; }
  if (d.ResponseCode !== '0') return { error: d.errorMessage || d.ResponseDescription || 'Safaricom rejected the request.' };
  await env.DB.prepare('INSERT INTO tx(id,user_id,phone,amount,ref,status,message,checkout_id,cbkey,source,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id, u.id, phone, amount, ref || '', 'pending', 'Waiting for the customer to enter their PIN', d.CheckoutRequestID, cbkey, source, Date.now()).run();
  return { id };
}

const REASONS = { 1: 'Insufficient M-Pesa balance', 1032: 'Customer cancelled the prompt', 1037: 'Prompt timed out. Customer did not respond', 2001: 'Customer entered the wrong PIN', 1001: 'Customer has another transaction in progress' };
async function finish(env, tx, code, desc, meta) {
  const m = {}; (meta?.Item || []).forEach(i => m[i.Name] = i.Value);
  const status = code === 0 ? 'success' : code === 1032 ? 'cancelled' : 'failed';
  const msg = code === 0 ? 'Payment received' : REASONS[code] || desc || 'Payment failed';
  const r = await env.DB.prepare('UPDATE tx SET status=?,receipt=?,message=?,done_at=? WHERE id=? AND status=?')
    .bind(status, m.MpesaReceiptNumber || null, msg, Date.now(), tx.id, 'pending').run();
  if (!r.meta.changes) return;
  const u = await env.DB.prepare('SELECT tg_chat FROM users WHERE id=?').bind(tx.user_id).first();
  const icon = { success: '✅ SUCCESSFUL', cancelled: '🚫 CANCELLED', failed: '❌ FAILED' }[status];
  await tg(env, u?.tg_chat, `${icon}\nKES ${tx.amount}\nPhone: ${tx.phone}\n${msg}${m.MpesaReceiptNumber ? '\nReceipt: ' + m.MpesaReceiptNumber : ''}`);
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
    else {
      await env.DB.prepare('UPDATE users SET tg_chat=?,tg_code=NULL WHERE id=?').bind(chat, u.id).run();
      await tg(env, chat, 'Connected ✅\nSend a phone number and amount to prompt a customer.\nExample: 0712345678 500\nPaybill with account: 0712345678 500 ACC123');
    }
    return json({ ok: true });
  }
  const u = await env.DB.prepare('SELECT * FROM users WHERE tg_chat=?').bind(chat).first();
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
      if (p.startsWith('/telegram/webhook/')) return webhook(env, req, p.split('/').pop(), url.origin);

      if (M === 'POST' && (p === '/api/register' || p === '/api/login')) {
        const { email, password, confirm } = await req.json();
        const em = String(email || '').trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return json({ error: 'Enter a valid email address.' }, 400);
        if (p === '/api/register') {
          if (!password || password.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400);
          if (password !== confirm) return json({ error: 'Passwords do not match.' }, 400);
          const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
          try {
            const r = await env.DB.prepare('INSERT INTO users(email,pass_hash,salt,created_at) VALUES(?,?,?,?)').bind(em, await hashPw(password, salt), salt, Date.now()).run();
            return json({ ok: true }, 200, await startSession(env, r.meta.last_row_id));
          } catch { return json({ error: 'That email is already registered. Sign in instead.' }, 409); }
        }
        const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(em).first();
        if (!u || await hashPw(password || '', u.salt) !== u.pass_hash) return json({ error: 'Wrong email or password.' }, 401);
        return json({ ok: true }, 200, await startSession(env, u.id));
      }

      const u = await authUser(req, env);
      if (p === '/api/logout') {
        await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(/sid=([a-f0-9]+)/.exec(req.headers.get('cookie') || '')?.[1] || '').run();
        return json({ ok: true }, 200, { 'set-cookie': 'sid=; Path=/; Max-Age=0' });
      }
      if (!u) return json({ error: 'Not signed in' }, 401);
      const s = await unseal(env, u.settings);

      if (p === '/api/me') return json({ email: u.email, verified: !!u.verified, telegram: !!u.tg_chat,
        settings: s ? { env: s.env, type: s.type, shortcode: s.shortcode, account: s.account, saved: true } : null });

      if (p === '/api/settings' && M === 'PUT') {
        const b = await req.json();
        const n = { env: b.env === 'live' ? 'live' : 'sandbox', type: b.type === 'till' ? 'till' : 'paybill',
          shortcode: String(b.shortcode || '').trim(), account: String(b.account || '').trim(),
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
        let tx = await env.DB.prepare('SELECT * FROM tx WHERE id=? AND user_id=?').bind(p.split('/').pop(), u.id).first();
        if (!tx) return json({ error: 'Not found' }, 404);
        if (tx.status === 'pending' && Date.now() - tx.created_at > 25000 && s) {
          try {
            const d = await stkQuery(s, tx.checkout_id);
            if (d.ResultCode !== undefined) {
              await finish(env, tx, +d.ResultCode, d.ResultDesc, null);
              tx = await env.DB.prepare('SELECT * FROM tx WHERE id=?').bind(tx.id).first();
            }
          } catch {}
        }
        return json(tx);
      }

      if (p === '/api/history') {
        const { results } = await env.DB.prepare('SELECT id,phone,amount,ref,status,receipt,message,created_at FROM tx WHERE user_id=? ORDER BY created_at DESC LIMIT 1000').bind(u.id).all();
        const days = {};
        for (const t of results) {
          const d = new Date(t.created_at + 3 * 36e5).toISOString().slice(0, 10); // Nairobi day
          const g = days[d] ||= { date: d, total: 0, count: 0, tx: [] };
          g.tx.push(t); g.count++;
          if (t.status === 'success') g.total += t.amount;
        }
        return json({ days: Object.values(days) });
      }

      if (p === '/api/telegram/link' && M === 'POST') {
        const code = rid().slice(0, 16);
        await env.DB.prepare('UPDATE users SET tg_code=? WHERE id=?').bind(code, u.id).run();
        return json({ url: `https://t.me/${env.BOT_USERNAME}?start=${code}` });
      }
      if (p === '/api/telegram/unlink' && M === 'POST') {
        await env.DB.prepare('UPDATE users SET tg_chat=NULL WHERE id=?').bind(u.id).run();
        return json({ ok: true });
      }
      return json({ error: 'Not found' }, 404);
    } catch (e) { return json({ error: 'Server error' }, 500); }
  }
};
