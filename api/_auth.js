// Funções de autenticação compartilhadas (Web Crypto, roda no Edge).
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
export const COOKIE = 'lcl_sessao';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 dias

export function users() {
  // Uma pessoa por linha (ou separadas por ponto e vírgula): email=pbkdf2$...
  const o = {};
  for (const ln of String(process.env.AUTH_USERS || '').split(/[\n;]+/)) {
    const i = ln.indexOf('=');
    if (i > 0) o[ln.slice(0, i).trim().toLowerCase()] = ln.slice(i + 1).trim();
  }
  return o;
}
export function admins() { return (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean); }

async function pbkdf2(pass, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };

export async function checkPassword(email, pass) {
  const rec = users()[String(email || '').trim().toLowerCase()];
  if (!rec || !pass) { await pbkdf2('x', enc.encode('x'), 100000); return false; }
  const [alg, iter, salt, hash] = rec.split('$');
  if (alg !== 'pbkdf2') return false;
  return same(await pbkdf2(pass, unb64u(salt), +iter), unb64u(hash));
}

async function hmacKey() {
  const s = process.env.AUTH_SECRET;
  if (!s) throw new Error('AUTH_SECRET ausente');
  return crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
export async function makeSession(email) {
  const p = b64u(enc.encode(JSON.stringify({ e: email.toLowerCase(), x: Math.floor(Date.now() / 1000) + MAX_AGE })));
  const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(), enc.encode(p)));
  return `${COOKIE}=${p}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`;
}
export const clearSession = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

export async function sessionEmail(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [p, sig] = m[1].split('.');
  if (!p || !sig) return null;
  try {
    if (!(await crypto.subtle.verify('HMAC', await hmacKey(), unb64u(sig), enc.encode(p)))) return null;
    const o = JSON.parse(new TextDecoder().decode(unb64u(p)));
    if (!o.e || o.x < Date.now() / 1000) return null;
    return users()[o.e] ? o.e : null; // e-mail removido perde o acesso na hora
  } catch (e) { return null; }
}
