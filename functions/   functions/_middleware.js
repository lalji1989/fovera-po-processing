/**
 * Cloudflare Pages middleware — the actual gate.
 *
 * Every request for the app passes through here first. Without a valid Supabase
 * session token the HTML is never sent, so the application cannot be read by
 * anyone who merely knows the URL.
 *
 * Environment variables (Pages → Settings → Variables and Secrets):
 *   SUPABASE_JWT_SECRET  — Supabase → Project Settings → API → JWT Secret  (encrypt this)
 *   ALLOWED_EMAILS       — optional comma-separated allow-list, e.g. "a@x.com,b@x.com"
 *   ALLOWED_DOMAIN       — optional, e.g. "fovera.com"
 */

const PUBLIC_PATHS = ['/login', '/login.html', '/auth-callback', '/auth-callback.html', '/favicon.ico'];

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (PUBLIC_PATHS.some(p => url.pathname === p || url.pathname.startsWith(p + '/'))) {
    return next();
  }

  // the login page hands us the access token in a cookie
  const token = readCookie(request.headers.get('Cookie') || '', 'sb-access-token');
  if (!token) return redirectToLogin(url);

  const secret = env.SUPABASE_JWT_SECRET;
  if (!secret) {
    return new Response(
      'Server not configured: SUPABASE_JWT_SECRET is missing. Add it under ' +
      'Pages → Settings → Variables and Secrets, then redeploy.',
      { status: 500, headers: { 'Content-Type': 'text/plain' } });
  }

  const claims = await verifyJWT(token, secret);
  if (!claims) return redirectToLogin(url, 'expired');

  const email = String(claims.email || '').toLowerCase();
  if (!isAllowed(email, env)) {
    return new Response(
      `${email || 'That account'} is not permitted to use this application.`,
      { status: 403, headers: { 'Content-Type': 'text/plain' } });
  }

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'no-store');   // never cache an authenticated page
  return out;
}

function isAllowed(email, env) {
  if (!email) return false;
  const list = (env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const domain = (env.ALLOWED_DOMAIN || '').trim().toLowerCase().replace(/^@/, '');
  if (!list.length && !domain) return true;            // Supabase invite-only is the gate
  if (list.includes(email)) return true;
  if (domain && email.endsWith('@' + domain)) return true;
  return false;
}

function redirectToLogin(url, reason) {
  const to = new URL('/login.html', url.origin);
  to.searchParams.set('next', url.pathname + url.search);
  if (reason) to.searchParams.set('reason', reason);
  return Response.redirect(to.toString(), 302);
}

function readCookie(header, name) {
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

/* ---- HS256 verification using Web Crypto, available in the Workers runtime ---- */
function b64urlToBytes(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function verifyJWT(token, secret) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
    claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
  } catch { return null; }

  if (header.alg !== 'HS256') return null;          // refuse "none" and algorithm swaps

  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

  const ok = await crypto.subtle.verify(
    'HMAC', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) return null;

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && claims.exp <= now) return null;
  if (typeof claims.nbf === 'number' && claims.nbf > now + 60) return null;
  if (claims.role && claims.role === 'anon') return null;   // anon key is not a user session

  return claims;
}
