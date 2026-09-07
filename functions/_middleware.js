/**
 * Cloudflare Pages middleware — the actual gate.
 *
 * Every request for the app passes through here first. Without a valid Supabase
 * session token the HTML is never sent, so the application cannot be read by
 * anyone who merely knows the URL.
 *
 * Supabase signs session tokens one of two ways, and this verifies both:
 *   ES256 / RS256 — the current default. Tokens are signed with a private key and
 *                   verified against the project's public JWKS. Nothing secret is
 *                   needed on this side, so no configuration is required.
 *   HS256         — the legacy shared-secret scheme. Needs SUPABASE_JWT_SECRET.
 * Supporting both means a project can rotate between them without locking anyone out.
 *
 * Environment variables (Pages → Settings → Variables and Secrets):
 *   SUPABASE_URL         — optional, defaults to the project baked in below
 *   SUPABASE_JWT_SECRET  — only needed for legacy HS256 projects (encrypt it)
 *   ALLOWED_EMAILS       — optional comma-separated allow-list, e.g. "a@x.com,b@x.com"
 *   ALLOWED_DOMAIN       — optional, e.g. "fovera.com"
 */

const SUPABASE_URL_DEFAULT = 'https://kgqcjleyxlsluyvljhke.supabase.co';

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

  const result = await verifyJWT(token, env);

  if (!result.ok && result.reason === 'config') {
    return new Response(
      'Server not configured: this Supabase project signs tokens with HS256, so ' +
      'SUPABASE_JWT_SECRET must be set under Pages → Settings → Variables and Secrets, ' +
      'then redeploy.',
      { status: 500, headers: { 'Content-Type': 'text/plain' } });
  }
  if (!result.ok) return redirectToLogin(url, 'expired');

  const email = String(result.claims.email || '').toLowerCase();
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

function b64urlToBytes(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const baseUrl = env => String(env.SUPABASE_URL || SUPABASE_URL_DEFAULT).replace(/\/+$/, '');

/* The public keys change rarely, so hold them in the isolate and let Cloudflare's
   cache absorb the rest. On a fetch failure we keep serving the last good copy —
   a blip at Supabase should not sign everyone out. */
let _jwks = null, _jwksAt = 0;
const JWKS_TTL_MS = 10 * 60 * 1000;

async function getJwks(env, force = false) {
  const now = Date.now();
  if (!force && _jwks && now - _jwksAt < JWKS_TTL_MS) return _jwks;
  try {
    const res = await fetch(baseUrl(env) + '/auth/v1/.well-known/jwks.json',
                            { cf: { cacheTtl: 600, cacheEverything: true } });
    if (!res.ok) return _jwks;
    const body = await res.json();
    if (body && Array.isArray(body.keys) && body.keys.length) {
      _jwks = body.keys;
      _jwksAt = now;
    }
  } catch (_) { /* keep the stale copy */ }
  return _jwks;
}

/* Import a JWKS entry, stripping the fields that make importKey fussy. */
async function importJwk(jwk, alg) {
  const algo = alg === 'ES256'
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  const clean = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, n: jwk.n, e: jwk.e, ext: true };
  for (const k of Object.keys(clean)) if (clean[k] === undefined) delete clean[k];
  return crypto.subtle.importKey('jwk', clean, algo, false, ['verify']);
}

/**
 * Verify a Supabase access token.
 * Returns { ok: true, claims } or { ok: false, reason: 'invalid' | 'config' }.
 */
export async function verifyJWT(token, env) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return { ok: false, reason: 'invalid' };
  const [h, p, s] = parts;

  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
    claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
  } catch { return { ok: false, reason: 'invalid' }; }

  const signed = new TextEncoder().encode(`${h}.${p}`);
  const sig = b64urlToBytes(s);
  let ok = false;

  if (header.alg === 'HS256') {
    const secret = env.SUPABASE_JWT_SECRET;
    if (!secret) return { ok: false, reason: 'config' };
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    ok = await crypto.subtle.verify('HMAC', key, sig, signed);

  } else if (header.alg === 'ES256' || header.alg === 'RS256') {
    const verifyAlgo = header.alg === 'ES256'
      ? { name: 'ECDSA', hash: 'SHA-256' }
      : { name: 'RSASSA-PKCS1-v1_5' };
    // A rotated signing key means our cached JWKS is stale, so on a miss refetch once.
    for (const force of [false, true]) {
      const keys = await getJwks(env, force);
      if (!keys) break;
      const jwk = keys.find(k => k.kid === header.kid);
      if (!jwk) { if (!force) continue; else break; }
      try {
        const key = await importJwk(jwk, header.alg);
        ok = await crypto.subtle.verify(verifyAlgo, key, sig, signed);
      } catch (_) { ok = false; }
      break;
    }

  } else {
    return { ok: false, reason: 'invalid' };   // refuse "none" and algorithm swaps
  }

  if (!ok) return { ok: false, reason: 'invalid' };

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && claims.exp <= now) return { ok: false, reason: 'invalid' };
  if (typeof claims.nbf === 'number' && claims.nbf > now + 60) return { ok: false, reason: 'invalid' };
  if (claims.role && claims.role === 'anon') return { ok: false, reason: 'invalid' };  // anon key is not a user session
  // the token must come from the project whose keys we just verified against
  if (claims.iss && claims.iss !== baseUrl(env) + '/auth/v1') return { ok: false, reason: 'invalid' };

  return { ok: true, claims };
}
