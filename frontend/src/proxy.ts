import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Next.js proxy (middleware): path normalization, server-side auth guard,
 * and per-request CSP nonce generation.
 *
 * Unauthenticated visitors are redirected to /login before the page shell
 * is ever rendered, preventing HTML/JS leakage from protected routes.
 *
 * We check for the existence of the access cookie (sb_access) as a
 * lightweight heuristic. The actual auth verification still happens on
 * the API side — this just prevents the bare page shell from rendering
 * for users without any session cookie.
 *
 * A unique nonce is generated per request and injected into the CSP header.
 * Next.js automatically applies it to its own inline <script> tags.  The
 * nonce is also forwarded via the `x-nonce` request header so that server
 * components can read it (e.g. to pass to next-themes ThemeProvider).
 */

const AUTH_COOKIE = 'sb_access';

/** Routes that do NOT require authentication */
const PUBLIC_PATHS = ['/login', '/register', '/privacy', '/tos'];

function isPublicPath(pathname: string): boolean {
  if (pathname === '/') return true;
  return PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(`${p}/`));
}

/** Derive API origin once at startup for CSP connect-src / img-src */
const apiHost = (() => {
  try { return new URL(process.env['NEXT_PUBLIC_API_URL'] ?? '').origin; } catch { return ''; }
})();

/** Build a Content-Security-Policy header value with a per-request nonce */
function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    // 'nonce-…'   — only scripts bearing this nonce may execute (inline)
    // 'strict-dynamic' — scripts loaded *by* a nonced script are also trusted
    `script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`,
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${apiHost} https://www.gravatar.com https://*.sentry.io`,
    `img-src 'self' data: blob: https://www.gravatar.com https://steamcommunity-a.akamaihd.net ${apiHost}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;

  // 1. Normalize double-slash paths
  const normalized = path.replace(/\/+/g, '/');
  if (normalized !== path) {
    const url = request.nextUrl.clone();
    url.pathname = normalized;
    return NextResponse.redirect(url);
  }

  // 2. Server-side auth guard for protected routes
  const isPublic = isPublicPath(path);
  const hasSession = request.cookies.has(AUTH_COOKIE);

  if (!isPublic && !hasSession) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';
    return NextResponse.redirect(loginUrl);
  }

  // Note: we intentionally do NOT redirect authenticated users away from
  // /login or /register here. The proxy only checks cookie existence, not
  // validity — expired tokens would cause a redirect loop (proxy sends
  // the user to /, page sees invalid token → shows landing → user clicks
  // Sign In → proxy sends back to / → loop). The client-side auth context
  // handles the authenticated-user redirect once it has validated the token.

  // 3. Generate per-request CSP nonce
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = buildCsp(nonce);

  // Forward nonce + CSP to the server-side renderer via request headers
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // Set CSP on the response so the browser enforces it
  response.headers.set('Content-Security-Policy', csp);

  return response;
}

export const config = {
  matcher: [
    // Match all paths except static files, Next.js internals, and health check
    '/((?!_next/static|_next/image|favicon.ico|monitoring|health|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
