import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Next.js middleware: path normalization + server-side auth guard.
 *
 * Unauthenticated visitors are redirected to /login before the page shell
 * is ever rendered, preventing HTML/JS leakage from protected routes.
 *
 * We check for the existence of the access cookie (sb_access) as a
 * lightweight heuristic. The actual auth verification still happens on
 * the API side — this just prevents the bare page shell from rendering
 * for users without any session cookie.
 */

const AUTH_COOKIE = 'sb_access';

/** Routes that do NOT require authentication */
const PUBLIC_PATHS = ['/login', '/register', '/privacy', '/tos'];

function isPublicPath(pathname: string): boolean {
  if (pathname === '/') return true;
  return PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(`${p}/`));
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

  return NextResponse.next();
}

export const config = {
  matcher: [
    // Match all paths except static files, Next.js internals, and health check
    '/((?!_next/static|_next/image|favicon.ico|monitoring|health|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
