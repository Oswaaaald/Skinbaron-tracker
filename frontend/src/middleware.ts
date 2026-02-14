import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Next.js middleware to normalize double-slash paths.
 * Replaces the client-side dangerouslySetInnerHTML script in layout.tsx.
 */
export function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const normalized = path.replace(/\/+/g, '/');

  if (normalized !== path) {
    const url = request.nextUrl.clone();
    url.pathname = normalized;
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    // Match all paths except static files and Next.js internals
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
