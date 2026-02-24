import type { NextConfig } from "next";
import { withSentryConfig } from "@sentry/nextjs";

// Derive API hostname for CSP connect-src
const apiUrl = process.env['NEXT_PUBLIC_API_URL'] ?? '';
const apiHost = (() => {
  try { return new URL(apiUrl).origin; } catch { return ''; }
})();

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployments
  output: 'standalone',
  
  // Compiler optimizations
  compiler: {
    // Remove console.log in production
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn'],
    } : false,
  },
  
  // Optimize for modern browsers (ES2020+)
  // Note: Next.js 16 standalone mode includes some polyfills by default
  // This is not fully controllable without custom webpack config
  experimental: {
    optimizePackageImports: ['lucide-react'],
  },

  // Security headers
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Content-Security-Policy',
          value: [
            "default-src 'self'",
            // Next.js injects inline scripts for hydration/bootstrap — 'unsafe-inline' is
            // required until nonce-based CSP is implemented via middleware.
            // 'unsafe-eval' is needed because some bundled libraries (e.g. Sentry,
            // compiled WebAssembly polyfills) use eval() or new Function() at runtime.
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            `connect-src 'self' ${apiHost} https://www.gravatar.com https://*.sentry.io`,
            `img-src 'self' data: blob: https://www.gravatar.com https://steamcommunity-a.akamaihd.net ${apiHost}`,
            "font-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
          ].join('; '),
        },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
      ],
    },
  ],
  
  // Image optimization for external sources
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'www.gravatar.com',
        pathname: '/avatar/**',
      },
      {
        protocol: 'https',
        hostname: 'steamcommunity-a.akamaihd.net',
        pathname: '/economy/image/**',
      },
      // Allow avatar images from the API backend (dynamic hostname from env)
      ...(process.env['NEXT_PUBLIC_API_URL']
        ? (() => {
            try {
              const url = new URL(process.env['NEXT_PUBLIC_API_URL']);
              return [{
                protocol: url.protocol.replace(':', '') as 'http' | 'https',
                hostname: url.hostname,
                pathname: '/api/avatars/**',
              }];
            } catch { return []; }
          })()
        : []),
    ],
    formats: ['image/avif', 'image/webp'],
  },
};

export default withSentryConfig(nextConfig, {
  // Suppress source map upload warnings when no auth token is set
  silent: !process.env['SENTRY_AUTH_TOKEN'],

  // Don't widen the scope of uploaded source maps
  widenClientFileUpload: false,

  // Tunnel Sentry events through a Next.js route to avoid ad-blockers
  tunnelRoute: '/monitoring',
});
