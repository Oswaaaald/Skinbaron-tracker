import type { NextConfig } from "next";
import { withSentryConfig } from "@sentry/nextjs";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployments
  output: 'standalone',

  // Disable browser source maps in production (security + avoids broken .map references)
  productionBrowserSourceMaps: false,
  
  // Compiler optimizations
  compiler: {
    // Remove console.log in production
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn'],
    } : false,
  },
  
  // Optimize for modern browsers — browserslist in package.json targets chrome/edge/firefox 111+, safari 16.4+
  experimental: {
    optimizePackageImports: ['lucide-react'],
  },

  // Security headers (CSP is set dynamically in proxy.ts with per-request nonce)
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
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

  // Delete source maps after upload to Sentry (don't ship to browser)
  sourcemaps: {
    deleteSourcemapsAfterUpload: true,
  },

  // Tunnel Sentry events through a Next.js route to avoid ad-blockers
  tunnelRoute: '/monitoring',
});
