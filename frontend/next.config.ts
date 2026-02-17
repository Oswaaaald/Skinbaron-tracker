import type { NextConfig } from "next";
import { withSentryConfig } from "@sentry/nextjs";

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

  // Automatically tree-shake Sentry logger statements
  disableLogger: true,

  // Don't widen the scope of uploaded source maps
  widenClientFileUpload: false,

  // Tunnel Sentry events through a Next.js route to avoid ad-blockers
  tunnelRoute: '/monitoring',

  // Disable automatic instrumentation for page loads (we handle it ourselves)
  autoInstrumentServerFunctions: false,
  autoInstrumentMiddleware: false,
  autoInstrumentAppDirectory: true,
});
