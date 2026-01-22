import type { NextConfig } from "next";

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
  // This reduces bundle size by removing unnecessary polyfills
  experimental: {
    optimizePackageImports: ['lucide-react', '@radix-ui/react-icons'],
    // Inline critical CSS
    optimizeCss: true,
  },
  
  // Image optimization currently not needed
  // Images are used only in Discord notifications (backend), not in Next.js frontend
  // If you add skin images to the web interface later, uncomment and configure domains
  // images: {
  //   remotePatterns: [
  //     // Add Steam CDN domains here when needed
  //   ],
  // },
};

export default nextConfig;
