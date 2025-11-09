import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployments
  output: 'standalone',
  
  // Image optimization - ready for skin thumbnails
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'skinbaron.de',
        port: '',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: 'steamcommunity-a.akamaihd.net',
        port: '',
        pathname: '/economy/image/**',
      },
    ],
  },
};

export default nextConfig;
