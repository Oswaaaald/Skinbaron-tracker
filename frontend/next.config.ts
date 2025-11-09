import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployments
  output: 'standalone',
  
  // Image optimization - currently unused but ready for future skin thumbnails
  // images: {
  //   remotePatterns: [
  //     {
  //       protocol: 'https',
  //       hostname: 'skinbaron.de',
  //       port: '',
  //       pathname: '/**',
  //     },
  //   ],
  // },
};

export default nextConfig;
