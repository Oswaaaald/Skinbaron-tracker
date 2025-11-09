import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker deployments
  output: 'standalone',
  
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
