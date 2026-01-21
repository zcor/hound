import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Output standalone build for Docker/Railway
  output: 'standalone',
  
  // Environment variables available at runtime
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },
  
  // Image optimization (if using external images)
  images: {
    unoptimized: true, // For simpler deployment
  },
};

export default nextConfig;
