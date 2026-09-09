/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable static export for Capacitor (iOS/Android) builds
  // Comment this out if you use Next.js API routes on the server
  // output: 'export',

  reactStrictMode: true,

  // Allow images from these external domains
  images: {
    domains: [
      'www.allsee-tech.com',
      'fonts.googleapis.com',
      'fonts.gstatic.com',
    ],
  },

  // Security & PWA headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options',    value: 'nosniff' },
          { key: 'X-Frame-Options',            value: 'DENY' },
          { key: 'X-XSS-Protection',           value: '1; mode=block' },
          { key: 'Referrer-Policy',            value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy',         value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
      {
        // Cache static assets aggressively
        source: '/icons/(.*)',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=31536000, immutable' }],
      },
      {
        source: '/manifest.json',
        headers: [{ key: 'Cache-Control', value: 'public, max-age=86400' }],
      },
      {
        // Service worker must not be cached so updates apply immediately
        source: '/service-worker.js',
        headers: [{ key: 'Cache-Control', value: 'no-cache, no-store, must-revalidate' }],
      },
    ];
  },
};

module.exports = nextConfig;
