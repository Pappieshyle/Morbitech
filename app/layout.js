// app/layout.js  — Next.js App Router root layout
// This file wires up the PWA manifest, meta tags, and service worker.

import Script from 'next/script';

export const metadata = {
  metadataBase: new URL('https://morbitech.vercel.app'),
  title: {
    default: 'Morbitech — Digital Signage West Africa',
    template: '%s | Morbitech',
  },
  description:
    'West Africa\'s professional digital signage distributor. LED displays, video walls, touch kiosks & more. Transparent pricing. Pay with Pi, USD, or NGN. Serving Nigeria, Ghana, Cameroon, Côte d\'Ivoire and beyond.',
  keywords: [
    'digital signage Nigeria', 'LED display Lagos', 'video wall West Africa',
    'touch screen kiosk', 'digital poster', 'commercial display',
    'Pi Network app', 'morbitech',
  ],
  authors: [{ name: 'Morbitech', url: 'https://morbitech.com' }],
  creator: 'Morbitech',
  publisher: 'Morbitech',
  openGraph: {
    type: 'website',
    locale: 'en_NG',
    url: 'https://morbitech.vercel.app',
    siteName: 'Morbitech',
    title: 'Morbitech — Digital Signage West Africa',
    description: 'Professional digital signage solutions for West Africa. Transparent pricing, Pi payments accepted.',
    images: [{ url: '/og-image.png', width: 1200, height: 630, alt: 'Morbitech Digital Signage' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Morbitech — Digital Signage West Africa',
    description: 'LED displays, video walls, kiosks & more. Transparent pricing. Pi payments accepted.',
    creator: '@Pappie_shyle',
    images: ['/og-image.png'],
  },
  robots: { index: true, follow: true },
  manifest: '/manifest.json',
  icons: {
    icon:    [{ url: '/icons/icon-96.png' }, { url: '/icons/icon-192.png' }],
    apple:   [{ url: '/icons/icon-192.png' }],
    shortcut:[{ url: '/icons/icon-96.png'  }],
  },
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Morbitech',
  },
  
};
export const viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  themeColor: '#3b82f6',
};
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        {/* Pi Network SDK — loads before app */}
        <Script
          src="https://sdk.minepi.com/pi-sdk.js"
          strategy="beforeInteractive"
        />
        {/* PWA theme colour for Safari */}
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        <meta name="apple-mobile-web-app-title" content="Morbitech" />
        <link rel="apple-touch-icon" href="/icons/icon-192.png" />
        <link rel="mask-icon" href="/icons/icon-512.png" color="#3b82f6" />
      </head>
      <body>
        {children}

        {/* Register service worker */}
        <Script id="register-sw" strategy="afterInteractive">
          {`
            if ('serviceWorker' in navigator) {
              window.addEventListener('load', function () {
                navigator.serviceWorker.register('/service-worker.js')
                  .then(function(reg) {
                    console.log('[SW] Registered:', reg.scope);
                  })
                  .catch(function(err) {
                    console.warn('[SW] Registration failed:', err);
                  });
              });
            }
          `}
        </Script>
      </body>
    </html>
  );
  
}
