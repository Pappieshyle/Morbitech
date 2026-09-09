# Morbitech — Deployment & PWA Guide

## File structure — where each file goes

```
morbitech/                        ← Next.js project root
├── app/
│   └── layout.js                 ← ✅ Copy layout.js here
├── components/
│   └── MorbitechApp.jsx          ← ✅ Copy morbitech-app.jsx here
├── hooks/
│   └── usePWA.js                 ← ✅ Copy usePWA.js here
├── public/
│   ├── manifest.json             ← ✅ Copy manifest.json here
│   ├── service-worker.js         ← ✅ Copy service-worker.js here
│   ├── offline.html              ← ✅ Copy offline.html here
│   ├── robots.txt                ← ✅ Copy robots.txt here
│   ├── sitemap.xml               ← ✅ Copy sitemap.xml here
│   └── icons/
│       ├── icon-48.png           ← 🎨 Generate from your logo
│       ├── icon-72.png
│       ├── icon-96.png
│       ├── icon-128.png
│       ├── icon-192.png
│       └── icon-512.png          ← Must be maskable (safe zone)
└── next.config.js                ← ✅ Copy next.config.js here
```

---

## Step 1 — Generate app icons

Use https://realfavicongenerator.net or https://pwa-asset-generator to
create all icon sizes from your logo. Output them to public/icons/.

```bash
npx pwa-asset-generator ./logo.png ./public/icons \
  --background "#050c18" \
  --theme-color "#3b82f6" \
  --manifest ./public/manifest.json
```

---

## Step 2 — Deploy to Vercel (web app)

```bash
npm run build
vercel --prod
```

Point your custom domain (morbitech.com) to Vercel in your DNS settings.
Add CNAME: morbitech.com → cname.vercel-dns.com

---

## Step 3 — Register as Pi App

1. Go to https://developers.minepi.com
2. Create a new app → set App URL to https://morbitech.com
3. In morbitech-app.jsx, replace the mock Pi object with:
   const Pi = window.Pi;
4. Redeploy to Vercel

---

## Step 4 — Wrap for Android (Google Play)

```bash
# Install Capacitor
npm install @capacitor/core @capacitor/cli @capacitor/android

# Init (run once)
npx cap init Morbitech com.morbitech.app --web-dir=out

# In next.config.js, uncomment: output: 'export'
npm run build

# Add Android
npx cap add android
npx cap sync

# Open Android Studio and build signed AAB
npx cap open android
```

Upload the .aab to Google Play Console.
Cost: one-time $25 developer account.
Review time: 3–7 days.

---

## Step 5 — Wrap for iOS (App Store)

Requires: Mac with Xcode 14+

```bash
npm install @capacitor/ios
npx cap add ios
npx cap sync
npx cap open ios   # opens Xcode
```

In Xcode:
- Set Bundle ID: com.morbitech.app
- Set version: 1.0.0
- Add app icons to Assets.xcassets
- Archive → Distribute → App Store Connect

Cost: $99/year Apple Developer account.
Review time: 1–3 weeks.

---

## PWA install prompt (optional UI)

In your app, call usePWA() to show an "Install App" button:

```jsx
import usePWA from '../hooks/usePWA';

function InstallBanner() {
  const { installPrompt, promptInstall, updateReady, applyUpdate } = usePWA();
  if (updateReady) return (
    <div onClick={applyUpdate}>
      New version available — tap to update
    </div>
  );
  if (!installPrompt) return null;
  return (
    <button onClick={promptInstall}>
      📲 Install Morbitech App
    </button>
  );
}
```

---

## Checklist before going live

- [ ] Replace mock Pi object with window.Pi in morbitech-app.jsx
- [ ] Add real bank account details in CheckoutPage
- [ ] Connect contact form to EmailJS or Formspree
- [ ] Generate and add all icon sizes to public/icons/
- [ ] Add OG image (1200×630) as public/og-image.png
- [ ] Update sitemap.xml with real domain
- [ ] Update robots.txt with real domain
- [ ] Test on mobile (Chrome, Safari) — check install prompt
- [ ] Test offline mode — disconnect wifi and reload
- [ ] Register on Pi Developer Portal

---

## Non-Pi retailer access

Retailers without Pi can access the full webapp at morbitech.com.
They can browse all products, add to cart, and check out via:
- Bank transfer (NGN)
- Request invoice (B2B)

Pi payment is an additional option — it never blocks non-Pi users.
