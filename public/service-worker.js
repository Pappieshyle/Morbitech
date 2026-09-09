// ─────────────────────────────────────────────────────────────────────────────
// Morbitech Service Worker
// Strategy: Cache-first for assets, Network-first for API/pages
// ─────────────────────────────────────────────────────────────────────────────

const CACHE_NAME = "morbitech-v1";
const OFFLINE_PAGE = "/offline.html";

// Assets to pre-cache on install
const PRECACHE_ASSETS = [
  "/",
  "/offline.html",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  // Google Fonts
  "https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap",
];

// ── Install ───────────────────────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  console.log("[SW] Installing Morbitech service worker…");
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => {
        console.log("[SW] Pre-caching assets");
        return cache.addAll(PRECACHE_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

// ── Activate ──────────────────────────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  console.log("[SW] Activating Morbitech service worker…");
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) =>
        Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log("[SW] Deleting old cache:", name);
              return caches.delete(name);
            })
        )
      )
      .then(() => self.clients.claim())
  );
});

// ── Fetch ─────────────────────────────────────────────────────────────────────
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== "GET") return;

  // Skip Chrome extensions and browser internals
  if (url.protocol === "chrome-extension:") return;

  // Skip Pi SDK and Anthropic API calls — always go to network
  if (
    url.hostname.includes("minepi.com") ||
    url.hostname.includes("anthropic.com") ||
    url.hostname.includes("api.anthropic.com")
  ) {
    return;
  }

  // ── Strategy: Cache-first for static assets ──────────────────────────────
  if (isStaticAsset(request)) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // ── Strategy: Network-first for HTML pages ───────────────────────────────
  if (request.headers.get("accept")?.includes("text/html")) {
    event.respondWith(networkFirstWithOfflineFallback(request));
    return;
  }

  // ── Strategy: Stale-while-revalidate for everything else ─────────────────
  event.respondWith(staleWhileRevalidate(request));
});

// ─────────────────────────────────────────────────────────────────────────────
// Caching strategies
// ─────────────────────────────────────────────────────────────────────────────

/** Cache-first: serve from cache, fall back to network and update cache */
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return new Response("Asset unavailable offline", { status: 503 });
  }
}

/** Network-first: try network, fall back to cache, then offline page */
async function networkFirstWithOfflineFallback(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    const offlinePage = await caches.match(OFFLINE_PAGE);
    return (
      offlinePage ||
      new Response(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Morbitech — Offline</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'DM Sans', sans-serif; background: #050c18; color: #e8edf5; display: flex; align-items: center; justify-content: center; min-height: 100vh; text-align: center; padding: 24px; }
    .logo { font-size: 28px; font-weight: 800; margin-bottom: 16px; }
    .logo span { color: #3b82f6; }
    h1 { font-size: 22px; margin-bottom: 12px; }
    p { color: rgba(255,255,255,0.5); font-size: 15px; line-height: 1.7; margin-bottom: 28px; max-width: 380px; }
    button { padding: 12px 28px; border-radius: 10px; background: #3b82f6; border: none; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer; }
  </style>
</head>
<body>
  <div>
    <div class="logo">Morbi<span>tech</span></div>
    <h1>You're offline</h1>
    <p>It looks like your internet connection is unavailable. Please check your connection and try again.</p>
    <button onclick="window.location.reload()">Try again</button>
  </div>
</body>
</html>`,
        { status: 200, headers: { "Content-Type": "text/html" } }
      )
    );
  }
}

/** Stale-while-revalidate: serve cache immediately, update in background */
async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const networkFetch = fetch(request).then((response) => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  });
  return cached || networkFetch;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function isStaticAsset(request) {
  const url = new URL(request.url);
  return (
    url.pathname.match(/\.(js|css|png|jpg|jpeg|svg|gif|webp|ico|woff|woff2|ttf|otf)$/) ||
    url.hostname === "fonts.googleapis.com" ||
    url.hostname === "fonts.gstatic.com"
  );
}

// ── Push notifications ────────────────────────────────────────────────────────
self.addEventListener("push", (event) => {
  const data = event.data?.json() ?? {};
  const title = data.title || "Morbitech";
  const options = {
    body: data.body || "New update from Morbitech Digital Signage",
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-72.png",
    tag: data.tag || "morbitech-notification",
    data: { url: data.url || "/" },
    actions: [
      { action: "view", title: "View", icon: "/icons/icon-96.png" },
      { action: "dismiss", title: "Dismiss" },
    ],
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  if (event.action === "dismiss") return;
  const url = event.notification.data?.url || "/";
  event.waitUntil(
    clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        const existing = clientList.find((c) => c.url === url && "focus" in c);
        if (existing) return existing.focus();
        return clients.openWindow(url);
      })
  );
});

// ── Background sync ───────────────────────────────────────────────────────────
self.addEventListener("sync", (event) => {
  if (event.tag === "sync-orders") {
    event.waitUntil(syncPendingOrders());
  }
  if (event.tag === "sync-enquiries") {
    event.waitUntil(syncPendingEnquiries());
  }
});

async function syncPendingOrders() {
  // In production: read from IndexedDB and POST to your backend
  console.log("[SW] Syncing pending orders…");
}

async function syncPendingEnquiries() {
  console.log("[SW] Syncing pending enquiries…");
}
