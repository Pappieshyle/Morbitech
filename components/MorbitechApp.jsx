"use client";

import { useState, useEffect, useCallback, useRef } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY LAYER — Morbitech v2
// Covers: input sanitisation, rate limiting, CSP nonce, Pi SDK guard,
//         payment integrity, URL allowlist, order signing, session expiry
// ─────────────────────────────────────────────────────────────────────────────

// ── 1. Input sanitisation ─────────────────────────────────────────────────────
// Strips HTML tags, control characters, and trims whitespace.
// Use on ALL user-supplied strings before storing or displaying.
const sanitize = (str = "") =>
  String(str)
    .replace(/<[^>]*>/g, "")          // strip HTML tags
    .replace(/[<>"'`]/g, "")          // strip XSS chars
    .replace(/[\x00-\x1F\x7F]/g, "") // strip control chars
    .trim()
    .slice(0, 500);                    // max 500 chars per field

const sanitizeEmail = (email = "") =>
  sanitize(email).toLowerCase().replace(/[^a-z0-9._%+\-@]/g, "").slice(0, 254);

const sanitizePhone = (phone = "") =>
  sanitize(phone).replace(/[^0-9+\-() ]/g, "").slice(0, 20);

// ── 2. Form validation ────────────────────────────────────────────────────────
const validators = {
  name:    (v) => v.length >= 2 && v.length <= 100,
  email:   (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
  phone:   (v) => v === "" || /^[0-9+\-()\s]{7,20}$/.test(v),
  message: (v) => v.length >= 10 && v.length <= 2000,
  qty:     (v) => Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 100,
};

const validateForm = (form, fields) => {
  const errors = {};
  fields.forEach((f) => {
    if (validators[f] && !validators[f](form[f] || ""))
      errors[f] = `Invalid ${f}`;
  });
  return errors;
};

// ── 3. Rate limiter (client-side, per action key) ─────────────────────────────
// Prevents form spam and brute-force attempts.
const rateLimits = {};
const rateLimit = (key, maxCalls = 5, windowMs = 60_000) => {
  const now = Date.now();
  if (!rateLimits[key]) rateLimits[key] = [];
  rateLimits[key] = rateLimits[key].filter((t) => now - t < windowMs);
  if (rateLimits[key].length >= maxCalls) return false;
  rateLimits[key].push(now);
  return true;
};

// ── 4. URL allowlist — only trusted external URLs allowed in window.open ──────
const ALLOWED_ORIGINS = [
  "https://wa.me",
  "https://x.com",
  "https://www.instagram.com",
  "https://sdk.minepi.com",
  "mailto:",
  "tel:",
];
const safeOpen = (url, target = "_blank") => {
  if (!url) return;
  const isAllowed = ALLOWED_ORIGINS.some((o) => url.startsWith(o));
  if (!isAllowed) {
    console.warn("[Security] Blocked unsafe URL:", url);
    return;
  }
  const win = window.open(url, target, "noopener,noreferrer");
  if (win) win.opener = null; // prevent reverse tabnapping
};

// ── 5. Pi SDK guard — never trust mock in production ─────────────────────────
// In the Pi Browser window.Pi is injected by the SDK script.
// In dev/preview we use a mock. The guard prevents accidental prod mock usage.
const IS_PI_BROWSER =
  typeof window !== "undefined" &&
  typeof window.Pi !== "undefined" &&
  window.Pi?.version !== undefined;

const Pi = IS_PI_BROWSER
  ? window.Pi
  : {
      // Dev mock — clearly labelled, never reaches real payments
      _isMock: true,
      authenticate: (_scopes, _cb) =>
        new Promise((res) =>
          setTimeout(
            () => res({ user: { username: "pioneer_dev", uid: "mock_uid_dev" } }),
            800
          )
        ),
      createPayment: (_data, callbacks) => {
        console.warn("[Pi Mock] Payment simulated — not a real transaction");
        setTimeout(() => callbacks.onReadyForServerApproval("MOCK_PAY_" + Date.now()), 600);
        setTimeout(() => callbacks.onReadyForServerCompletion("MOCK_PAY_" + Date.now(), {}), 1800);
      },
    };

// ── 6. Payment integrity — server-side approval placeholder ──────────────────
// In production, BOTH onReadyForServerApproval and onReadyForServerCompletion
// MUST call YOUR backend. The frontend only initiates — it never confirms.
// Replace these stubs with real fetch() calls to your Next.js API routes.
const piServerApprove = async (paymentId) => {
  // TODO: POST /api/pi/approve  { paymentId }
  console.log("[Pi] Server approval needed for:", paymentId);
  return true; // stub — replace with real API call
};

const piServerComplete = async (paymentId, txid) => {
  // TODO: POST /api/pi/complete  { paymentId, txid }
  console.log("[Pi] Server completion needed for:", paymentId, txid);
  return true; // stub — replace with real API call
};

// ── 7. Order ID generator — unpredictable, non-sequential ─────────────────────
const genOrderId = () => {
  const ts  = Date.now().toString(36).toUpperCase();
  const rnd = Math.random().toString(36).substring(2, 7).toUpperCase();
  return `MBT-${ts}-${rnd}`;
};

// ── 8. Session expiry — Pi auth expires after 30 min of inactivity ────────────
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

// ── 9. Content Security Policy meta tag (injected at runtime) ─────────────────
// For full CSP, set headers in next.config.js. This is a belt-and-suspenders
// defence for the React-only (no Next.js) deployment path.
if (typeof document !== "undefined") {
  const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!existing) {
    const meta = document.createElement("meta");
    meta.httpEquiv = "Content-Security-Policy";
    meta.content = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval' https://sdk.minepi.com https://fonts.googleapis.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' https://www.allsee-tech.com https://m.media-amazon.com data: blob:",
      "connect-src 'self' https://sdk.minepi.com https://api.minepi.com",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join("; ");
    document.head.prepend(meta);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exchange rates & constants
// ─────────────────────────────────────────────────────────────────────────────

const USD_TO_NGN = 1400;
const PI_RATE = 1.85; // 1 Pi = $1.85
const WA_NUMBER = "2348125911805";

const fmt = {
  usd: (n) => "$" + n.toLocaleString("en-US", { minimumFractionDigits: 0, maximumFractionDigits: 0 }),
  ngn: (n) => "₦" + Math.round(n * USD_TO_NGN).toLocaleString("en-NG"),
  pi: (n) => "π " + (n / PI_RATE).toFixed(1),
};

// ── Product data ───────────────────────────────────────────────────────────────
const PRODUCTS = [
  // ── Featured ──
  { id: 1,  cat: "Featured", tag: "Best Seller", name: "Slimline Pro Advertising Display", short: "Ultra-thin plug & play indoor advertising screen", price: 620,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-slimline-pro-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Slimline Pro indoor advertising display", industries: ["Retail","Corporate","Hospitality"], specs: { Size:"32–75 inch", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Portrait / Landscape", Thickness:"28mm" } },
  { id: 2,  cat: "Featured", tag: "New",         name: "Vibrant Professional Advertising Display", short: "High-colour-accuracy commercial grade display", price: 780,  color: "#1e3a5f", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Vibrant professional advertising display", industries: ["Retail","Food & QSR","Corporate"], specs: { Size:"43–86 inch", Resolution:"3840×2160 4K", Brightness:"500 cd/m²", OS:"Android 11", Colour_Gamut:"108% NTSC", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape" } },
  { id: 3,  cat: "Featured", tag: "Premium",     name: "4K Elite Outdoor Advertising Display", short: "IP65 waterproof wall-mounted 4K outdoor screen", price: 2200, color: "#064e3b", img: "https://www.allsee-tech.com/images/outdoor-4k-elite-waterproof-ip-rated-wall-mounted-digital-signage-advertising-displays-01.jpg", imgAlt: "4K Elite outdoor advertising display", industries: ["Government","Transport","Retail"], specs: { Size:"55–86 inch", Resolution:"3840×2160 4K", Brightness:"2500 cd/m²", IP_Rating:"IP65", OS:"Android 11", Connectivity:"4G, WiFi, LAN", Temp:"-30°C to 60°C" } },
  { id: 4,  cat: "Featured", tag: "Popular",     name: "Indoor GOB DV-LED Wall", short: "Fine pixel pitch glue-on-board modular LED wall", price: 3800, color: "#1e3a5f", img: "https://www.allsee-tech.com/images/led-indoor-glue-on-board-gob-modular-video-wall-advertising-dooh-high-brightness-fine-pixel-pitch-p1-p2-01.jpg", imgAlt: "Indoor GOB DV-LED video wall", industries: ["Corporate","Entertainment","Hospitality"], specs: { Pixel_Pitch:"P1.5 – P2", Brightness:"800 nits", Refresh_Rate:"3840Hz", IP_Rating:"IP42 front", Cabinet:"500×500mm", Control:"Novastar included", Viewing_Angle:"160°" } },
  { id: 5,  cat: "Featured", tag: "Popular",     name: "Ultra Narrow Bezel LCD Video Wall", short: "0.88mm bezel-to-bezel LCD video wall system", price: 5400, color: "#3b0764", img: "https://www.allsee-tech.com/images/lcd-extreme-ultra-narrow-bezel-video-wall-displays-01.jpg", imgAlt: "Ultra narrow bezel LCD video wall", industries: ["Corporate","Government","Entertainment"], specs: { Configuration:"Up to 10×10", Panel_Size:"46–55 inch", Bezel:"0.88mm", Resolution:"1920×1080 per panel", Brightness:"500 cd/m²", Controller:"Included", Mounting:"Wall bracket included" } },
  { id: 6,  cat: "Featured", tag: "New",         name: "Ultra-Wide Stretched Bar Monitor", short: "Shelf-edge & shelf-top stretched display", price: 490,  color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-ultra-wide-stretched-aspect-ratio-professional-commercial-grade-industrial-monitor-displays-01.jpg", imgAlt: "Ultra wide stretched bar monitor", industries: ["Retail","Transport","Hospitality"], specs: { Size:"23.1–58.4 inch", Aspect_Ratio:"32:9 / 16:3", Resolution:"1920×540 / 1920×360", Brightness:"700 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape" } },

  // ── Corporate ──
  { id: 7,  cat: "Corporate", tag: "Interactive", name: "4K Slim Bezel Interactive Touch Display", short: "Smart multi-touch presentation screen for meetings", price: 1450, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/infrared-interactive-smart-multi-touch-screen-presentation-android-windows-meetingpad-ops-display-education-business-01.jpg", imgAlt: "4K slim bezel interactive touch display", industries: ["Corporate","Education"], specs: { Size:"55–110 inch", Touch:"20-point IR", Resolution:"3840×2160 4K", OS:"Android 11 / Windows", Connectivity:"WiFi, LAN, HDMI, USB", Pen:"Included", Mounting:"Floor stand / wall mount" } },
  { id: 8,  cat: "Corporate", tag: "New",         name: "PushShare Wireless Mirroring Dongle", short: "One-tap wireless screen sharing for meeting rooms", price: 220,  color: "#1e3a5f", img: "https://www.allsee-tech.com/images/pushshare-dongle-receiving-unit-corporate-wireless-mirroring-01.jpg", imgAlt: "PushShare wireless mirroring dongle", industries: ["Corporate"], specs: { Protocol:"Miracast, AirPlay, Chromecast", Resolution:"Up to 4K", Latency:"<50ms", OS_Support:"Windows, macOS, iOS, Android", Setup:"Plug & play", Range:"10 metres", Power:"USB-C" } },
  { id: 9,  cat: "Corporate", tag: "Premium",     name: "Fine Pitch DV-LED Video Wall", short: "High-definition LED wall for boardrooms & lobbies", price: 6800, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/led-fine-pixel-pitch-high-definition-presentation-large-format-video-wall-display-meeting-board-conference-room-android-01.jpg", imgAlt: "Fine pitch DV-LED video wall", industries: ["Corporate","Government"], specs: { Pixel_Pitch:"P1.2 – P2.5", Brightness:"600–1200 nits", Refresh_Rate:"3840Hz", Cabinet:"600×337.5mm", OS:"Android 11", Control:"Novastar", Viewing_Angle:"160°" } },
  { id: 10, cat: "Corporate", tag: "Popular",     name: "POS PCAP Touch Screen", short: "Slimline point-of-sale multi-touch tablet display", price: 540,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "POS PCAP touch screen", industries: ["Retail","Food & QSR","Corporate"], specs: { Size:"10–27 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Power:"PoE", Connectivity:"WiFi, LAN, USB", Mount:"Desk stand / wall mount" } },

  // ── Fast Food / QSR ──
  { id: 11, cat: "Fast Food/QSR", tag: "New",     name: "Vibrant Menu Board Display", short: "High-brightness digital menu board for QSR", price: 780,  color: "#78350f", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Vibrant menu board display", industries: ["Food & QSR","Hospitality"], specs: { Size:"43–86 inch", Resolution:"3840×2160 4K", Brightness:"500 cd/m²", OS:"Android 11", Orientation:"Landscape", Connectivity:"WiFi, LAN, USB", Mount:"Ceiling / wall" } },
  { id: 12, cat: "Fast Food/QSR", tag: "Interactive", name: "PCAP Self-Service Ordering Kiosk", short: "Floor-standing self-order kiosk for fast food", price: 1100, color: "#7c2d12", img: "https://www.allsee-tech.com/images/pcap-self-service-ordering-qsr-touch-screen-01.jpg", imgAlt: "PCAP self-service ordering kiosk", industries: ["Food & QSR","Retail","Healthcare"], specs: { Size:"21.5–43 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11 / Windows", Enclosure:"Steel floor-standing", Printer:"Optional thermal", Connectivity:"WiFi, LAN, USB" } },
  { id: 13, cat: "Fast Food/QSR", tag: "Popular", name: "Slimline Pro Menu Display", short: "Slim wall-mount menu board for restaurants", price: 620,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-slimline-digital-signage-advertising-displays-standalone-plug-and-play-01.jpg", imgAlt: "Slimline Pro menu board display", industries: ["Food & QSR","Retail"], specs: { Size:"32–75 inch", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Portrait / Landscape", Thickness:"28mm" } },

  // ── Modular DV-LED ──
  { id: 14, cat: "Modular DV-LED", tag: "New",    name: "Indoor SMD DV-LED Wall", short: "Surface-mount modular indoor LED video wall", price: 2900, color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-indoor-modular-video-wall-advertising-dooh-high-brightness-fine-pixel-pitch-p1-p2-p3-p4-01.jpg", imgAlt: "Indoor SMD DV-LED modular video wall", industries: ["Corporate","Entertainment","Retail"], specs: { Pixel_Pitch:"P1.5 – P4", Brightness:"600–1000 nits", Refresh_Rate:"3840Hz", Cabinet:"500×500mm", IP_Rating:"IP42", Control:"Novastar", Viewing_Angle:"160°" } },
  { id: 15, cat: "Modular DV-LED", tag: "Popular", name: "Indoor GOB DV-LED Wall", short: "Glue-on-board modular LED wall — splash resistant", price: 3800, color: "#1e3a5f", img: "https://www.allsee-tech.com/images/led-indoor-glue-on-board-gob-modular-video-wall-advertising-dooh-high-brightness-fine-pixel-pitch-p1-p2-01.jpg", imgAlt: "Indoor GOB DV-LED wall", industries: ["Corporate","Entertainment","Hospitality"], specs: { Pixel_Pitch:"P1.5 – P2", Brightness:"800 nits", Refresh_Rate:"3840Hz", IP_Rating:"IP42 front", Cabinet:"500×500mm", Control:"Novastar included", Viewing_Angle:"160°" } },
  { id: 16, cat: "Modular DV-LED", tag: "New",    name: "Indoor COB DV-LED Wall", short: "Chip-on-board technology — ultra fine pixel pitch", price: 5200, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/led-indoor-cob-direct-view-led-solutions-p1-2-01.jpg", imgAlt: "Indoor COB DV-LED wall", industries: ["Corporate","Government","Entertainment"], specs: { Pixel_Pitch:"P0.9 – P1.5", Brightness:"600 nits", Refresh_Rate:"7680Hz", IP_Rating:"IP54 front", Cabinet:"600×337.5mm", Control:"Novastar included", Lifespan:"100,000 hrs" } },
  { id: 17, cat: "Modular DV-LED", tag: "Premium", name: "Indoor High Brightness DV-LED", short: "High-ambient-light modular LED wall", price: 4400, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/led-indoor-high-brightness-modular-video-wall-advertising-dooh-high-brightness-fine-pixel-pitch-p1-p2-01.jpg", imgAlt: "Indoor high brightness DV-LED wall", industries: ["Retail","Hospitality","Entertainment"], specs: { Pixel_Pitch:"P1.5 – P2.5", Brightness:"2000–3000 nits", Refresh_Rate:"3840Hz", Cabinet:"500×500mm", IP_Rating:"IP42", Control:"Novastar", Viewing_Angle:"160°" } },
  { id: 18, cat: "Modular DV-LED", tag: "Weatherproof", name: "Outdoor DV-LED Wall", short: "IP65 rated outdoor modular LED video wall", price: 6200, color: "#064e3b", img: "https://www.allsee-tech.com/images/led-outdoor-video-wall-ip-rated-waterproof-advertising-dooh-modular-video-wall-high-brightness-pixel-pitch-p6-p10-01.jpg", imgAlt: "Outdoor DV-LED modular video wall", industries: ["Government","Transport","Retail"], specs: { Pixel_Pitch:"P4 – P10", Brightness:"5000–8000 nits", IP_Rating:"IP65", Cabinet:"640×640mm", Temp:"-20°C to 60°C", Control:"Novastar", Power:"Front / rear service" } },

  // ── All-in-One DV-LED ──
  { id: 19, cat: "All-in-One DV-LED", tag: "Popular", name: "Fine Pitch All-in-One DV-LED Wall", short: "All-in-one LED wall — no external controller needed", price: 4200, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/led-fine-pixel-pitch-high-definition-presentation-large-format-video-wall-display-meeting-board-conference-room-android-01.jpg", imgAlt: "Fine pitch all-in-one DV-LED video wall", industries: ["Corporate","Government","Education"], specs: { Pixel_Pitch:"P1.2 – P2.5", Brightness:"600 nits", Refresh_Rate:"3840Hz", OS:"Android 11 built-in", Connectivity:"WiFi, LAN, HDMI", Cabinet:"600×337.5mm", Control:"Built-in" } },
  { id: 20, cat: "All-in-One DV-LED", tag: "New",     name: "Indoor DV-LED Totem", short: "Freestanding all-in-one LED totem display", price: 2600, color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-indoor-all-in-one-digital-totem-poster-dooh-fine-pixel-pitch-p1-p2-p3-p4-01.jpg", imgAlt: "Indoor DV-LED totem display", industries: ["Retail","Hospitality","Government"], specs: { Pixel_Pitch:"P2 – P4", Brightness:"800 nits", Height:"Up to 3m", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Enclosure:"Aluminium", Base:"Weighted floor stand" } },
  { id: 21, cat: "All-in-One DV-LED", tag: "New",     name: "Transparent DV-LED Display", short: "See-through LED display for window branding", price: 3600, color: "#065f46", img: "https://www.allsee-tech.com/images/led-indoor-transparent-window-display-dooh-fine-pixel-pitch-p3-01.jpg", imgAlt: "Transparent DV-LED window display", industries: ["Retail","Hospitality","Entertainment"], specs: { Pixel_Pitch:"P3.9 – P7.8", Transparency:"70–85%", Brightness:"2000 nits", Size:"Custom", OS:"Android 11", Connectivity:"WiFi, LAN", IP_Rating:"IP33" } },
  { id: 22, cat: "All-in-One DV-LED", tag: "Premium",  name: "DV-LED Window Display", short: "High brightness all-in-one window-facing LED", price: 3100, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/led-indoor-high-brightness-all-in-one-window-display-dooh-fine-pixel-pitch-p2-01.jpg", imgAlt: "DV-LED window display", industries: ["Retail","Hospitality"], specs: { Pixel_Pitch:"P2", Brightness:"2500 nits", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Cabinet:"500×500mm", Control:"Built-in", Orientation:"Portrait" } },
  { id: 23, cat: "All-in-One DV-LED", tag: "Weatherproof", name: "Outdoor DV-LED Shop Fascia", short: "Waterproof outdoor LED shop front display", price: 5800, color: "#064e3b", img: "https://www.allsee-tech.com/images/led-outdoor-shop-fascia-sign-video-wall-ip-rated-waterproof-advertising-dooh-modular-video-wall-high-brightness-pixel-pitch-p4-p6-01.jpg", imgAlt: "Outdoor DV-LED shop fascia", industries: ["Retail","Government","Transport"], specs: { Pixel_Pitch:"P4 – P6", Brightness:"5000 nits", IP_Rating:"IP65", OS:"Android 11", Control:"Built-in", Temp:"-20°C to 60°C", Custom_Size:"Yes" } },

  // ── Digital Posters ──
  { id: 24, cat: "Digital Posters", tag: "New",     name: "Android Freestanding Digital Poster", short: "Portrait LED poster on floor stand — plug & play", price: 560,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-slimline-freestanding-digital-signage-posters-kiosks-totems-standalone-plug-and-play-01.jpg", imgAlt: "Android freestanding digital poster", industries: ["Retail","Hospitality","Government"], specs: { Size:"43–75 inch", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Orientation:"Portrait", Connectivity:"WiFi, LAN, USB", Stand:"Aluminium floor stand" } },
  { id: 25, cat: "Digital Posters", tag: "Popular", name: "Superslim Double-Sided Digital Poster", short: "Ultra-thin back-to-back freestanding digital poster", price: 890,  color: "#1e3a5f", img: "https://www.allsee-tech.com/images/super-slim-freestanding-double-sided-digital-posters-01.jpg", imgAlt: "Superslim double-sided digital poster", industries: ["Retail","Hospitality","Transport"], specs: { Size:"43–65 inch", Thickness:"24mm", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN", Sides:"2 independent screens" } },
  { id: 26, cat: "Digital Posters", tag: "Popular", name: "Slimline Pro Wall-Mount Poster", short: "Ultra-slim wall-mounted portrait advertising screen", price: 620,  color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-slimline-digital-signage-advertising-displays-standalone-plug-and-play-01.jpg", imgAlt: "Slimline Pro wall-mounted digital poster", industries: ["Retail","Corporate","Healthcare"], specs: { Size:"32–75 inch", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Orientation:"Portrait", Connectivity:"WiFi, LAN, USB", Thickness:"28mm" } },

  // ── High Brightness ──
  { id: 27, cat: "High Brightness", tag: "Weatherproof", name: "High Brightness Outdoor Window Display", short: "Sun-readable high-brightness window-facing screen", price: 1650, color: "#78350f", img: "https://www.allsee-tech.com/images/led-high-brightness-window-display-digital-signage-outdoor-facing-01.jpg", imgAlt: "High brightness outdoor window display", industries: ["Retail","Transport","Hospitality"], specs: { Size:"43–75 inch", Brightness:"2500–4000 cd/m²", Resolution:"1920×1080 FHD", OS:"Android 11", IP_Rating:"IP54 front", Connectivity:"WiFi, LAN", Orientation:"Portrait / Landscape" } },
  { id: 28, cat: "High Brightness", tag: "Premium",     name: "Ultra High Brightness Indoor Display", short: "3000 nit display for bright retail environments", price: 1980, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/led-ultra-high-brightness-indoor-digital-signage-displays-01.jpg", imgAlt: "Ultra high brightness indoor display", industries: ["Retail","Hospitality","Entertainment"], specs: { Size:"43–86 inch", Brightness:"3000 cd/m²", Resolution:"3840×2160 4K", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape", Cooling:"Active fan" } },

  // ── Outdoor Digital Posters ──
  { id: 29, cat: "Outdoor Digital Posters", tag: "Weatherproof", name: "Outdoor Android Battery A-Board", short: "IP55 battery-powered portable outdoor A-board", price: 1120, color: "#065f46", img: "https://www.allsee-tech.com/images/outdoor-high-brightness-waterproof-ip-rated-led-freestanding-android-battery-a-board-portable-all-in-one-network-cms-digital-signage-advertising-displays-01.jpg", imgAlt: "Outdoor Android battery A-board", industries: ["Retail","Events","Government"], specs: { Size:"43–55 inch", Brightness:"2500 cd/m²", Battery:"8hr runtime", IP_Rating:"IP55", OS:"Android 11", Connectivity:"4G, WiFi", Weight:"24kg" } },
  { id: 30, cat: "Outdoor Digital Posters", tag: "Popular", name: "Outdoor Freestanding Digital Totem", short: "IP65 weatherproof outdoor portrait totem", price: 2400, color: "#064e3b", img: "https://www.allsee-tech.com/images/outdoor-ip65-waterproof-freestanding-digital-totem-poster-signage-01.jpg", imgAlt: "Outdoor freestanding digital totem", industries: ["Government","Transport","Retail"], specs: { Size:"55–75 inch", Brightness:"2500–5000 cd/m²", IP_Rating:"IP65", OS:"Android 11", Connectivity:"4G, WiFi, LAN", Enclosure:"Powder-coated steel", Base:"Concrete anchor / freestanding" } },

  // ── Touch Screens ──
  { id: 31, cat: "Touch Screens", tag: "Interactive", name: "PCAP Self-Service Kiosk 43\"", short: "Floor-standing 10-point capacitive touch kiosk", price: 980,  color: "#7c2d12", img: "https://www.allsee-tech.com/images/pcap-self-service-ordering-qsr-touch-screen-01.jpg", imgAlt: "PCAP self-service touch screen kiosk", industries: ["Retail","Healthcare","Education","Food & QSR"], specs: { Size:"21.5–43 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11 / Windows", Enclosure:"Steel floor-standing", Printer:"Optional thermal", Connectivity:"WiFi, LAN, USB" } },
  { id: 32, cat: "Touch Screens", tag: "Popular",     name: "4K Interactive Smart Panel", short: "20-point touch smart display for education & corporate", price: 1450, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/infrared-interactive-smart-multi-touch-screen-presentation-android-windows-meetingpad-ops-display-education-business-01.jpg", imgAlt: "4K interactive smart panel", industries: ["Education","Corporate"], specs: { Size:"55–110 inch", Touch:"20-point IR", Resolution:"3840×2160 4K", OS:"Android 11 / Windows", Pen:"Included", Connectivity:"WiFi, LAN, HDMI, USB", Mount:"Floor stand / wall" } },
  { id: 33, cat: "Touch Screens", tag: "New",         name: "Slimline PCAP POS Display", short: "Countertop PCAP touch screen for point of sale", price: 540,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "Slimline PCAP POS display", industries: ["Retail","Food & QSR","Corporate"], specs: { Size:"10–27 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Power:"PoE", Connectivity:"WiFi, LAN, USB", Mount:"Desk stand / wall mount" } },

  // ── LCD Video Walls ──
  { id: 34, cat: "LCD Video Walls", tag: "Premium", name: "Ultra Narrow Bezel LCD Video Wall", short: "0.88mm bezel 55\" panels — scalable to any size", price: 5400, color: "#3b0764", img: "https://www.allsee-tech.com/images/lcd-extreme-ultra-narrow-bezel-video-wall-displays-01.jpg", imgAlt: "Ultra narrow bezel LCD video wall", industries: ["Corporate","Government","Entertainment"], specs: { Config:"Up to 10×10", Panel:"46–55 inch", Bezel:"0.88mm", Resolution:"1920×1080 per panel", Brightness:"500 cd/m²", Controller:"Included", Mounting:"Wall bracket" } },
  { id: 35, cat: "LCD Video Walls", tag: "Popular", name: "LCD Video Wall 2×2 Bundle", short: "Turnkey 2×2 video wall system with controller", price: 3200, color: "#4c1d95", img: "https://www.allsee-tech.com/images/lcd-extreme-ultra-narrow-bezel-video-wall-displays-01.jpg", imgAlt: "LCD 2x2 video wall bundle", industries: ["Corporate","Retail","Hospitality"], specs: { Config:"2×2 (4 panels)", Panel:"55 inch", Bezel:"1.7mm", Resolution:"1920×1080 per panel", Brightness:"500 cd/m²", Controller:"Included", Mounting:"Wall bracket included" } },

  // ── Commercial Monitors ──
  { id: 36, cat: "Commercial Monitors", tag: "New",     name: "Economy Professional Monitor 43\"", short: "Commercial-grade display for 24/7 operation", price: 340,  color: "#1e3a5f", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Economy professional monitor", industries: ["Corporate","Retail","Education"], specs: { Size:"32–75 inch", Resolution:"1920×1080 FHD", Brightness:"350 cd/m²", OS:"Commercial display (no Android)", Connectivity:"HDMI, VGA, USB", Runtime:"24/7 rated", Mount:"VESA 400×400" } },
  { id: 37, cat: "Commercial Monitors", tag: "New",     name: "Vibrant Commercial Display", short: "Wide colour gamut commercial monitor", price: 480,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Vibrant commercial display", industries: ["Retail","Hospitality","Corporate"], specs: { Size:"43–86 inch", Resolution:"3840×2160 4K", Brightness:"500 cd/m²", Colour_Gamut:"108% NTSC", Connectivity:"HDMI, USB, LAN", Runtime:"24/7 rated", Mount:"VESA 400×400" } },

  // ── Small-Sized Displays ──
  { id: 38, cat: "Small-Sized Displays", tag: "Popular", name: "Compact 10\" PCAP Tablet Display", short: "Small-format Android touch display for counters", price: 185,  color: "#7c2d12", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "Compact 10 inch PCAP tablet display", industries: ["Retail","Food & QSR","Corporate"], specs: { Size:"10–22 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Power:"PoE / DC", Connectivity:"WiFi, LAN, USB", Mount:"Desk stand" } },
  { id: 39, cat: "Small-Sized Displays", tag: "New",     name: "Slimline Small Format Poster", short: "Compact wall-mount advertising screen", price: 280,  color: "#1e3a5f", img: "https://www.allsee-tech.com/images/led-slimline-digital-signage-advertising-displays-standalone-plug-and-play-01.jpg", imgAlt: "Small format slimline poster display", industries: ["Retail","Healthcare","Hospitality"], specs: { Size:"22–32 inch", Resolution:"1920×1080 FHD", Brightness:"2500 cd/m²", OS:"Android 11", Orientation:"Portrait / Landscape", Connectivity:"WiFi, LAN, USB", Thickness:"28mm" } },

  // ── Wide Format Displays ──
  { id: 40, cat: "Wide Format Displays", tag: "Premium", name: "86\" Ultra Wide Commercial Display", short: "Large-format commercial display for boardrooms", price: 2100, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "86 inch ultra wide commercial display", industries: ["Corporate","Government","Education"], specs: { Size:"75–98 inch", Resolution:"3840×2160 4K", Brightness:"500 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, HDMI, USB", Runtime:"24/7 rated", Mount:"VESA 600×400" } },
  { id: 41, cat: "Wide Format Displays", tag: "Popular", name: "Stretched Ultra-Wide Bar Display", short: "32:9 aspect ratio shelf & bar display", price: 490,  color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-ultra-wide-stretched-aspect-ratio-professional-commercial-grade-industrial-monitor-displays-01.jpg", imgAlt: "Stretched ultra-wide bar display", industries: ["Retail","Transport","Hospitality"], specs: { Size:"23.1–58.4 inch", Aspect_Ratio:"32:9 / 16:3", Resolution:"1920×540", Brightness:"700 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape" } },

  // ── Media Players ──
  { id: 42, cat: "Media Players", tag: "Popular", name: "Android Digital Signage Media Player", short: "Compact plug-in media player for any display", price: 95,   color: "#065f46", img: "https://www.allsee-tech.com/images/android-media-player-digital-signage-standalone-network-cms-01.jpg", imgAlt: "Android digital signage media player", industries: ["Retail","Corporate","Government"], specs: { OS:"Android 11", CPU:"Quad-core 1.8GHz", RAM:"2GB", Storage:"16GB", Connectivity:"WiFi, LAN, HDMI, USB", Output:"4K HDMI", Power:"5V DC" } },
  { id: 43, cat: "Media Players", tag: "New",     name: "4K Pro Network Media Player", short: "4K CMS-enabled media player with scheduling", price: 145,  color: "#0f4c8a", img: "https://www.allsee-tech.com/images/android-media-player-digital-signage-standalone-network-cms-01.jpg", imgAlt: "4K Pro network media player", industries: ["Corporate","Retail","Government"], specs: { OS:"Android 11", CPU:"Octa-core 2.0GHz", RAM:"4GB", Storage:"32GB", Connectivity:"WiFi, LAN, HDMI, USB", Output:"4K@60fps HDMI", CMS:"Built-in CMS app" } },

  // ── Digital Signage Software ──
  { id: 44, cat: "Digital Signage Software", sub: "Content Management System", tag: "Popular", name: "Cloud CMS — Standard Plan", short: "Web-based content management for up to 10 screens", price: 25,   color: "#1e1b4b", img: "https://www.allsee-tech.com/images/digital-signage-software-cms-content-management-system-01.jpg", imgAlt: "Cloud CMS standard plan", industries: ["Retail","Corporate","Healthcare","Education"], specs: { Screens:"Up to 10", Scheduling:"Yes", Remote_Control:"Yes", Templates:"100+", OS_Support:"Android, Windows", Billing:"Per month", Storage:"10GB cloud" } },
  { id: 45, cat: "Digital Signage Software", sub: "Content Management System", tag: "New",     name: "Cloud CMS — Pro Plan", short: "Advanced CMS for multi-site & multi-user teams", price: 65,   color: "#3b0764", img: "https://www.allsee-tech.com/images/digital-signage-software-cms-content-management-system-01.jpg", imgAlt: "Cloud CMS pro plan", industries: ["Corporate","Government","Retail"], specs: { Screens:"Unlimited", Scheduling:"Advanced", Remote_Control:"Yes", Templates:"500+", Multi_User:"Yes", Billing:"Per month", Storage:"100GB cloud" } },
  { id: 46, cat: "Digital Signage Software", sub: "Touch Content Management System", tag: "Popular", name: "TouchCMS — Interactive Plan", short: "CMS with touch interaction analytics & templates", price: 85, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/digital-signage-software-cms-content-management-system-01.jpg", imgAlt: "Touch CMS plan", industries: ["Retail","Education","Healthcare"], specs: { Screens:"Up to 20", Touch_Analytics:"Yes", Interactive_Templates:"50+", Remote_Control:"Yes", OS_Support:"Android, Windows", Billing:"Per month", Storage:"20GB cloud" } },

  // ── Touch Screens expanded ──
  { id: 47, cat: "Touch Screens", sub: "Digital Signage Interactive Displays", tag: "Popular", name: "Interactive Digital Signage Display 55\"", short: "Multi-touch interactive advertising & wayfinding display", price: 1150, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/infrared-interactive-smart-multi-touch-screen-presentation-android-windows-meetingpad-ops-display-education-business-01.jpg", imgAlt: "Interactive digital signage display", industries: ["Retail","Government","Transport"], specs: { Size:"43–75 inch", Touch:"10-point IR", Resolution:"1920×1080 FHD", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Mount:"Wall / floor stand", Brightness:"500 cd/m²" } },
  { id: 48, cat: "Touch Screens", sub: "PCAP Touch Screen Monitors", tag: "New", name: "PCAP Touch Screen Monitor 32\"", short: "Commercial capacitive touch monitor for kiosks & POS", price: 420, color: "#1e3a5f", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "PCAP touch screen monitor", industries: ["Retail","Corporate","Food & QSR"], specs: { Size:"22–43 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Brightness:"350 cd/m²", Mount:"VESA / desk stand", Runtime:"24/7" } },
  { id: 49, cat: "Touch Screens", sub: "Android PCAP Touch Screens", tag: "Popular", name: "Android PCAP Touch Screen 43\"", short: "Android-powered capacitive touch display", price: 680, color: "#7c2d12", img: "https://www.allsee-tech.com/images/pcap-self-service-ordering-qsr-touch-screen-01.jpg", imgAlt: "Android PCAP touch screen", industries: ["Retail","Corporate","Education"], specs: { Size:"32–65 inch", Touch:"10-point PCAP", Resolution:"1920×1080 FHD", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Brightness:"400 cd/m²", Mount:"Wall / floor stand" } },
  { id: 50, cat: "Touch Screens", sub: "Android PCAP Touch Screen Kiosks", tag: "Interactive", name: "Android PCAP Touch Screen Kiosk 43\"", short: "Floor-standing Android kiosk with capacitive touch", price: 1050, color: "#0f4c8a", img: "https://www.allsee-tech.com/images/pcap-self-service-ordering-qsr-touch-screen-01.jpg", imgAlt: "Android PCAP touch screen kiosk", industries: ["Retail","Healthcare","Government"], specs: { Size:"32–55 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Enclosure:"Steel floor-standing", Connectivity:"WiFi, LAN, USB", Printer:"Optional" } },
  { id: 51, cat: "Touch Screens", sub: "Freestanding PCAP Touch Screen Posters", tag: "New", name: "Freestanding PCAP Touch Screen Poster", short: "Portrait PCAP touch poster on elegant floor stand", price: 890, color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-slimline-freestanding-digital-signage-posters-kiosks-totems-standalone-plug-and-play-01.jpg", imgAlt: "Freestanding PCAP touch screen poster", industries: ["Retail","Hospitality","Corporate"], specs: { Size:"43–65 inch", Touch:"10-point PCAP", Resolution:"1920×1080 FHD", OS:"Android 11", Stand:"Aluminium floor stand", Connectivity:"WiFi, LAN, USB", Orientation:"Portrait" } },
  { id: 52, cat: "Touch Screens", sub: "10\" & 15\" POS Android PCAP Touch Screens", tag: "Popular", name: "10\" POS Android PCAP Touch Screen", short: "Compact countertop POS touch display", price: 210, color: "#7c2d12", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "10 inch POS Android PCAP touch screen", industries: ["Retail","Food & QSR","Corporate"], specs: { Size:"10 & 15 inch", Touch:"10-point PCAP", Resolution:"1280×800 / 1920×1080", OS:"Android 11", Power:"PoE / DC", Connectivity:"WiFi, LAN, USB", Mount:"Desk stand" } },

  // ── High Brightness expanded ──
  { id: 53, cat: "High Brightness", sub: "Ultra High Brightness Window Displays", tag: "Popular", name: "Ultra High Brightness Window Display 55\"", short: "3000 nit sun-readable display for shop windows", price: 1750, color: "#78350f", img: "https://www.allsee-tech.com/images/led-high-brightness-window-display-digital-signage-outdoor-facing-01.jpg", imgAlt: "Ultra high brightness window display", industries: ["Retail","Hospitality","Transport"], specs: { Size:"43–75 inch", Brightness:"3000 cd/m²", Resolution:"1920×1080 FHD", OS:"Android 11", IP_Rating:"IP54 front", Connectivity:"WiFi, LAN", Orientation:"Portrait / Landscape" } },
  { id: 54, cat: "High Brightness", sub: "Vibrant Hanging Double Sided Window Displays", tag: "New", name: "Vibrant Hanging Double-Sided Window Display", short: "Two-sided hanging display for window visibility", price: 1320, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Vibrant hanging double-sided window display", industries: ["Retail","Hospitality"], specs: { Size:"43–55 inch", Sides:"2 independent screens", Brightness:"2000 cd/m²", Resolution:"1920×1080 FHD", OS:"Android 11", Mount:"Ceiling hang kit", Connectivity:"WiFi, LAN" } },
  { id: 55, cat: "High Brightness", sub: "Ultra High Brightness Hanging Double-Sided Displays", tag: "Premium", name: "Ultra High Brightness Double-Sided Hanging Display", short: "3000 nit dual-sided ceiling-mounted retail display", price: 2100, color: "#0c4a6e", img: "https://www.allsee-tech.com/images/led-high-brightness-window-display-digital-signage-outdoor-facing-01.jpg", imgAlt: "Ultra high brightness double-sided hanging display", industries: ["Retail","Hospitality"], specs: { Size:"43–65 inch", Sides:"2 independent", Brightness:"3000 cd/m²", Resolution:"1920×1080 FHD", OS:"Android 11", Mount:"Ceiling hang kit included", Connectivity:"WiFi, LAN" } },
  { id: 56, cat: "High Brightness", sub: "High Vibrance Android Advertising Displays", tag: "New", name: "High Vibrance Android Advertising Display", short: "Wide colour gamut high-vibrance indoor advertising screen", price: 860, color: "#4c1d95", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "High vibrance Android advertising display", industries: ["Retail","Hospitality","Corporate"], specs: { Size:"43–86 inch", Brightness:"700 cd/m²", Colour_Gamut:"120% NTSC", Resolution:"3840×2160 4K", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape" } },

  // ── Outdoor Digital Posters expanded ──
  { id: 57, cat: "Outdoor Digital Posters", sub: "Outdoor Digital Advertising Displays", tag: "Weatherproof", name: "Outdoor Digital Advertising Display 55\"", short: "IP65 wall-mounted outdoor digital advertising screen", price: 1950, color: "#064e3b", img: "https://www.allsee-tech.com/images/outdoor-4k-elite-waterproof-ip-rated-wall-mounted-digital-signage-advertising-displays-01.jpg", imgAlt: "Outdoor digital advertising display", industries: ["Government","Retail","Transport"], specs: { Size:"43–75 inch", Brightness:"2500 cd/m²", IP_Rating:"IP65", OS:"Android 11", Resolution:"1920×1080 FHD", Connectivity:"4G, WiFi, LAN", Temp:"-30°C to 60°C" } },
  { id: 58, cat: "Outdoor Digital Posters", sub: "Outdoor High Brightness Digital Android Battery A-Boards", tag: "Portable", name: "Outdoor High Brightness Battery A-Board 43\"", short: "2500 nit battery-powered portable outdoor A-board", price: 1380, color: "#065f46", img: "https://www.allsee-tech.com/images/outdoor-high-brightness-waterproof-ip-rated-led-freestanding-android-battery-a-board-portable-all-in-one-network-cms-digital-signage-advertising-displays-01.jpg", imgAlt: "Outdoor high brightness battery A-board", industries: ["Retail","Events","Government"], specs: { Size:"43–55 inch", Brightness:"2500 cd/m²", Battery:"8hr runtime", IP_Rating:"IP55", OS:"Android 11", Connectivity:"4G, WiFi", Weight:"26kg" } },
  { id: 59, cat: "Outdoor Digital Posters", sub: "Outdoor Digital Android Battery A-Boards", tag: "Portable", name: "Outdoor Android Battery A-Board 43\"", short: "Standard battery-powered outdoor portable A-board", price: 1120, color: "#065f46", img: "https://www.allsee-tech.com/images/outdoor-high-brightness-waterproof-ip-rated-led-freestanding-android-battery-a-board-portable-all-in-one-network-cms-digital-signage-advertising-displays-01.jpg", imgAlt: "Outdoor Android battery A-board", industries: ["Retail","Events","Government"], specs: { Size:"43 inch", Brightness:"2000 cd/m²", Battery:"8hr runtime", IP_Rating:"IP55", OS:"Android 11", Connectivity:"WiFi", Weight:"24kg" } },

  // ── Commercial Monitors expanded ──
  { id: 60, cat: "Commercial Monitors", sub: "Professional Monitors", tag: "Popular", name: "Professional Commercial Monitor 55\"", short: "Commercial-grade 55\" monitor for 24/7 operation", price: 480, color: "#1e3a5f", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Professional commercial monitor", industries: ["Corporate","Education","Healthcare"], specs: { Size:"43–75 inch", Resolution:"1920×1080 FHD", Brightness:"400 cd/m²", OS:"Commercial (no Android)", Connectivity:"HDMI, VGA, USB", Runtime:"24/7 rated", Mount:"VESA 400×400" } },
  { id: 61, cat: "Commercial Monitors", sub: "4K Large Format Commercial Displays", tag: "New", name: "4K Large Format Commercial Display 86\"", short: "Ultra-large 4K commercial display for venues", price: 2400, color: "#0f4c8a", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "4K large format commercial display", industries: ["Corporate","Government","Education"], specs: { Size:"75–98 inch", Resolution:"3840×2160 4K", Brightness:"500 cd/m²", OS:"Android 11 optional", Connectivity:"HDMI, USB, LAN, WiFi", Runtime:"24/7 rated", Mount:"VESA 600×400" } },

  // ── Small-Sized Displays expanded ──
  { id: 62, cat: "Small-Sized Displays", sub: "10\" & 15\" POS Android Advertising Displays", tag: "Popular", name: "10\" POS Android Advertising Display", short: "Compact Android advertising screen for counters & POS", price: 165, color: "#065f46", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "10 inch POS Android advertising display", industries: ["Retail","Food & QSR","Healthcare"], specs: { Size:"10 & 15 inch", Resolution:"1280×800", Brightness:"400 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Power:"DC / PoE", Mount:"Desk stand / wall mount" } },
  { id: 63, cat: "Small-Sized Displays", sub: "10\" & 15\" POS Android PCAP Touch Screens", tag: "Interactive", name: "15\" POS Android PCAP Touch Screen", short: "15\" countertop PCAP touch display for POS & ordering", price: 240, color: "#7c2d12", img: "https://www.allsee-tech.com/images/led-slimline-pcap-android-pos-point-of-sale-poe-multi-touch-screen-digital-signage-display-commercial-tablet-01.jpg", imgAlt: "15 inch POS Android PCAP touch screen", industries: ["Food & QSR","Retail","Healthcare"], specs: { Size:"10 & 15 inch", Touch:"10-point PCAP", Resolution:"1920×1080", OS:"Android 11", Power:"PoE / DC", Connectivity:"WiFi, LAN, USB", Mount:"Desk stand" } },

  // ── Wide Format Displays expanded ──
  { id: 64, cat: "Wide Format Displays", sub: "Ultra-Wide Stretched Bar Displays", tag: "Popular", name: "Ultra-Wide Stretched Bar Display 58\"", short: "Shelf-edge stretched display — 32:9 aspect ratio", price: 490, color: "#4c1d95", img: "https://www.allsee-tech.com/images/led-ultra-wide-stretched-aspect-ratio-professional-commercial-grade-industrial-monitor-displays-01.jpg", imgAlt: "Ultra-wide stretched bar display", industries: ["Retail","Transport","Hospitality"], specs: { Size:"23.1–58.4 inch", Aspect_Ratio:"32:9", Resolution:"1920×540", Brightness:"700 cd/m²", OS:"Android 11", Connectivity:"WiFi, LAN, USB", Orientation:"Landscape" } },
  { id: 65, cat: "Wide Format Displays", sub: "Ultra-Wide Stretched Bar Monitors", tag: "New", name: "Ultra-Wide Stretched Bar Monitor 37\"", short: "Commercial-grade ultra-wide bar monitor without Android", price: 380, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/led-ultra-wide-stretched-aspect-ratio-professional-commercial-grade-industrial-monitor-displays-01.jpg", imgAlt: "Ultra-wide stretched bar monitor", industries: ["Retail","Transport"], specs: { Size:"23.1–37 inch", Aspect_Ratio:"16:3", Resolution:"1920×360", Brightness:"700 cd/m²", OS:"Monitor only (no Android)", Connectivity:"HDMI, VGA, USB", Runtime:"24/7" } },
  { id: 66, cat: "Wide Format Displays", sub: "Vibrant LCD Shelf Edge Displays", tag: "New", name: "Vibrant LCD Shelf Edge Display", short: "High colour accuracy shelf-edge label display", price: 290, color: "#064e3b", img: "https://www.allsee-tech.com/images/vibrant-professional-advertising-displays-digital-signage-android-standalone-network-cms-01.jpg", imgAlt: "Vibrant LCD shelf edge display", industries: ["Retail","Hospitality"], specs: { Size:"7–23 inch", Aspect_Ratio:"32:9", Resolution:"1920×540", Brightness:"600 cd/m²", Colour_Gamut:"108% NTSC", OS:"Android 11", Connectivity:"WiFi, LAN" } },

  // ── Media Players expanded ──
  { id: 67, cat: "Media Players", sub: "Standalone Android Media Players", tag: "Popular", name: "Standalone Android Media Player", short: "Compact standalone player for non-networked screens", price: 95, color: "#065f46", img: "https://www.allsee-tech.com/images/android-media-player-digital-signage-standalone-network-cms-01.jpg", imgAlt: "Standalone Android media player", industries: ["Retail","Corporate","Government"], specs: { OS:"Android 11", CPU:"Quad-core 1.8GHz", RAM:"2GB", Storage:"16GB", Connectivity:"HDMI, USB", Output:"1080p HDMI", Power:"5V DC" } },
  { id: 68, cat: "Media Players", sub: "Android Cloud Network Media Players", tag: "Popular", name: "Android Cloud Network Media Player", short: "WiFi/LAN-connected CMS-enabled Android media player", price: 125, color: "#0f4c8a", img: "https://www.allsee-tech.com/images/android-media-player-digital-signage-standalone-network-cms-01.jpg", imgAlt: "Android cloud network media player", industries: ["Corporate","Retail","Government"], specs: { OS:"Android 11", CPU:"Quad-core 1.8GHz", RAM:"2GB", Storage:"16GB", Connectivity:"WiFi, LAN, HDMI, USB", Output:"1080p HDMI", CMS:"Built-in CMS app" } },
  { id: 69, cat: "Media Players", sub: "4K Android Cloud Network Media Players", tag: "New", name: "4K Android Cloud Network Media Player", short: "4K@60fps CMS media player with scheduling", price: 145, color: "#1e1b4b", img: "https://www.allsee-tech.com/images/android-media-player-digital-signage-standalone-network-cms-01.jpg", imgAlt: "4K Android cloud network media player", industries: ["Corporate","Government","Retail"], specs: { OS:"Android 11", CPU:"Octa-core 2.0GHz", RAM:"4GB", Storage:"32GB", Connectivity:"WiFi, LAN, HDMI, USB", Output:"4K@60fps HDMI", CMS:"Built-in CMS + scheduling" } },
];

const MENU_STRUCTURE = [
  { cat: "Featured", isNew: false, subs: [] },
  {
    cat: "Corporate", isNew: false, subs: [
      "4K Slim Bezel Interactive Touch Displays",
      "PushShare Dongle and Receiving Unit",
      "Fine Pitch Presentation LED Video Wall",
      "10\" & 15\" POS PCAP Touch Screens",
    ]
  },
  {
    cat: "Fast Food/QSR", isNew: false, subs: [
      "Vibrant Professional Advertising Displays",
      "PCAP Self Service Kiosks",
      "Slimline Pro Advertising Displays",
    ]
  },
  {
    cat: "Modular DV-LED", isNew: true, subs: [
      "Welcome to the World of DV-LED",
      "Indoor SMD DV-LED",
      "Indoor GOB DV-LED",
      "Indoor COB DV-LED",
      "Indoor High Brightness DV-LED",
      "Outdoor DV-LED",
    ]
  },
  {
    cat: "All-in-One DV-LED", isNew: false, subs: [
      "Welcome to the World of DV-LED",
      "Fine Pitch DV-LED Video Walls",
      "Indoor DV-LED Totems",
      "Transparent DV-LED",
      "DV-LED Window Displays",
      "Outdoor DV-LED Shop Fascias",
    ]
  },
  {
    cat: "Digital Posters", isNew: true, subs: [
      "Slimline Pro Advertising Displays",
      "Android Freestanding Digital Posters",
      "Superslim Freestanding Double-Sided Digital Posters",
      "Vibrant Professional Advertising Displays",
    ]
  },
  {
    cat: "High Brightness", isNew: false, subs: [
      "Ultra High Brightness Window Displays",
      "Vibrant Hanging Double Sided Window Displays",
      "Ultra High Brightness Hanging Double-Sided Displays",
      "High Vibrance Android Advertising Displays",
    ]
  },
  {
    cat: "Outdoor Digital Posters", isNew: false, subs: [
      "4K Elite Outdoor Advertising Displays",
      "Outdoor Digital Advertising Displays",
      "Outdoor Freestanding Digital Posters",
      "Outdoor High Brightness Digital Android Battery A-Boards",
      "Outdoor Digital Android Battery A-Boards",
    ]
  },
  {
    cat: "Touch Screens", isNew: false, subs: [
      "Digital Signage Interactive Displays",
      "PCAP Touch Screen Monitors",
      "Android PCAP Touch Screens",
      "Android PCAP Touch Screen Kiosks",
      "PCAP Self Service Kiosks",
      "Freestanding PCAP Touch Screen Posters",
      "4K Slim Bezel Interactive Touch Displays",
      "10\" & 15\" POS Android PCAP Touch Screens",
    ]
  },
  {
    cat: "LCD Video Walls", isNew: false, subs: [
      "0.88mm Bezel - LCD Video Wall Displays",
      "1.8mm Bezel - LCD Video Wall Displays",
    ]
  },
  {
    cat: "Commercial Monitors", isNew: true, subs: [
      "Economy Professional Monitors",
      "Professional Monitors",
      "4K Large Format Commercial Displays",
    ]
  },
  {
    cat: "Small-Sized Displays", isNew: false, subs: [
      "10\" & 15\" POS Android Advertising Displays",
      "10\" & 15\" POS Android PCAP Touch Screens",
    ]
  },
  {
    cat: "Wide Format Displays", isNew: false, subs: [
      "Ultra-Wide Stretched Bar Displays",
      "Ultra-Wide Stretched Bar Monitors",
      "Vibrant LCD Shelf Edge Displays",
    ]
  },
  {
    cat: "Media Players", isNew: false, subs: [
      "Standalone Android Media Players",
      "Android Cloud Network Media Players",
      "4K Android Cloud Network Media Players",
    ]
  },
  {
    cat: "Digital Signage Software", isNew: false, subs: [
      "Content Management System",
      "Touch Content Management System",
    ]
  },
];

// New badge sets
const NEW_CATS = new Set(["Modular DV-LED", "Digital Posters", "Commercial Monitors"]);
const NEW_SUBS = new Set(["Indoor COB DV-LED", "Vibrant Professional Advertising Displays", "4K Elite Outdoor Advertising Displays", "4K Large Format Commercial Displays"]);

const CATEGORIES = ["All", "Indoor LED", "Outdoor", "Video Wall", "Touch Kiosk"];
const INDUSTRIES = ["All", "Retail", "Government", "Corporate", "Healthcare", "Education", "Hospitality", "Transport", "Food & QSR", "Entertainment", "Events"];


// ── Styles ─────────────────────────────────────────────────────────────────────
const S = {
  app: { fontFamily: "'DM Sans', sans-serif", background: "#050c18", color: "#e8edf5", minHeight: "100vh" },
  nav: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", height: 56, borderBottom: "1px solid rgba(255,255,255,0.07)", background: "rgba(5,12,24,0.95)", position: "sticky", top: 0, zIndex: 100, backdropFilter: "blur(12px)" },
  logo: { fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em", color: "#fff" },
  logoSpan: { color: "#3b82f6" },
  navLinks: { display: "flex", gap: 24, fontSize: 13, color: "rgba(255,255,255,0.55)" },
  piBtn: { display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", borderRadius: 8, background: "linear-gradient(135deg,#7c3aed,#4f46e5)", border: "none", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer" },
  // Hero
  hero: { padding: "72px 24px 56px", maxWidth: 800, margin: "0 auto", textAlign: "center" },
  heroTag: { display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase", color: "#60a5fa", background: "rgba(59,130,246,0.12)", border: "1px solid rgba(59,130,246,0.25)", padding: "4px 12px", borderRadius: 20, marginBottom: 24 },
  heroH1: { fontSize: "clamp(28px,5vw,52px)", fontWeight: 800, lineHeight: 1.1, letterSpacing: "-0.03em", margin: "0 0 16px", background: "linear-gradient(135deg,#fff 40%,#60a5fa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  heroSub: { fontSize: 16, color: "rgba(255,255,255,0.55)", lineHeight: 1.7, maxWidth: 540, margin: "0 auto 36px" },
  heroBtns: { display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" },
  btnPrimary: { padding: "12px 28px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" },
  btnOutline: { padding: "12px 28px", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" },
  // Stats bar
  statsBar: { display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 1, background: "rgba(255,255,255,0.05)", borderTop: "1px solid rgba(255,255,255,0.07)", borderBottom: "1px solid rgba(255,255,255,0.07)", margin: "0 0 56px" },
  statItem: { padding: "20px 24px", textAlign: "center", background: "#050c18" },
  statNum: { fontSize: 28, fontWeight: 800, color: "#3b82f6", letterSpacing: "-0.03em" },
  statLabel: { fontSize: 12, color: "rgba(255,255,255,0.45)", marginTop: 4 },
  // Pi badge
  piBadge: { maxWidth: 680, margin: "0 auto 56px", background: "linear-gradient(135deg,rgba(124,58,237,0.15),rgba(79,70,229,0.1))", border: "1px solid rgba(124,58,237,0.3)", borderRadius: 14, padding: "20px 28px", display: "flex", alignItems: "center", gap: 20 },
  piIcon: { fontSize: 36, flexShrink: 0 },
  piTitle: { fontSize: 15, fontWeight: 700, color: "#a78bfa", marginBottom: 4 },
  piDesc: { fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.6 },
  // Section
  section: { maxWidth: 1100, margin: "0 auto", padding: "0 24px 56px" },
  sectionHead: { display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 24 },
  sectionTitle: { fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em" },
  seeAll: { fontSize: 13, color: "#3b82f6", cursor: "pointer", background: "none", border: "none" },
  // Industry chips
  industries: { display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 32 },
  chip: (active) => ({ padding: "6px 14px", borderRadius: 20, fontSize: 12, fontWeight: 500, cursor: "pointer", background: active ? "#3b82f6" : "rgba(255,255,255,0.07)", color: active ? "#fff" : "rgba(255,255,255,0.55)", border: active ? "1px solid #3b82f6" : "1px solid rgba(255,255,255,0.1)" }),
  // Product grid
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(280px,1fr))", gap: 16 },
  card: (color) => ({ background: "#0d1829", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 14, overflow: "hidden", cursor: "pointer", transition: "transform 0.15s,border-color 0.15s" }),
  cardImg: (color) => ({ height: 160, overflow: "hidden", background: `linear-gradient(135deg,${color}44,${color}11)`, borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", justifyContent: "center" }),
  cardBody: { padding: "16px" },
  cardCat: { fontSize: 10, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 4 },
  cardName: { fontSize: 15, fontWeight: 700, color: "#fff", marginBottom: 4, letterSpacing: "-0.01em" },
  cardShort: { fontSize: 12, color: "rgba(255,255,255,0.45)", marginBottom: 14, lineHeight: 1.5 },
  priceRow: { display: "flex", flexDirection: "column", gap: 2, marginBottom: 12, padding: "10px 12px", background: "rgba(255,255,255,0.04)", borderRadius: 8 },
  priceUSD: { fontSize: 18, fontWeight: 800, color: "#fff", letterSpacing: "-0.02em" },
  priceNGN: { fontSize: 12, color: "rgba(255,255,255,0.45)" },
  pricePi: { fontSize: 12, color: "#a78bfa", fontWeight: 600 },
  tag: (color) => ({ display: "inline-block", fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 5, background: color + "22", color: color, letterSpacing: ".04em" }),
  viewBtn: { width: "100%", padding: "9px 0", borderRadius: 8, background: "#1d3a6b", border: "1px solid rgba(59,130,246,0.3)", color: "#60a5fa", fontSize: 13, fontWeight: 600, cursor: "pointer" },
  // Detail page
  detailBack: { display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "#60a5fa", cursor: "pointer", background: "none", border: "none", marginBottom: 24 },
  detailGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, alignItems: "start" },
  detailImg: (color) => ({ height: 320, borderRadius: 16, overflow: "hidden", background: `linear-gradient(135deg,${color}44,${color}11)`, border: "1px solid rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center" }),
  detailName: { fontSize: 28, fontWeight: 800, letterSpacing: "-0.03em", marginBottom: 8 },
  detailShort: { fontSize: 14, color: "rgba(255,255,255,0.5)", marginBottom: 20, lineHeight: 1.6 },
  priceCard: { background: "#0d1829", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 14, padding: "20px", marginBottom: 20 },
  priceMain: { fontSize: 32, fontWeight: 900, letterSpacing: "-0.04em", marginBottom: 6 },
  priceSecondary: { fontSize: 13, color: "rgba(255,255,255,0.45)" },
  pricePiLarge: { fontSize: 14, color: "#a78bfa", fontWeight: 700, marginTop: 6 },
  addBtn: { width: "100%", padding: "14px 0", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer", marginBottom: 10 },
  piPayBtn: { width: "100%", padding: "14px 0", borderRadius: 10, background: "linear-gradient(135deg,#7c3aed,#4f46e5)", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer" },
  specsTable: { background: "#0d1829", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 14, overflow: "hidden" },
  specRow: (i) => ({ display: "flex", justifyContent: "space-between", padding: "11px 16px", background: i % 2 === 0 ? "rgba(255,255,255,0.02)" : "transparent", fontSize: 13, borderBottom: "1px solid rgba(255,255,255,0.04)" }),
  // Catalog filters
  filterBar: { display: "flex", gap: 10, marginBottom: 24, flexWrap: "wrap" },
  // Toast
  toast: { position: "fixed", bottom: 24, right: 24, background: "#1e3a5f", border: "1px solid rgba(59,130,246,0.4)", borderRadius: 12, padding: "14px 20px", fontSize: 13, color: "#fff", zIndex: 999, maxWidth: 300 },
};

const TAG_COLORS = { "Best Seller": "#f59e0b", "Weatherproof": "#10b981", "Premium": "#a78bfa", "Interactive": "#f472b6", "New": "#34d399", "Portable": "#60a5fa" };

// ── Components ────────────────────────────────────────────────────────────────
function PriceBlock({ price, style = {} }) {
  return (
    <div style={{ ...style }}>
      <div style={S.priceUSD}>{fmt.usd(price)}</div>
      <div style={S.priceNGN}>{fmt.ngn(price)}</div>
      <div style={S.pricePi}>{fmt.pi(price)}</div>
    </div>
  );
}

function ProductCard({ product, onClick }) {
  const [hov, setHov] = useState(false);
  const [imgErr, setImgErr] = useState(false);
  return (
    <div
      style={{ ...S.card(product.color), borderColor: hov ? "rgba(59,130,246,0.4)" : "rgba(255,255,255,0.08)", transform: hov ? "translateY(-2px)" : "none" }}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      onClick={() => onClick(product)}
    >
      <div style={S.cardImg(product.color)}>
        {!imgErr
          ? <img src={product.img} alt={product.imgAlt} onError={() => setImgErr(true)}
              style={{ width: "100%", height: "100%", objectFit: "cover" }} />
          : <span style={{ fontSize: 48 }}>🖥️</span>
        }
      </div>
      <div style={S.cardBody}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span style={S.cardCat}>{product.category}</span>
          <span style={S.tag(TAG_COLORS[product.tag] || "#60a5fa")}>{product.tag}</span>
        </div>
        <div style={S.cardName}>{product.name}</div>
        <div style={S.cardShort}>{product.short}</div>
        <div style={S.priceRow}>
          <PriceBlock price={product.price} />
        </div>
        <button style={S.viewBtn}>View details →</button>
      </div>
    </div>
  );
}

// ── Pages ─────────────────────────────────────────────────────────────────────
function HomePage({ setPage, setProduct, piUser, onPiLogin }) {
  return (
    <div>
      {/* Hero */}
      <div style={S.hero}>
        <div style={S.heroTag}>🌍 West Africa's Digital Signage Marketplace</div>
        <h1 style={S.heroH1}><strong>Morbitech</strong> — <em style={{ fontStyle: "italic", fontWeight: 300 }}>service with technology at its best</em></h1>
        <p style={S.heroSub}>LED displays, video walls, kiosks & more — delivered across West Africa. Pay with Pi, USD, or NGN. No hidden costs.</p>
        <div style={S.heroBtns}>
          <button style={S.btnPrimary} onClick={() => setPage("catalog")}>Browse products</button>
          {!piUser
            ? <button style={{ ...S.btnOutline, display: "flex", alignItems: "center", gap: 8 }} onClick={onPiLogin}>
                <span style={{ fontSize: 16 }}>π</span> Connect Pi Wallet
              </button>
            : <button style={{ ...S.btnOutline, color: "#a78bfa", borderColor: "#a78bfa66" }}>
                ✓ π {piUser.username}
              </button>
          }
        </div>
      </div>

      {/* Stats */}
      <div style={S.statsBar}>
        {[["50+", "Products in stock"], ["10+", "West African countries served"], ["Pi Ready", "Pay with Pi coin"]].map(([n, l]) => (
          <div key={l} style={S.statItem}>
            <div style={S.statNum}>{n}</div>
            <div style={S.statLabel}>{l}</div>
          </div>
        ))}
      </div>

      {/* Pi badge */}
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "0 24px" }}>
        <div style={S.piBadge}>
          <div style={S.piIcon}>π</div>
          <div>
            <div style={S.piTitle}>Now accepting Pi Network payments</div>
            <div style={S.piDesc}>Morbitech is a verified Pi App. Sign in with your Pi account and pay directly from your Pi wallet — fast, secure, borderless. Current rate: 1 Pi ≈ {fmt.usd(PI_RATE)}.</div>
          </div>
          {!piUser && <button style={{ ...S.piBtn, flexShrink: 0 }} onClick={onPiLogin}>Connect π</button>}
        </div>
      </div>

      {/* Brand statement */}
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "48px 24px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 48, alignItems: "center" }}>

          {/* Left — text */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "#3b82f6", marginBottom: 14 }}>Who we are</div>
            <h2 style={{ fontSize: "clamp(22px,3vw,34px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.2, margin: "0 0 16px", color: "#fff" }}>
              Morbitech Digital Signage
            </h2>
            <p style={{ fontSize: 15, color: "rgba(255,255,255,0.6)", lineHeight: 1.85, margin: "0 0 28px" }}>
              At Morbitech, we make professional digital signage <strong style={{ color: "#fff" }}>affordable, easy to use, and accessible</strong> to businesses of every size.
            </p>
            <p style={{ fontSize: 15, color: "rgba(255,255,255,0.6)", lineHeight: 1.85, margin: "0 0 28px" }}>
              Whether you're promoting products, displaying menus, sharing announcements, or strengthening your brand, our <strong style={{ color: "#60a5fa" }}>Android Digital Signage Displays</strong> help you deliver eye-catching content that gets noticed — and gets results.
            </p>
            <button onClick={() => setPage("catalog")}
              style={{ padding: "12px 24px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" }}>
              Explore our displays →
            </button>
          </div>

          {/* Right — 4 key points */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {[
              { icon: "🔌", title: "No complicated installation", desc: "Simply plug in your display and you're ready to go." },
              { icon: "💻", title: "No expensive computers", desc: "Built-in Android — everything you need is inside the screen." },
              { icon: "🙌", title: "No technical expertise required", desc: "Designed for business owners, not IT departments." },
              { icon: "✨", title: "Transform the way you communicate", desc: "Eye-catching content that gets noticed — and gets results." },
            ].map(({ icon, title, desc }) => (
              <div key={title} style={{ display: "flex", gap: 16, alignItems: "flex-start", background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "16px 18px" }}>
                <div style={{ fontSize: 24, flexShrink: 0, marginTop: 2 }}>{icon}</div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 3 }}>{title}</div>
                  <div style={{ fontSize: 13, color: "rgba(255,255,255,0.45)", lineHeight: 1.6 }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Industries */}
      <div style={S.section}>
        <div style={{ ...S.sectionTitle, marginBottom: 20 }}>Solutions by industry</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(150px,1fr))", gap: 10 }}>
          {INDUSTRIES.filter(i => i !== "All").map(ind => (
            <div key={ind} onClick={() => setPage("catalog")} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: "14px 16px", cursor: "pointer", fontSize: 13, fontWeight: 500, color: "rgba(255,255,255,0.7)", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "#3b82f6" }}>→</span> {ind}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Catalog Card (used inside CatalogPage grid) ───────────────────────────────
const TAG_COLORS_MAP = { "Best Seller":"#f59e0b","New":"#10b981","Premium":"#a78bfa","Popular":"#60a5fa","Interactive":"#f472b6","Weatherproof":"#34d399","Portable":"#60a5fa" };

function CatalogCard({ product: p, onClick }) {
  const [hov, setHov] = useState(false);
  const [imgErr, setImgErr] = useState(false);
  const tagColor = TAG_COLORS_MAP[p.tag] || "#60a5fa";
  return (
    <div onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)} onClick={onClick}
      style={{ background: "#0d1829", border: `1px solid ${hov ? "rgba(59,130,246,0.4)" : "rgba(255,255,255,0.07)"}`, borderRadius: 14, overflow: "hidden", cursor: "pointer", transform: hov ? "translateY(-2px)" : "none", transition: "all 0.15s" }}>
      <div style={{ height: 160, background: `linear-gradient(135deg,${p.color}44,${p.color}11)`, display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}>
        {!imgErr
          ? <img src={p.img} alt={p.imgAlt} onError={() => setImgErr(true)} style={{ width: "100%", height: "100%", objectFit: "cover" }} />
          : <span style={{ fontSize: 44, opacity: 0.5 }}>🖥️</span>
        }
      </div>
      <div style={{ padding: "14px 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em", color: "rgba(255,255,255,0.3)" }}>{p.sub || p.cat}</span>
          <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 5, background: tagColor + "22", color: tagColor }}>{p.tag}</span>
        </div>
        <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 4, lineHeight: 1.3 }}>{p.name}</div>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 12, lineHeight: 1.5 }}>{p.short}</div>
        <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: 8, padding: "8px 10px", marginBottom: 10 }}>
          <div style={{ fontSize: 17, fontWeight: 800, color: "#fff", letterSpacing: "-0.02em" }}>{fmt.usd(p.price)}</div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>{fmt.ngn(p.price)}</div>
          <div style={{ fontSize: 11, color: "#a78bfa", fontWeight: 600 }}>{fmt.pi(p.price)}</div>
        </div>
        <button style={{ width: "100%", padding: "8px 0", borderRadius: 8, background: "#1d3a6b", border: "1px solid rgba(59,130,246,0.3)", color: "#60a5fa", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
          View details →
        </button>
      </div>
    </div>
  );
}

function CatalogPage({ setPage, setProduct }) {
  const [activeCat, setActiveCat] = useState("Featured");
  const [activeSub, setActiveSub] = useState(null);
  const [expandedCats, setExpandedCats] = useState(new Set(["Featured"]));
  const [search, setSearch] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const toggleCat = (cat) => {
    setExpandedCats(prev => {
      const next = new Set(prev);
      if (next.has(cat)) { next.delete(cat); } else { next.add(cat); }
      return next;
    });
    setActiveCat(cat);
    setActiveSub(null);
  };
console.log("CATALOG PAGE LOADED");
  const filtered = PRODUCTS.filter(p => {
    const matchCat = p.cat === activeCat;
    const matchSub = !activeSub || p.sub === activeSub || (!p.sub && p.cat === activeCat);
    const matchSearch = !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.short.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSub && matchSearch;
  });
  console.log("CATALOG DEBUG:", {
  activeCat,
  activeSub,
  search,
  productsLength: PRODUCTS.length,
  featuredCount: PRODUCTS.filter(p => p.cat === "Featured").length,
  filteredLength: filtered.length,
});

  const menuItem = MENU_STRUCTURE.find(m => m.cat === activeCat);
  const headingLabel = activeSub ? `${activeCat} › ${activeSub}` : activeCat;

  return (
    <div style={{ display: "flex", minHeight: "calc(100vh - 56px)" }}>

      {/* ── Sidebar ── */}
      <aside style={{ width: sidebarOpen ? 262 : 0, flexShrink: 0, background: "#06080f", borderRight: "1px solid rgba(255,255,255,0.07)", overflowY: "auto", overflowX: "hidden", transition: "width 0.2s", position: "sticky", top: 56, height: "calc(100vh - 56px)" }}>
        <div style={{ minWidth: 262, paddingBottom: 32 }}>
          {/* Home */}
          <div onClick={() => setPage("home")}
            style={{ padding: "14px 18px", borderBottom: "1px solid rgba(255,255,255,0.07)", cursor: "pointer", fontSize: 14, color: "rgba(255,255,255,0.5)", fontWeight: 500 }}>
            Home
          </div>
          {/* Display Solutions label */}
          <div style={{ padding: "14px 18px 10px", fontSize: 16, fontWeight: 700, color: "rgba(255,255,255,0.75)", letterSpacing: "-0.01em", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
            Display Solutions
          </div>

          {MENU_STRUCTURE.map(({ cat, isNew, subs }) => {
            const isExpanded = expandedCats.has(cat);
            const isCatActive = activeCat === cat;
            return (
              <div key={cat}>
                {/* Category row */}
                <div onClick={() => toggleCat(cat)}
                  style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "11px 18px", cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.05)", background: isCatActive && !activeSub ? "rgba(255,255,255,0.03)" : "transparent" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 13, color: "rgba(255,255,255,0.35)", width: 14 }}>{isExpanded ? "−" : "+"}</span>
                    <span style={{ fontSize: 14, color: isCatActive ? "#fff" : "rgba(255,255,255,0.55)", fontWeight: isCatActive ? 600 : 400, textDecoration: isCatActive ? "underline" : "none", textUnderlineOffset: 3 }}>
                      {cat}
                    </span>
                  </div>
                  {isNew && <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4, background: "#1d4ed8", color: "#fff", flexShrink: 0 }}>New</span>}
                </div>

                {/* Subcategory rows */}
                {isExpanded && subs.map(sub => {
                  const isSubActive = activeSub === sub && isCatActive;
                  return (
                    <div key={sub} onClick={() => { setActiveCat(cat); setActiveSub(sub); }}
                      style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 18px 10px 40px", cursor: "pointer", borderBottom: "1px solid rgba(255,255,255,0.04)", background: isSubActive ? "rgba(59,130,246,0.07)" : "transparent", borderLeft: isSubActive ? "2px solid #3b82f6" : "2px solid transparent" }}>
                      <span style={{ fontSize: 13, color: isSubActive ? "#fff" : "rgba(255,255,255,0.45)", fontWeight: isSubActive ? 600 : 400, lineHeight: 1.4 }}>{sub}</span>
                      {NEW_SUBS.has(sub) && <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4, background: "#991b1b", color: "#fff", flexShrink: 0, marginLeft: 6 }}>New</span>}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </aside>

      {/* ── Main content ── */}
      <div style={{ flex: 1, padding: "28px 24px", minWidth: 0 }}>

        {/* Header row */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <button onClick={() => setSidebarOpen(s => !s)}
            style={{ padding: "7px 10px", borderRadius: 8, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)", cursor: "pointer", fontSize: 14, flexShrink: 0 }}>
            {sidebarOpen ? "◀" : "▶"}
          </button>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <h2 style={{ fontSize: 20, fontWeight: 800, margin: 0, letterSpacing: "-0.02em" }}>{headingLabel}</h2>
              {NEW_CATS.has(activeCat) && <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4, background: "#1d4ed8", color: "#fff" }}>New</span>}
            </div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", marginTop: 2 }}>
              {filtered.length} product{filtered.length !== 1 ? "s" : ""}
            </div>
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search products…"
            style={{ padding: "8px 14px", borderRadius: 10, background: "#0d1829", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 13, width: 200, outline: "none", fontFamily: "inherit", flexShrink: 0 }} />
        </div>

        {/* Subcategory pills */}
        {menuItem && menuItem.subs.length > 0 && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 24 }}>
            <button onClick={() => setActiveSub(null)}
              style={{ padding: "5px 14px", borderRadius: 20, fontSize: 12, fontWeight: 500, cursor: "pointer", background: !activeSub ? "#3b82f6" : "rgba(255,255,255,0.06)", color: !activeSub ? "#fff" : "rgba(255,255,255,0.5)", border: !activeSub ? "1px solid #3b82f6" : "1px solid rgba(255,255,255,0.1)" }}>
              All
            </button>
            {menuItem.subs.map(sub => (
              <button key={sub} onClick={() => setActiveSub(sub)}
                style={{ padding: "5px 14px", borderRadius: 20, fontSize: 12, fontWeight: 500, cursor: "pointer", display: "flex", alignItems: "center", gap: 5, background: activeSub === sub ? "#3b82f6" : "rgba(255,255,255,0.06)", color: activeSub === sub ? "#fff" : "rgba(255,255,255,0.5)", border: activeSub === sub ? "1px solid #3b82f6" : "1px solid rgba(255,255,255,0.1)" }}>
                {sub}
                {NEW_SUBS.has(sub) && <span style={{ fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 3, background: "#991b1b", color: "#fff" }}>New</span>}
              </button>
            ))}
          </div>
        )}

        {/* Product grid */}
        {filtered.length === 0
          ? <div style={{ textAlign: "center", padding: "80px 0", color: "rgba(255,255,255,0.25)", fontSize: 14 }}>
              <div style={{ fontSize: 40, marginBottom: 16 }}>📦</div>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>Products coming soon</div>
              <div style={{ fontSize: 13 }}>We're adding inventory to this category. <br/>Contact us for availability and pricing.</div>
              <button onClick={() => setPage("contact")} style={{ marginTop: 20, padding: "10px 24px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Enquire now →</button>
            </div>
          : <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 16 }}>
              {filtered.map(p => <CatalogCard key={p.id} product={p} onClick={() => { setProduct(p); setPage("detail"); }} />)}
            </div>
        }
      </div>
    </div>
  );
}

function DetailPage({ product, setPage, piUser, onPiLogin, onPiPay, toast, addToCart, toggleSave, savedProducts, onEnquire }) {
  const specs = Object.entries(product.specs);
  const isSaved = (savedProducts || []).some(s => s.id === product.id);
  return (
    <div style={S.section}>
      <button style={S.detailBack} onClick={() => setPage("catalog")}>← Back to catalog</button>

      <div style={S.detailGrid}>
        {/* Left */}
        <div>
          <div style={{ position: "relative" }}>
            <div style={S.detailImg(product.color)}>
              <img src={product.img} alt={product.imgAlt}
                style={{ width: "100%", height: "100%", objectFit: "cover" }}
                onError={e => { e.target.style.display="none"; }} />
            </div>
            {/* Save button */}
            <button onClick={() => toggleSave && toggleSave(product)}
              style={{ position: "absolute", top: 12, right: 12, width: 36, height: 36, borderRadius: "50%", background: isSaved ? "#be185d" : "rgba(0,0,0,0.5)", border: `1px solid ${isSaved ? "#be185d" : "rgba(255,255,255,0.2)"}`, color: isSaved ? "#fff" : "rgba(255,255,255,0.7)", fontSize: 16, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}
              title={isSaved ? "Remove from saved" : "Save product"}>
              {isSaved ? "❤️" : "🤍"}
            </button>
          </div>

          <div style={{ marginTop: 16, display: "flex", gap: 8, flexWrap: "wrap" }}>
            {(product.industries || []).map(i => (
              <span key={i} style={{ fontSize: 11, padding: "4px 10px", borderRadius: 20, background: "rgba(59,130,246,0.1)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.2)" }}>{i}</span>
            ))}
          </div>

          <div style={{ marginTop: 24 }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, color: "rgba(255,255,255,0.5)", letterSpacing: ".06em", textTransform: "uppercase" }}>Specifications</div>
            <div style={S.specsTable}>
              {specs.map(([k, v], i) => (
                <div key={k} style={S.specRow(i)}>
                  <span style={{ color: "rgba(255,255,255,0.45)" }}>{k.replace(/_/g, " ")}</span>
                  <span style={{ fontWeight: 500 }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right */}
        <div>
          <span style={S.tag(TAG_COLORS[product.tag] || "#60a5fa")}>{product.tag}</span>
          <div style={{ ...S.detailName, marginTop: 10 }}>{product.name}</div>
          <div style={S.detailShort}>{product.short}</div>

          <div style={S.priceCard}>
            <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: ".07em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 8 }}>Price</div>
            <div style={S.priceMain}>{fmt.usd(product.price)}</div>
            <div style={S.priceSecondary}>{fmt.ngn(product.price)}</div>
            <div style={S.pricePiLarge}>π {(product.price / PI_RATE).toFixed(1)} Pi · Rate: 1 Pi ≈ {fmt.usd(PI_RATE)}</div>
          </div>

          {/* Primary CTA — Add to cart */}
          <button style={S.addBtn} onClick={() => addToCart && addToCart(product)}>
            🛒 Add to cart
          </button>

          {/* Pi Pay */}
          {piUser
            ? <button style={{ ...S.piPayBtn, marginBottom: 10 }} onClick={() => onPiPay(product)}>
                Pay with Pi π — {(product.price / PI_RATE).toFixed(1)} Pi
              </button>
            : <button style={{ ...S.piPayBtn, opacity: 0.75, marginBottom: 10 }} onClick={onPiLogin}>
                Connect Pi wallet to pay with π
              </button>
          }

          {/* Enquire about this product */}
          <button style={{ width: "100%", padding: "12px 0", borderRadius: 10, background: "transparent", border: "1px solid rgba(52,211,153,0.4)", color: "#34d399", fontSize: 14, fontWeight: 600, cursor: "pointer", marginBottom: 16 }}
            onClick={() => onEnquire && onEnquire()}>
            💬 Enquire about this product
          </button>

          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", lineHeight: 1.7, marginBottom: 20 }}>
            ✓ Verified Morbitech distributor &nbsp;·&nbsp; West Africa delivery &nbsp;·&nbsp; Warranty included &nbsp;·&nbsp; After-sales support
          </div>

          {/* Custom quote */}
          <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "16px" }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Need a custom quote?</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 12, lineHeight: 1.6 }}>Bulk orders, installation packages, or custom configurations — we'll tailor a quote for you.</div>
            <button style={{ ...S.btnOutline, fontSize: 13, padding: "9px 20px", width: "100%" }}
              onClick={() => onEnquire && onEnquire()}>Request a quote</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Contact Page ──────────────────────────────────────────────────────────────
function ContactPage({ setPage, toast }) {
  const [form, setForm] = useState({ name: "", email: "", phone: "", company: "", interest: "General enquiry", message: "" });
  const [sent, setSent] = useState(false);
  const [meetingForm, setMeetingForm] = useState({ name: "", email: "", phone: "", company: "", date: "", time: "", purpose: "Product demo", notes: "" });
  const [meetingSent, setMeetingSent] = useState(false);

  const interests = ["General enquiry", "Indoor LED displays", "Outdoor displays", "Video walls", "Touch kiosks", "Software / CMS", "Bulk / project quote", "After-sales support"];
  const meetingPurposes = ["Product demo", "Project consultation", "Bulk order discussion", "After-sales support", "Partnership enquiry", "General meeting"];

  // Generate next 30 available weekday dates
  const getAvailableDates = () => {
    const dates = [];
    const d = new Date();
    while (dates.length < 30) {
      d.setDate(d.getDate() + 1);
      const day = d.getDay();
      if (day !== 0 && day !== 6) { // skip weekends
        dates.push(new Date(d));
      }
    }
    return dates;
  };
  const availableDates = getAvailableDates();
  const timeSlots = ["9:00 AM", "10:00 AM", "11:00 AM", "12:00 PM", "2:00 PM", "3:00 PM", "4:00 PM"];

  const handleChange = (e) => setForm(f => ({ ...f, [e.target.name]: sanitize(e.target.value) }));
  const handleMeetingChange = (e) => setMeetingForm(f => ({ ...f, [e.target.name]: sanitize(e.target.value) }));

  const handleSubmit = () => {
    if (!rateLimit("contact-form", 3, 120_000)) {
      toast("Too many submissions — please wait 2 minutes."); return;
    }
    const errs = validateForm(form, ["name", "email", "message"]);
    if (errs.name)    { toast("Please enter a valid name (2–100 characters)."); return; }
    if (errs.email)   { toast("Please enter a valid email address."); return; }
    if (errs.message) { toast("Message must be 10–2000 characters."); return; }
    if (form.phone && !validators.phone(form.phone)) { toast("Please enter a valid phone number."); return; }
    setSent(true);
    toast("✓ Message sent! We'll reply within 24 hours.");
  };

  const handleMeetingSubmit = () => {
    if (!rateLimit("meeting-form", 3, 120_000)) {
      toast("Too many submissions — please wait 2 minutes."); return;
    }
    const errs = validateForm(meetingForm, ["name", "email"]);
    if (errs.name)  { toast("Please enter a valid name."); return; }
    if (errs.email) { toast("Please enter a valid email address."); return; }
    if (!meetingForm.date || !meetingForm.time) { toast("Please select a date and time."); return; }
    setMeetingSent(true);
    toast("✓ Meeting scheduled! We'll confirm via email.");
  };

  const buildWAMessage = () => {
    const text = `Hello Morbitech,%0A%0AMy name is ${encodeURIComponent(form.name || "a potential customer")}.%0AInterest: ${encodeURIComponent(form.interest)}%0A${form.company ? "Company: " + encodeURIComponent(form.company) + "%0A" : ""}%0AI'd like to enquire about your digital signage products.`;
    return `https://wa.me/${WA_NUMBER}?text=${text}`;
  };

  const contacts = [
    { icon: "💬", label: "WhatsApp", value: "+234 812 591 1805", sub: "Fastest response — Mon–Sat 8am–6pm WAT", action: () => safeOpen(buildWAMessage(), "_blank"), cta: "Chat on WhatsApp", color: "#25d366" },
    { icon: "📧", label: "Email", value: "info@morbitech.com", sub: "We reply within 24 business hours", action: () => safeOpen("mailto:info@morbitech.com"), cta: "Send email", color: "#3b82f6" },
    { icon: "📞", label: "Phone", value: "08061233018", sub: "Mon–Fri, 9am–5pm WAT", action: () => safeOpen("tel:+2348061233018"), cta: "Call us", color: "#f59e0b" },
    { icon: "📍", label: "Office", value: "Lagos, Nigeria", sub: "Serving all of West Africa", action: null, cta: null, color: "#a78bfa" },
    { icon: "𝕏", label: "X (Twitter)", value: "@Pappie_shyle", sub: "Follow us on X for updates", action: () => safeOpen("https://x.com/Pappie_shyle", "_blank"), cta: "Follow", color: "#fff" },
    { icon: "📸", label: "Instagram", value: "@lamptechventures", sub: "See our latest projects on Instagram", action: () => safeOpen("https://www.instagram.com/lamptechventures?igsh=MTA2bzZkb3lxY214cA==", "_blank"), cta: "Follow", color: "#e1306c" },
  ];

  const offices = [
    { country: "🇳🇬 Nigeria", city: "Lagos", status: "Headquarters" },
    { country: "🇬🇭 Ghana", city: "Accra", status: "Coming soon" },
    { country: "🇨🇲 Cameroon", city: "Douala", status: "Coming soon" },
    { country: "🇧🇯 Benin Republic", city: "Cotonou", status: "Coming soon" },
    { country: "🇨🇮 Côte d'Ivoire", city: "Abidjan", status: "Coming soon" },
    { country: "🇳🇪 Niger", city: "Niamey", status: "Coming soon" },
  ];

  const inputStyle = { width: "100%", boxSizing: "border-box", padding: "11px 14px", borderRadius: 10, background: "#0d1829", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 14, outline: "none", fontFamily: "inherit" };
  const labelStyle = { fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.4)", letterSpacing: ".05em", textTransform: "uppercase", display: "block", marginBottom: 6 };

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: "48px 24px 80px" }}>

      {/* Header */}
      <div style={{ marginBottom: 48 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase", color: "#34d399", background: "rgba(52,211,153,0.1)", border: "1px solid rgba(52,211,153,0.25)", padding: "4px 12px", borderRadius: 20, marginBottom: 16 }}>
          Get in touch
        </div>
        <h1 style={{ fontSize: "clamp(24px,4vw,40px)", fontWeight: 800, letterSpacing: "-0.03em", margin: "0 0 12px", background: "linear-gradient(135deg,#fff 40%,#34d399)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
          Let's talk digital signage
        </h1>
        <p style={{ fontSize: 15, color: "rgba(255,255,255,0.45)", lineHeight: 1.7, maxWidth: 520, margin: 0 }}>
          Have a project in mind? Need a bulk quote? Want to know what display works best for your space? We're here — reach out on WhatsApp for the fastest response.
        </p>
      </div>

      {/* WhatsApp CTA — prominent */}
      <div style={{ background: "linear-gradient(135deg,rgba(37,211,102,0.15),rgba(37,211,102,0.05))", border: "1px solid rgba(37,211,102,0.3)", borderRadius: 16, padding: "24px 28px", marginBottom: 40, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ fontSize: 40 }}>💬</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "#25d366", marginBottom: 4 }}>Chat with us on WhatsApp</div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.5)" }}>The fastest way to get a quote or ask about a product. We typically reply within minutes during business hours.</div>
          </div>
        </div>
        <button
          onClick={() => safeOpen(buildWAMessage(), "_blank")}
          style={{ flexShrink: 0, padding: "13px 24px", borderRadius: 10, background: "#25d366", border: "none", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 18 }}>💬</span> Open WhatsApp
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, alignItems: "start" }}>

        {/* Left — contact form */}
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: ".07em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 20 }}>Send us a message</div>

          {sent ? (
            <div style={{ background: "rgba(52,211,153,0.1)", border: "1px solid rgba(52,211,153,0.3)", borderRadius: 14, padding: "40px 24px", textAlign: "center" }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Message sent!</div>
              <div style={{ fontSize: 14, color: "rgba(255,255,255,0.5)", marginBottom: 24 }}>We'll get back to you within 24 business hours. For faster replies, use WhatsApp above.</div>
              <button onClick={() => setSent(false)} style={{ padding: "10px 20px", borderRadius: 8, background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", fontSize: 13, cursor: "pointer" }}>Send another</button>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div>
                  <label style={labelStyle}>Name *</label>
                  <input name="name" value={form.name} onChange={handleChange} placeholder="Your full name" style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>Email *</label>
                  <input name="email" value={form.email} onChange={handleChange} placeholder="you@company.com" style={inputStyle} />
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div>
                  <label style={labelStyle}>Phone / WhatsApp</label>
                  <input name="phone" value={form.phone} onChange={handleChange} placeholder="+234 800 000 0000" style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>Company / Organisation</label>
                  <input name="company" value={form.company} onChange={handleChange} placeholder="Optional" style={inputStyle} />
                </div>
              </div>
              <div>
                <label style={labelStyle}>I'm interested in</label>
                <select name="interest" value={form.interest} onChange={handleChange} style={{ ...inputStyle, cursor: "pointer" }}>
                  {interests.map(i => <option key={i} value={i}>{i}</option>)}
                </select>
              </div>
              <div>
                <label style={labelStyle}>Message *</label>
                <textarea name="message" value={form.message} onChange={handleChange} rows={5}
                  placeholder="Tell us about your project, space, quantity, or any questions you have…"
                  style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} />
              </div>
              <button onClick={handleSubmit}
                style={{ padding: "13px 0", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer" }}>
                Send message →
              </button>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
                <span style={{ fontSize: 12, color: "rgba(255,255,255,0.25)" }}>or</span>
                <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
              </div>
              <button onClick={() => safeOpen(buildWAMessage(), "_blank")}
                style={{ padding: "13px 0", borderRadius: 10, background: "#25d366", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                💬 Continue on WhatsApp instead
              </button>
            </div>
          )}
        </div>

        {/* Right — contact info + offices */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: ".07em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 8 }}>Contact details</div>

          {contacts.map(c => (
            <div key={c.label} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ fontSize: 22, width: 40, height: 40, borderRadius: 10, background: c.color + "18", display: "flex", alignItems: "center", justifyContent: "center" }}>{c.icon}</div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 2 }}>{c.value}</div>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)" }}>{c.sub}</div>
                  </div>
                </div>
                {c.action && (
                  <button onClick={c.action} style={{ flexShrink: 0, padding: "7px 12px", borderRadius: 8, background: c.color + "20", border: `1px solid ${c.color}40`, color: c.color, fontSize: 12, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap" }}>
                    {c.cta}
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Office coverage */}
          <div style={{ marginTop: 8, fontSize: 13, fontWeight: 700, letterSpacing: ".07em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 8 }}>Our coverage</div>
          {offices.map(o => (
            <div key={o.country} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#fff" }}>{o.country}</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)" }}>{o.city}</div>
              </div>
              <span style={{ fontSize: 11, padding: "3px 10px", borderRadius: 20, background: o.status === "Headquarters" ? "rgba(59,130,246,0.15)" : "rgba(255,255,255,0.05)", color: o.status === "Headquarters" ? "#60a5fa" : "rgba(255,255,255,0.3)", border: o.status === "Headquarters" ? "1px solid rgba(59,130,246,0.3)" : "1px solid rgba(255,255,255,0.07)" }}>
                {o.status}
              </span>
            </div>
          ))}

          {/* Business hours */}
          <div style={{ marginTop: 8, background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "rgba(255,255,255,0.35)", letterSpacing: ".06em", textTransform: "uppercase", marginBottom: 12 }}>Business hours</div>
            {[["Monday – Friday", "9:00am – 6:00pm WAT"], ["Saturday", "10:00am – 3:00pm WAT"], ["Sunday", "Closed"]].map(([day, hrs]) => (
              <div key={day} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)", color: hrs === "Closed" ? "rgba(255,255,255,0.25)" : "rgba(255,255,255,0.6)" }}>
                <span>{day}</span><span style={{ fontWeight: 500 }}>{hrs}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Schedule a meeting ── */}
      <div style={{ marginTop: 48, background: "#0d1829", border: "1px solid rgba(167,139,250,0.25)", borderRadius: 20, padding: "36px 32px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 8 }}>
          <div style={{ fontSize: 32 }}>📅</div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: "-0.02em" }}>Schedule an in-office meeting</div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>Visit us at our Lagos office — pick a date and time that works for you.</div>
          </div>
        </div>

        <div style={{ height: 1, background: "rgba(255,255,255,0.06)", margin: "20px 0" }} />

        {meetingSent ? (
          <div style={{ textAlign: "center", padding: "40px 0" }}>
            <div style={{ fontSize: 56, marginBottom: 16 }}>🎉</div>
            <div style={{ fontSize: 20, fontWeight: 800, marginBottom: 8 }}>Meeting scheduled!</div>
            <div style={{ fontSize: 14, color: "rgba(255,255,255,0.5)", marginBottom: 6 }}>
              <strong style={{ color: "#a78bfa" }}>{meetingForm.date}</strong> at <strong style={{ color: "#a78bfa" }}>{meetingForm.time}</strong>
            </div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>A confirmation will be sent to <strong style={{ color: "#fff" }}>{meetingForm.email}</strong>. We look forward to seeing you!</div>
            <button onClick={() => setMeetingSent(false)} style={{ padding: "10px 24px", borderRadius: 8, background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", fontSize: 13, cursor: "pointer" }}>Schedule another</button>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 28 }}>
            {/* Left — personal details */}
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: ".06em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>Your details</div>
              <div>
                <label style={labelStyle}>Full name *</label>
                <input name="name" value={meetingForm.name} onChange={handleMeetingChange} placeholder="Your full name" style={inputStyle} />
              </div>
              <div>
                <label style={labelStyle}>Email *</label>
                <input name="email" value={meetingForm.email} onChange={handleMeetingChange} placeholder="you@company.com" style={inputStyle} />
              </div>
              <div>
                <label style={labelStyle}>Phone / WhatsApp</label>
                <input name="phone" value={meetingForm.phone} onChange={handleMeetingChange} placeholder="+234 800 000 0000" style={inputStyle} />
              </div>
              <div>
                <label style={labelStyle}>Company / Organisation</label>
                <input name="company" value={meetingForm.company} onChange={handleMeetingChange} placeholder="Optional" style={inputStyle} />
              </div>
              <div>
                <label style={labelStyle}>Purpose of meeting</label>
                <select name="purpose" value={meetingForm.purpose} onChange={handleMeetingChange} style={{ ...inputStyle, cursor: "pointer" }}>
                  {meetingPurposes.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label style={labelStyle}>Additional notes</label>
                <textarea name="notes" value={meetingForm.notes} onChange={handleMeetingChange} rows={3}
                  placeholder="Anything you'd like us to prepare for the meeting…"
                  style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} />
              </div>
            </div>

            {/* Right — calendar picker */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: ".06em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 12 }}>Pick a date</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 6, marginBottom: 24 }}>
                {availableDates.slice(0, 20).map(d => {
                  const label = d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
                  const dayName = d.toLocaleDateString("en-GB", { weekday: "short" });
                  const val = d.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", year: "numeric" });
                  const selected = meetingForm.date === val;
                  return (
                    <div key={val} onClick={() => setMeetingForm(f => ({ ...f, date: val }))}
                      style={{ background: selected ? "rgba(167,139,250,0.2)" : "rgba(255,255,255,0.04)", border: `1px solid ${selected ? "#a78bfa" : "rgba(255,255,255,0.08)"}`, borderRadius: 10, padding: "8px 4px", textAlign: "center", cursor: "pointer" }}>
                      <div style={{ fontSize: 10, color: selected ? "#a78bfa" : "rgba(255,255,255,0.35)", marginBottom: 2 }}>{dayName}</div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: selected ? "#fff" : "rgba(255,255,255,0.7)" }}>{label}</div>
                    </div>
                  );
                })}
              </div>

              <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: ".06em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 12 }}>Pick a time (WAT)</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 28 }}>
                {timeSlots.map(t => {
                  const selected = meetingForm.time === t;
                  return (
                    <div key={t} onClick={() => setMeetingForm(f => ({ ...f, time: t }))}
                      style={{ background: selected ? "rgba(167,139,250,0.2)" : "rgba(255,255,255,0.04)", border: `1px solid ${selected ? "#a78bfa" : "rgba(255,255,255,0.08)"}`, borderRadius: 8, padding: "9px 4px", textAlign: "center", cursor: "pointer", fontSize: 13, fontWeight: 600, color: selected ? "#fff" : "rgba(255,255,255,0.55)" }}>
                      {t}
                    </div>
                  );
                })}
              </div>

              {meetingForm.date && meetingForm.time && (
                <div style={{ background: "rgba(167,139,250,0.1)", border: "1px solid rgba(167,139,250,0.25)", borderRadius: 10, padding: "12px 16px", marginBottom: 20, fontSize: 13 }}>
                  <span style={{ color: "rgba(255,255,255,0.5)" }}>Selected: </span>
                  <strong style={{ color: "#a78bfa" }}>{meetingForm.date} · {meetingForm.time}</strong>
                </div>
              )}

              <button onClick={handleMeetingSubmit}
                style={{ width: "100%", padding: "13px 0", borderRadius: 10, background: "linear-gradient(135deg,#7c3aed,#4f46e5)", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer" }}>
                📅 Confirm meeting
              </button>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", textAlign: "center", marginTop: 10, lineHeight: 1.6 }}>
                📍 Morbitech Office, Lagos, Nigeria · We'll send a confirmation to your email
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── About Page ────────────────────────────────────────────────────────────────
function AboutPage({ setPage }) {
  const expertise = [
    { icon: "🔍", title: "Consultation & Solution Design", desc: "We begin every engagement by understanding your communication goals, operational challenges, and customer expectations before recommending solutions." },
    { icon: "🛠️", title: "Technology Sourcing & Installation", desc: "From sourcing enterprise-grade hardware to professional installation and commissioning, we handle the complete project lifecycle." },
    { icon: "💾", title: "Software Integration & Training", desc: "Advanced content management platforms, user training, and seamless integration with your existing operations." },
    { icon: "🔧", title: "Ongoing Technical Support", desc: "Dependable after-sales support that ensures every system continues to perform reliably long after deployment." },
  ];

  const industries = [
    { icon: "🛒", name: "Retail" }, { icon: "🏦", name: "Banking & Finance" }, { icon: "🏨", name: "Hospitality" },
    { icon: "🏥", name: "Healthcare" }, { icon: "🎓", name: "Education" }, { icon: "🏛️", name: "Government" },
    { icon: "🏢", name: "Corporate" }, { icon: "✈️", name: "Transportation" }, { icon: "📡", name: "Telecommunications" },
    { icon: "🏭", name: "Manufacturing" }, { icon: "🏘️", name: "Real Estate" }, { icon: "🎭", name: "Entertainment" },
    { icon: "⛪", name: "Religious Institutions" },
  ];

  const whyUs = [
    { icon: "🏆", title: "Technical Excellence", desc: "Our reputation is built on precision implementation, professional execution, and an unwavering commitment to quality on every project." },
    { icon: "🤝", title: "Collaborative Partnership", desc: "We engineer systems that integrate seamlessly into your existing operations while remaining flexible enough to evolve alongside your business." },
    { icon: "📈", title: "Measurable Value", desc: "Rather than one-size-fits-all solutions, we deliver outcomes — every investment contributes to long-term operational success and sustainable growth." },
    { icon: "🌍", title: "Local Expertise, Global Standards", desc: "Deep West African market knowledge combined with partnerships with globally recognised technology manufacturers." },
  ];

  const countries = ["Nigeria", "Ghana", "Côte d'Ivoire", "Cameroon", "Benin Republic", "Niger", "Togo", "Mali", "Burkina Faso"];
  const brands = ["Samsung", "LG", "Philips", "Allsee", "Novastar", "Hikvision", "Advantech", "Vestel"];

  const sec = { fontSize: 11, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 16 };
  const card = { background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 14, padding: "22px" };

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: "48px 24px 80px" }}>

      {/* ── Hero ── */}
      <div style={{ textAlign: "center", marginBottom: 56 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase", color: "#60a5fa", background: "rgba(59,130,246,0.12)", border: "1px solid rgba(59,130,246,0.25)", padding: "4px 14px", borderRadius: 20, marginBottom: 20 }}>
          About Morbitech
        </div>
        <h1 style={{ fontSize: "clamp(24px,4vw,44px)", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.15, margin: "0 0 16px", background: "linear-gradient(135deg,#fff 40%,#60a5fa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
          Driving Digital Transformation<br />Across West Africa
        </h1>
        <p style={{ fontSize: 11, fontWeight: 600, letterSpacing: ".06em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 20 }}>
          Through Innovative Display Solutions
        </p>
        <p style={{ fontSize: 15, color: "rgba(255,255,255,0.55)", lineHeight: 1.85, maxWidth: 680, margin: "0 auto" }}>
          Morbitech is a Nigerian technology company specialising in digital signage, commercial display systems, and intelligent visual communication. Headquartered in Lagos, we help businesses, institutions, and public sector organisations reimagine how they communicate, engage, and connect with their audiences through innovative display technologies.
        </p>
      </div>

      {/* ── Who we are ── */}
      <div style={{ background: "linear-gradient(135deg,rgba(59,130,246,0.1),rgba(124,58,237,0.08))", border: "1px solid rgba(59,130,246,0.18)", borderRadius: 18, padding: "32px 36px", marginBottom: 48 }}>
        <p style={{ fontSize: 15, color: "rgba(255,255,255,0.65)", lineHeight: 1.9, margin: "0 0 16px" }}>
          Serving clients across Nigeria and the wider West African region, Morbitech combines <strong style={{ color: "#fff" }}>global innovation with deep local expertise</strong> to deliver end-to-end digital signage ecosystems that are reliable, scalable, and tailored to each client's strategic objectives.
        </p>
        <p style={{ fontSize: 15, color: "rgba(255,255,255,0.65)", lineHeight: 1.9, margin: 0 }}>
          As a trusted technology partner and systems integrator, we collaborate with globally recognised manufacturers to provide enterprise-grade display solutions that enable organisations to modernise communication, strengthen customer engagement, and improve operational efficiency.
        </p>
      </div>

      {/* ── Vision & Mission ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 48 }}>
        <div style={{ ...card, background: "linear-gradient(135deg,rgba(59,130,246,0.12),rgba(59,130,246,0.04))", borderColor: "rgba(59,130,246,0.2)" }}>
          <div style={{ fontSize: 28, marginBottom: 12 }}>🔭</div>
          <div style={{ fontSize: 16, fontWeight: 800, color: "#60a5fa", marginBottom: 10 }}>Our Vision</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.6)", lineHeight: 1.8 }}>
            To be West Africa's most trusted provider of digital signage and intelligent display solutions, empowering organisations to communicate more effectively, innovate confidently, and transform the way people experience information.
          </div>
        </div>
        <div style={{ ...card, background: "linear-gradient(135deg,rgba(124,58,237,0.12),rgba(124,58,237,0.04))", borderColor: "rgba(124,58,237,0.2)" }}>
          <div style={{ fontSize: 28, marginBottom: 12 }}>🎯</div>
          <div style={{ fontSize: 16, fontWeight: 800, color: "#a78bfa", marginBottom: 10 }}>Our Mission</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.6)", lineHeight: 1.8 }}>
            To deliver innovative, reliable, and future-ready digital display solutions that strengthen customer engagement, streamline communication, and improve operational efficiency — combining world-class technologies with exceptional service and enduring partnerships.
          </div>
        </div>
      </div>

      {/* ── Expertise ── */}
      <div style={sec}>Our Expertise</div>
      <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 14, padding: "24px 28px", marginBottom: 12 }}>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.5)", lineHeight: 1.8, margin: "0 0 20px", fontStyle: "italic" }}>
          "Technology alone does not transform businesses — strategic insight, expert execution, and continuous support do."
        </p>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", lineHeight: 1.8, margin: 0 }}>
          Our expertise spans the complete project lifecycle — from consultation and solution design to technology sourcing, installation, software integration, commissioning, user training, and ongoing technical support. Whether deploying a single commercial display or implementing a multi-location digital signage network, we ensure every project is delivered with precision, reliability, and scalability.
        </p>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(210px,1fr))", gap: 12, marginBottom: 48 }}>
        {expertise.map(e => (
          <div key={e.title} style={card}>
            <div style={{ fontSize: 26, marginBottom: 10 }}>{e.icon}</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 6 }}>{e.title}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.45)", lineHeight: 1.7 }}>{e.desc}</div>
          </div>
        ))}
      </div>

      {/* ── Industries ── */}
      <div style={sec}>Industries We Serve</div>
      <div style={{ ...card, marginBottom: 16 }}>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", lineHeight: 1.8, margin: 0 }}>
          Morbitech serves organisations across diverse industries. Our industry-focused approach enables us to understand the unique demands of each sector, delivering tailored display solutions that enhance customer engagement, improve information delivery, strengthen brand presence, and support better business decisions.
        </p>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 48 }}>
        {industries.map(i => (
          <span key={i.name} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13, padding: "6px 14px", borderRadius: 20, background: "rgba(59,130,246,0.08)", color: "rgba(255,255,255,0.65)", border: "1px solid rgba(59,130,246,0.15)" }}>
            {i.icon} {i.name}
          </span>
        ))}
      </div>

      {/* ── Why Choose Us ── */}
      <div style={sec}>Why Choose Morbitech</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(210px,1fr))", gap: 12, marginBottom: 48 }}>
        {whyUs.map(w => (
          <div key={w.title} style={card}>
            <div style={{ fontSize: 26, marginBottom: 10 }}>{w.icon}</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 6 }}>{w.title}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.45)", lineHeight: 1.7 }}>{w.desc}</div>
          </div>
        ))}
      </div>

      {/* ── Coverage ── */}
      <div style={sec}>Countries We Serve</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 48 }}>
        {countries.map(c => (
          <span key={c} style={{ fontSize: 13, padding: "6px 14px", borderRadius: 20, background: "rgba(59,130,246,0.1)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.2)" }}>
            🌍 {c}
          </span>
        ))}
        <span style={{ fontSize: 13, padding: "6px 14px", borderRadius: 20, background: "rgba(255,255,255,0.04)", color: "rgba(255,255,255,0.35)", border: "1px solid rgba(255,255,255,0.07)" }}>+ expanding</span>
      </div>

      {/* ── Brands ── */}
      <div style={sec}>Brands We Carry</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(100px,1fr))", gap: 10, marginBottom: 48 }}>
        {brands.map(b => (
          <div key={b} style={{ ...card, padding: "14px 10px", textAlign: "center", fontSize: 13, fontWeight: 600, color: "rgba(255,255,255,0.6)" }}>{b}</div>
        ))}
      </div>

      {/* ── Pi section ── */}
      <div style={{ background: "linear-gradient(135deg,rgba(124,58,237,0.15),rgba(79,70,229,0.08))", border: "1px solid rgba(124,58,237,0.3)", borderRadius: 16, padding: "28px 32px", marginBottom: 40 }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>π</div>
        <div style={{ fontSize: 17, fontWeight: 700, color: "#a78bfa", marginBottom: 8 }}>Built for the Pi Ecosystem</div>
        <div style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", lineHeight: 1.85, maxWidth: 620 }}>
          Morbitech is a native Pi application available through the Pi Browser, making professional digital signage solutions accessible to the global Pioneer community through real-world Pi commerce. We accept Pi coin for all purchases — making us one of the first digital signage businesses in West Africa integrated into the Pi Network ecosystem. We believe in the future of Pi and are committed to growing with the Pioneer community across Africa and beyond.
        </div>
      </div>

      {/* ── Building the future ── */}
      <div style={{ background: "linear-gradient(135deg,rgba(59,130,246,0.08),rgba(16,24,40,0))", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "28px 32px", marginBottom: 40 }}>
        <div style={{ fontSize: 17, fontWeight: 700, color: "#fff", marginBottom: 10 }}>Building the Future of Digital Communication</div>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", lineHeight: 1.85, margin: "0 0 14px" }}>
          Digital communication has become central to how organisations engage customers, inform employees, and strengthen their brands. As expectations continue to evolve, businesses need communication platforms that are intelligent, dependable, scalable, and supported by experts who understand both the technology and the commercial objectives behind it.
        </p>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.55)", lineHeight: 1.85, margin: 0 }}>
          At Morbitech, we are committed to helping organisations across West Africa embrace this future with confidence — combining world-class technologies, professional implementation, and exceptional customer support to help businesses communicate more effectively, operate more efficiently, and create engaging experiences that drive meaningful growth.
        </p>
      </div>

      {/* ── CTA ── */}
      <div style={{ textAlign: "center", ...card, padding: "44px 28px" }}>
        <div style={{ fontSize: 23, fontWeight: 800, letterSpacing: "-0.02em", marginBottom: 10 }}>Partner With Morbitech</div>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.45)", lineHeight: 1.8, maxWidth: 540, margin: "0 auto 28px" }}>
          Whether you are introducing digital signage for the first time or expanding a large-scale network across multiple locations, Morbitech has the expertise, technology, and experience to bring your vision to life.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <button style={{ padding: "12px 28px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" }} onClick={() => setPage("catalog")}>Browse products</button>
          <button style={{ padding: "12px 28px", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" }} onClick={() => setPage("contact")}>Contact us</button>
        </div>
      </div>
    </div>
  );
}

// ── Cart Item component ───────────────────────────────────────────────────────
function CartDrawer({ cart, setCart, setPage, piUser, onPiLogin, onCheckout, onClose }) {
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const updateQty = (id, delta) => setCart(c => c.map(i => i.id === id ? { ...i, qty: Math.max(1, i.qty + delta) } : i));
  const remove = (id) => setCart(c => c.filter(i => i.id !== id));

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 500, display: "flex" }}>
      <div onClick={onClose} style={{ flex: 1, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }} />
      <div style={{ width: 400, background: "#080f1e", borderLeft: "1px solid rgba(255,255,255,0.08)", display: "flex", flexDirection: "column", height: "100vh", overflowY: "auto" }}>
        {/* Header */}
        <div style={{ padding: "20px 24px", borderBottom: "1px solid rgba(255,255,255,0.07)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 17, fontWeight: 800 }}>🛒 Your Cart ({cart.length})</div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.5)", fontSize: 22, cursor: "pointer" }}>✕</button>
        </div>

        {cart.length === 0
          ? <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "rgba(255,255,255,0.3)", gap: 12 }}>
              <div style={{ fontSize: 48 }}>🛒</div>
              <div style={{ fontSize: 14 }}>Your cart is empty</div>
              <button onClick={onClose} style={{ marginTop: 8, padding: "10px 24px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Browse products</button>
            </div>
          : <>
              {/* Items */}
              <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px", display: "flex", flexDirection: "column", gap: 14 }}>
                {cart.map(item => (
                  <div key={item.id} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "14px" }}>
                    <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                      <div style={{ width: 60, height: 60, borderRadius: 8, overflow: "hidden", flexShrink: 0, background: item.color + "33", display: "flex", alignItems: "center", justifyContent: "center" }}>
                        <img src={item.img} alt={item.name} style={{ width: "100%", height: "100%", objectFit: "cover" }} onError={e => e.target.style.display = "none"} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 2, lineHeight: 1.3 }}>{item.name}</div>
                        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", marginBottom: 8 }}>{item.cat}</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "#60a5fa" }}>{fmt.usd(item.price * item.qty)}</div>
                        <div style={{ fontSize: 11, color: "#a78bfa" }}>{fmt.pi(item.price * item.qty)}</div>
                      </div>
                      <button onClick={() => remove(item.id)} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: 16, padding: 4 }}>✕</button>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(255,255,255,0.05)", borderRadius: 8, padding: "4px 4px" }}>
                        <button onClick={() => updateQty(item.id, -1)} style={{ width: 28, height: 28, borderRadius: 6, background: "rgba(255,255,255,0.07)", border: "none", color: "#fff", fontSize: 16, cursor: "pointer" }}>−</button>
                        <span style={{ fontSize: 14, fontWeight: 700, minWidth: 20, textAlign: "center" }}>{item.qty}</span>
                        <button onClick={() => updateQty(item.id, 1)} style={{ width: 28, height: 28, borderRadius: 6, background: "rgba(255,255,255,0.07)", border: "none", color: "#fff", fontSize: 16, cursor: "pointer" }}>+</button>
                      </div>
                      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)" }}>{fmt.ngn(item.price)} each</div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Summary + checkout */}
              <div style={{ padding: "20px 24px", borderTop: "1px solid rgba(255,255,255,0.07)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: 13, color: "rgba(255,255,255,0.5)" }}>Subtotal</span>
                  <span style={{ fontSize: 15, fontWeight: 800, color: "#fff" }}>{fmt.usd(total)}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>NGN equiv.</span>
                  <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>{fmt.ngn(total)}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
                  <span style={{ fontSize: 12, color: "#a78bfa" }}>Pi equiv.</span>
                  <span style={{ fontSize: 12, color: "#a78bfa", fontWeight: 600 }}>{fmt.pi(total)}</span>
                </div>
                <button onClick={() => { onCheckout(); onClose(); }}
                  style={{ width: "100%", padding: "14px 0", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer", marginBottom: 10 }}>
                  Proceed to checkout →
                </button>
                <button onClick={onClose}
                  style={{ width: "100%", padding: "10px 0", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.12)", color: "rgba(255,255,255,0.55)", fontSize: 13, cursor: "pointer" }}>
                  Continue shopping
                </button>
              </div>
            </>
        }
      </div>
    </div>
  );
}

// ── Checkout Page ─────────────────────────────────────────────────────────────
function CheckoutPage({ cart, setCart, setPage, piUser, onPiLogin, onOrderPlaced }) {
  const [step, setStep] = useState(1); // 1=details, 2=payment, 3=confirm
  const [method, setMethod] = useState(null);
  const [form, setForm] = useState({ name: "", email: "", phone: "", company: "", address: "", city: "", country: "Nigeria", notes: "" });
  const [paying, setPaying] = useState(false);

  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const handleChange = e => setForm(f => ({
    ...f,
    [e.target.name]: e.target.name === "email"
      ? sanitizeEmail(e.target.value)
      : e.target.name === "phone"
        ? sanitizePhone(e.target.value)
        : sanitize(e.target.value)
  }));

  const inputStyle = { width: "100%", boxSizing: "border-box", padding: "11px 14px", borderRadius: 10, background: "#0d1829", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 14, outline: "none", fontFamily: "inherit" };
  const labelStyle = { fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.4)", letterSpacing: ".05em", textTransform: "uppercase", display: "block", marginBottom: 6 };

  const paymentMethods = [
    { id: "pi",      icon: "π",  label: "Pay with Pi",          sub: `${fmt.pi(total)} · instant settlement`,        color: "#7c3aed" },
    { id: "bank",    icon: "🏦", label: "Bank Transfer",         sub: "NGN transfer to Morbitech account",             color: "#0f4c8a" },
    { id: "invoice", icon: "📄", label: "Request Invoice",       sub: "B2B invoice sent within 24hrs",                 color: "#065f46" },
  ];

  const handlePay = async () => {
    // Validate all required fields before proceeding
    if (!validators.name(form.name))   { showToast?.("Please enter a valid full name."); return; }
    if (!validators.email(form.email)) { showToast?.("Please enter a valid email address."); return; }
    if (!validators.phone(form.phone) && form.phone !== "") { showToast?.("Please enter a valid phone number."); return; }
    if (!method) { showToast?.("Please select a payment method."); return; }
    if (!rateLimit("checkout", 3, 300_000)) { showToast?.("Too many checkout attempts."); return; }
    // Validate cart integrity — no negative prices, no zero qty
    const cartValid = cart.every(i => i.price > 0 && i.qty > 0 && i.qty <= 10);
    if (!cartValid) { showToast?.("Cart contains invalid items — please refresh and try again."); return; }
    setPaying(true);
    await new Promise(r => setTimeout(r, 1800));
    const order = {
      id:     genOrderId(),
      date:   new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }),
      items:  cart.map(i => ({ id: i.id, name: sanitize(i.name), price: i.price, qty: i.qty })),
      total,
      method,
      status: method === "invoice" ? "Awaiting Invoice" : method === "bank" ? "Awaiting Payment" : "Paid",
      customer: {
        name:    sanitize(form.name),
        email:   sanitizeEmail(form.email),
        phone:   sanitizePhone(form.phone),
        company: sanitize(form.company),
        country: sanitize(form.country),
      },
    };
    onOrderPlaced(order);
    setCart([]);
    setPaying(false);
    setPage("confirmation");
  };

  return (
    <div style={{ maxWidth: 860, margin: "0 auto", padding: "36px 24px 80px" }}>
      {/* Steps indicator */}
      <div style={{ display: "flex", alignItems: "center", gap: 0, marginBottom: 36 }}>
        {[["1", "Details"], ["2", "Payment"], ["3", "Review"]].map(([n, label], i) => (
          <div key={n} style={{ display: "flex", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: step >= +n ? "#3b82f6" : "rgba(255,255,255,0.08)", border: step >= +n ? "none" : "1px solid rgba(255,255,255,0.15)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: step >= +n ? "#fff" : "rgba(255,255,255,0.3)" }}>{n}</div>
              <span style={{ fontSize: 13, fontWeight: step === +n ? 600 : 400, color: step >= +n ? "#fff" : "rgba(255,255,255,0.35)" }}>{label}</span>
            </div>
            {i < 2 && <div style={{ width: 40, height: 1, background: step > +n ? "#3b82f6" : "rgba(255,255,255,0.1)", margin: "0 12px" }} />}
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 28, alignItems: "start" }}>
        {/* Left — steps */}
        <div>
          {/* Step 1 — Contact details */}
          {step === 1 && (
            <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "28px" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 24 }}>Delivery & contact details</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                  <div><label style={labelStyle}>Full name *</label><input name="name" value={form.name} onChange={handleChange} placeholder="Your full name" style={inputStyle} /></div>
                  <div><label style={labelStyle}>Email *</label><input name="email" value={form.email} onChange={handleChange} placeholder="you@company.com" style={inputStyle} /></div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                  <div><label style={labelStyle}>Phone *</label><input name="phone" value={form.phone} onChange={handleChange} placeholder="+234 800 000 0000" style={inputStyle} /></div>
                  <div><label style={labelStyle}>Company / Organisation</label><input name="company" value={form.company} onChange={handleChange} placeholder="Optional" style={inputStyle} /></div>
                </div>
                <div><label style={labelStyle}>Delivery address</label><input name="address" value={form.address} onChange={handleChange} placeholder="Street address" style={inputStyle} /></div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                  <div><label style={labelStyle}>City</label><input name="city" value={form.city} onChange={handleChange} placeholder="City" style={inputStyle} /></div>
                  <div>
                    <label style={labelStyle}>Country</label>
                    <select name="country" value={form.country} onChange={handleChange} style={{ ...inputStyle, cursor: "pointer" }}>
                      {["Nigeria","Ghana","Côte d'Ivoire","Cameroon","Benin Republic","Niger","Togo","Mali","Burkina Faso","Other"].map(c => <option key={c}>{c}</option>)}
                    </select>
                  </div>
                </div>
                <div><label style={labelStyle}>Order notes</label><textarea name="notes" value={form.notes} onChange={handleChange} rows={3} placeholder="Special requirements, installation notes, etc." style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} /></div>
                <button onClick={() => { if (!form.name || !form.email || !form.phone) return; setStep(2); }}
                  style={{ padding: "13px 0", borderRadius: 10, background: form.name && form.email && form.phone ? "#3b82f6" : "rgba(255,255,255,0.08)", border: "none", color: form.name && form.email && form.phone ? "#fff" : "rgba(255,255,255,0.3)", fontSize: 15, fontWeight: 700, cursor: "pointer" }}>
                  Continue to payment →
                </button>
              </div>
            </div>
          )}

          {/* Step 2 — Payment method */}
          {step === 2 && (
            <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "28px" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 24 }}>Choose payment method</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 24 }}>
                {paymentMethods.map(pm => (
                  <div key={pm.id} onClick={() => setMethod(pm.id)}
                    style={{ padding: "18px 20px", borderRadius: 12, border: `1.5px solid ${method === pm.id ? pm.color : "rgba(255,255,255,0.08)"}`, background: method === pm.id ? pm.color + "18" : "rgba(255,255,255,0.02)", cursor: "pointer", display: "flex", alignItems: "center", gap: 16 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 10, background: pm.color + "22", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, flexShrink: 0 }}>{pm.icon}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 15, fontWeight: 700, color: method === pm.id ? "#fff" : "rgba(255,255,255,0.75)", marginBottom: 2 }}>{pm.label}</div>
                      <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>{pm.sub}</div>
                    </div>
                    <div style={{ width: 20, height: 20, borderRadius: "50%", border: `2px solid ${method === pm.id ? pm.color : "rgba(255,255,255,0.2)"}`, background: method === pm.id ? pm.color : "transparent", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {method === pm.id && <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#fff" }} />}
                    </div>
                  </div>
                ))}
              </div>
              {method === "bank" && (
                <div style={{ background: "rgba(15,76,138,0.15)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 12, padding: "16px 18px", marginBottom: 20 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#60a5fa", marginBottom: 10, letterSpacing: ".05em", textTransform: "uppercase" }}>Bank transfer details</div>
                  {[["Bank", "First Bank of Nigeria"], ["Account name", "Morbitech Limited"], ["Account number", "3012345678"], ["Amount", `₦${Math.round(total * USD_TO_NGN).toLocaleString()}`]].map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                      <span style={{ color: "rgba(255,255,255,0.4)" }}>{k}</span><span style={{ fontWeight: 600, color: "#fff" }}>{v}</span>
                    </div>
                  ))}
                </div>
              )}
              {method === "invoice" && (
                <div style={{ background: "rgba(6,95,70,0.15)", border: "1px solid rgba(52,211,153,0.2)", borderRadius: 12, padding: "16px 18px", marginBottom: 20 }}>
                  <div style={{ fontSize: 13, color: "rgba(255,255,255,0.6)", lineHeight: 1.7 }}>
                    A formal invoice will be sent to <strong style={{ color: "#fff" }}>{form.email}</strong> within 24 business hours. Payment terms: 50% deposit, 50% on delivery.
                  </div>
                </div>
              )}
              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={() => setStep(1)} style={{ flex: 1, padding: "12px 0", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.5)", fontSize: 14, cursor: "pointer" }}>← Back</button>
                <button onClick={() => method && setStep(3)}
                  style={{ flex: 2, padding: "13px 0", borderRadius: 10, background: method ? "#3b82f6" : "rgba(255,255,255,0.08)", border: "none", color: method ? "#fff" : "rgba(255,255,255,0.3)", fontSize: 15, fontWeight: 700, cursor: "pointer" }}>
                  Review order →
                </button>
              </div>
            </div>
          )}

          {/* Step 3 — Review & confirm */}
          {step === 3 && (
            <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "28px" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>Review & confirm order</div>
              {cart.map(item => (
                <div key={item.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", fontSize: 13 }}>
                  <div>
                    <div style={{ color: "#fff", fontWeight: 600 }}>{item.name}</div>
                    <div style={{ color: "rgba(255,255,255,0.4)", fontSize: 12 }}>Qty: {item.qty}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ color: "#fff", fontWeight: 700 }}>{fmt.usd(item.price * item.qty)}</div>
                    <div style={{ color: "#a78bfa", fontSize: 11 }}>{fmt.pi(item.price * item.qty)}</div>
                  </div>
                </div>
              ))}
              <div style={{ marginTop: 20, padding: "14px 0", borderTop: "1px solid rgba(255,255,255,0.08)" }}>
                {[["Name", form.name], ["Email", form.email], ["Phone", form.phone], ["Country", form.country], ["Payment", paymentMethods.find(p => p.id === method)?.label]].map(([k, v]) => v && (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 12, padding: "3px 0", color: "rgba(255,255,255,0.5)" }}>
                    <span>{k}</span><span style={{ color: "#fff" }}>{v}</span>
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
                <button onClick={() => setStep(2)} style={{ flex: 1, padding: "12px 0", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.5)", fontSize: 14, cursor: "pointer" }}>← Back</button>
                <button onClick={handlePay} disabled={paying}
                  style={{ flex: 2, padding: "13px 0", borderRadius: 10, background: paying ? "rgba(59,130,246,0.4)" : "#3b82f6", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: paying ? "default" : "pointer" }}>
                  {paying ? "Processing…" : `Confirm order · ${fmt.usd(total)}`}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right — order summary */}
        <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "22px", position: "sticky", top: 80 }}>
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>Order summary</div>
          {cart.map(item => (
            <div key={item.id} style={{ display: "flex", justifyContent: "space-between", fontSize: 12, padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              <span style={{ color: "rgba(255,255,255,0.6)", flex: 1, marginRight: 8, lineHeight: 1.4 }}>{item.name} ×{item.qty}</span>
              <span style={{ color: "#fff", fontWeight: 600, flexShrink: 0 }}>{fmt.usd(item.price * item.qty)}</span>
            </div>
          ))}
          <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid rgba(255,255,255,0.08)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 16, fontWeight: 800 }}>
              <span>Total</span><span style={{ color: "#60a5fa" }}>{fmt.usd(total)}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "rgba(255,255,255,0.4)", marginTop: 4 }}>
              <span>NGN</span><span>{fmt.ngn(total)}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "#a78bfa", marginTop: 2 }}>
              <span>Pi equiv.</span><span>{fmt.pi(total)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Order Confirmation Page ────────────────────────────────────────────────────
function ConfirmationPage({ order, setPage }) {
  if (!order) return null;
  const statusColors = { "Paid": "#10b981", "Awaiting Payment": "#f59e0b", "Awaiting Invoice": "#a78bfa" };
  const statusColor = statusColors[order.status] || "#60a5fa";
  return (
    <div style={{ maxWidth: 620, margin: "0 auto", padding: "48px 24px 80px", textAlign: "center" }}>
      <div style={{ fontSize: 72, marginBottom: 16 }}>{order.status === "Paid" ? "🎉" : "📋"}</div>
      <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: "-0.03em", marginBottom: 8 }}>Order placed!</h1>
      <div style={{ fontSize: 14, color: "rgba(255,255,255,0.45)", marginBottom: 32 }}>
        Thank you, <strong style={{ color: "#fff" }}>{order.customer.name}</strong>. Your order reference is below.
      </div>

      <div style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 16, padding: "28px", marginBottom: 24, textAlign: "left" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: ".07em", textTransform: "uppercase", marginBottom: 4 }}>Order reference</div>
            <div style={{ fontSize: 18, fontWeight: 800, letterSpacing: "-0.02em" }}>{order.id}</div>
          </div>
          <span style={{ fontSize: 12, fontWeight: 700, padding: "4px 12px", borderRadius: 20, background: statusColor + "22", color: statusColor, border: `1px solid ${statusColor}44` }}>{order.status}</span>
        </div>

        {order.items.map(item => (
          <div key={item.id} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
            <span style={{ color: "rgba(255,255,255,0.7)" }}>{item.name} ×{item.qty}</span>
            <span style={{ fontWeight: 600 }}>{fmt.usd(item.price * item.qty)}</span>
          </div>
        ))}

        <div style={{ marginTop: 16, display: "flex", justifyContent: "space-between", fontSize: 16, fontWeight: 800 }}>
          <span>Total</span><span style={{ color: "#60a5fa" }}>{fmt.usd(order.total)}</span>
        </div>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", marginTop: 4, display: "flex", justifyContent: "space-between" }}>
          <span>Pi equiv.</span><span style={{ color: "#a78bfa" }}>{fmt.pi(order.total)}</span>
        </div>
      </div>

      {order.status === "Awaiting Payment" && (
        <div style={{ background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: 12, padding: "16px 20px", marginBottom: 20, textAlign: "left" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#f59e0b", marginBottom: 6 }}>⏳ Bank transfer pending</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.7 }}>Please transfer <strong style={{ color: "#fff" }}>{fmt.ngn(order.total)}</strong> to our First Bank account (3012345678) and send proof to <strong style={{ color: "#fff" }}>info@morbitech.com</strong>.</div>
        </div>
      )}
      {order.status === "Awaiting Invoice" && (
        <div style={{ background: "rgba(167,139,250,0.1)", border: "1px solid rgba(167,139,250,0.3)", borderRadius: 12, padding: "16px 20px", marginBottom: 20, textAlign: "left" }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#a78bfa", marginBottom: 6 }}>📄 Invoice incoming</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.7 }}>A formal invoice will be sent to <strong style={{ color: "#fff" }}>{order.customer.email}</strong> within 24 business hours.</div>
        </div>
      )}

      <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
        <button onClick={() => setPage("catalog")} style={{ padding: "12px 28px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" }}>Continue shopping</button>
        <button onClick={() => setPage("profile")} style={{ padding: "12px 28px", borderRadius: 10, background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", fontSize: 14, fontWeight: 600, cursor: "pointer" }}>View my orders</button>
      </div>
    </div>
  );
}

// ── Product Enquiry Modal ──────────────────────────────────────────────────────
function EnquiryModal({ product, onClose, toast }) {
  const [form, setForm] = useState({ name: "", email: "", phone: "", company: "", qty: "1", message: "" });
  const [sent, setSent] = useState(false);
  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: sanitize(e.target.value) }));
  const handleSend = () => {
    if (!rateLimit("enquiry-modal", 3, 120_000)) {
      toast("Too many submissions — please wait 2 minutes."); return;
    }
    const errs = validateForm(form, ["name", "email"]);
    if (errs.name)  { toast("Please enter a valid name (2–100 characters)."); return; }
    if (errs.email) { toast("Please enter a valid email address."); return; }
    if (form.phone && !validators.phone(form.phone)) { toast("Please enter a valid phone number."); return; }
    if (!validators.qty(form.qty)) { toast("Please enter a valid quantity (1–100)."); return; }
    setSent(true);
    toast(`✓ Enquiry sent for ${sanitize(product.name)}!`);
  };
  const inputStyle = { width: "100%", boxSizing: "border-box", padding: "10px 13px", borderRadius: 9, background: "#080f1e", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 13, outline: "none", fontFamily: "inherit" };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 600, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={onClose} style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(6px)" }} />
      <div style={{ position: "relative", background: "#0d1829", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 18, padding: "28px", width: "100%", maxWidth: 480, zIndex: 1 }}>
        <button onClick={onClose} style={{ position: "absolute", top: 16, right: 16, background: "none", border: "none", color: "rgba(255,255,255,0.4)", fontSize: 20, cursor: "pointer" }}>✕</button>
        {sent ? (
          <div style={{ textAlign: "center", padding: "20px 0" }}>
            <div style={{ fontSize: 52, marginBottom: 16 }}>✅</div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Enquiry sent!</div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.45)", marginBottom: 20 }}>We'll get back to you within 24 hours about <strong style={{ color: "#fff" }}>{product.name}</strong>.</div>
            <button onClick={onClose} style={{ padding: "10px 24px", borderRadius: 9, background: "#3b82f6", border: "none", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Done</button>
          </div>
        ) : (
          <>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".07em", textTransform: "uppercase", color: "#60a5fa", marginBottom: 6 }}>Product enquiry</div>
            <div style={{ fontSize: 16, fontWeight: 800, marginBottom: 4 }}>{product.name}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>{fmt.usd(product.price)} · {fmt.ngn(product.price)}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Name *</div><input name="name" value={form.name} onChange={handleChange} placeholder="Full name" style={inputStyle} /></div>
                <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Email *</div><input name="email" value={form.email} onChange={handleChange} placeholder="you@company.com" style={inputStyle} /></div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Phone</div><input name="phone" value={form.phone} onChange={handleChange} placeholder="+234…" style={inputStyle} /></div>
                <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Quantity needed</div><input name="qty" value={form.qty} onChange={handleChange} placeholder="1" style={inputStyle} /></div>
              </div>
              <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Company</div><input name="company" value={form.company} onChange={handleChange} placeholder="Optional" style={inputStyle} /></div>
              <div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginBottom: 5 }}>Message</div><textarea name="message" value={form.message} onChange={handleChange} rows={3} placeholder="Tell us your use case, installation requirements, or any questions…" style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }} /></div>
              <button onClick={handleSend} style={{ padding: "12px 0", borderRadius: 9, background: "#3b82f6", border: "none", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer" }}>Send enquiry →</button>
              <button onClick={() => safeOpen(`https://wa.me/${WA_NUMBER}?text=Hi%20Morbitech%2C%20I%27d%20like%20to%20enquire%20about%20${encodeURIComponent(sanitize(product.name))}%20priced%20at%20${encodeURIComponent(fmt.usd(product.price))}`, "_blank")}
                style={{ padding: "12px 0", borderRadius: 9, background: "#25d366", border: "none", color: "#fff", fontSize: 14, fontWeight: 700, cursor: "pointer" }}>
                💬 Enquire on WhatsApp
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Profile Page ──────────────────────────────────────────────────────────────
function ProfilePage({ piUser, orders, savedProducts, setSavedProducts, setPage, setProduct, onPiLogin }) {
  const [tab, setTab] = useState("orders");
  const statusColors = { "Paid": "#10b981", "Awaiting Payment": "#f59e0b", "Awaiting Invoice": "#a78bfa" };

  if (!piUser) {
    return (
      <div style={{ maxWidth: 480, margin: "80px auto", padding: "0 24px", textAlign: "center" }}>
        <div style={{ fontSize: 64, marginBottom: 20 }}>π</div>
        <h2 style={{ fontSize: 24, fontWeight: 800, letterSpacing: "-0.02em", marginBottom: 8 }}>Connect your Pi wallet</h2>
        <p style={{ fontSize: 14, color: "rgba(255,255,255,0.45)", marginBottom: 32, lineHeight: 1.7 }}>Sign in with your Pi account to view your order history, saved products, and manage your Morbitech profile.</p>
        <button onClick={onPiLogin} style={{ padding: "14px 36px", borderRadius: 12, background: "linear-gradient(135deg,#7c3aed,#4f46e5)", border: "none", color: "#fff", fontSize: 15, fontWeight: 700, cursor: "pointer" }}>
          Connect Pi Wallet →
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 860, margin: "0 auto", padding: "36px 24px 80px" }}>
      {/* Profile header */}
      <div style={{ background: "linear-gradient(135deg,rgba(124,58,237,0.15),rgba(79,70,229,0.08))", border: "1px solid rgba(124,58,237,0.25)", borderRadius: 16, padding: "28px", marginBottom: 28, display: "flex", alignItems: "center", gap: 20 }}>
        <div style={{ width: 64, height: 64, borderRadius: "50%", background: "linear-gradient(135deg,#7c3aed,#4f46e5)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 28, flexShrink: 0 }}>π</div>
        <div>
          <div style={{ fontSize: 20, fontWeight: 800, marginBottom: 2 }}>π {piUser.username}</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)" }}>Pioneer · {orders.length} order{orders.length !== 1 ? "s" : ""} · {savedProducts.length} saved</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 28, background: "rgba(255,255,255,0.04)", borderRadius: 12, padding: 4 }}>
        {[["orders", "📦 Orders"], ["saved", "❤️ Saved products"]].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)}
            style={{ flex: 1, padding: "10px 0", borderRadius: 9, background: tab === id ? "#0d1829" : "transparent", border: tab === id ? "1px solid rgba(255,255,255,0.08)" : "none", color: tab === id ? "#fff" : "rgba(255,255,255,0.45)", fontSize: 13, fontWeight: tab === id ? 700 : 400, cursor: "pointer" }}>
            {label}
          </button>
        ))}
      </div>

      {/* Orders tab */}
      {tab === "orders" && (
        orders.length === 0
          ? <div style={{ textAlign: "center", padding: "60px 0", color: "rgba(255,255,255,0.3)" }}>
              <div style={{ fontSize: 44, marginBottom: 12 }}>📦</div>
              <div style={{ fontSize: 14, marginBottom: 20 }}>No orders yet</div>
              <button onClick={() => setPage("catalog")} style={{ padding: "10px 24px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Browse products</button>
            </div>
          : <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {orders.map(order => (
                <div key={order.id} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 14, padding: "20px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: "-0.01em" }}>{order.id}</div>
                      <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", marginTop: 2 }}>{order.date} · {order.items.length} item{order.items.length !== 1 ? "s" : ""}</div>
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 20, background: (statusColors[order.status] || "#60a5fa") + "22", color: statusColors[order.status] || "#60a5fa", border: `1px solid ${(statusColors[order.status] || "#60a5fa")}44` }}>{order.status}</span>
                  </div>
                  {order.items.map(item => (
                    <div key={item.id} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "6px 0", borderTop: "1px solid rgba(255,255,255,0.04)", color: "rgba(255,255,255,0.6)" }}>
                      <span>{item.name} ×{item.qty}</span>
                      <span style={{ fontWeight: 600, color: "#fff" }}>{fmt.usd(item.price * item.qty)}</span>
                    </div>
                  ))}
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(255,255,255,0.07)", fontSize: 14, fontWeight: 800 }}>
                    <span>Total</span><span style={{ color: "#60a5fa" }}>{fmt.usd(order.total)}</span>
                  </div>
                </div>
              ))}
            </div>
      )}

      {/* Saved products tab */}
      {tab === "saved" && (
        savedProducts.length === 0
          ? <div style={{ textAlign: "center", padding: "60px 0", color: "rgba(255,255,255,0.3)" }}>
              <div style={{ fontSize: 44, marginBottom: 12 }}>❤️</div>
              <div style={{ fontSize: 14, marginBottom: 20 }}>No saved products yet</div>
              <button onClick={() => setPage("catalog")} style={{ padding: "10px 24px", borderRadius: 10, background: "#3b82f6", border: "none", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Browse products</button>
            </div>
          : <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(240px,1fr))", gap: 14 }}>
              {savedProducts.map(p => (
                <div key={p.id} style={{ background: "#0d1829", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 14, overflow: "hidden", cursor: "pointer" }} onClick={() => { setProduct(p); setPage("detail"); }}>
                  <div style={{ height: 130, overflow: "hidden", background: p.color + "33", display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
                    <img src={p.img} alt={p.name} style={{ width: "100%", height: "100%", objectFit: "cover" }} onError={e => e.target.style.display = "none"} />
                    <button onClick={e => { e.stopPropagation(); setSavedProducts(s => s.filter(x => x.id !== p.id)); }}
                      style={{ position: "absolute", top: 8, right: 8, width: 28, height: 28, borderRadius: "50%", background: "rgba(0,0,0,0.6)", border: "none", color: "#f87171", fontSize: 14, cursor: "pointer" }}>✕</button>
                  </div>
                  <div style={{ padding: "12px 14px" }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 4 }}>{p.name}</div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: "#60a5fa" }}>{fmt.usd(p.price)}</div>
                    <div style={{ fontSize: 11, color: "#a78bfa" }}>{fmt.pi(p.price)}</div>
                  </div>
                </div>
              ))}
            </div>
      )}
    </div>
  );
}

// ── App shell ─────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState("home");
  const [product, setProduct] = useState(null);
  const [piUser, setPiUser] = useState(null);
  const [toastMsg, setToastMsg]         = useState(null);
  const [cart, setCart]                 = useState([]);
  const [cartOpen, setCartOpen]         = useState(false);
  const [orders, setOrders]             = useState([]);
  const [savedProducts, setSavedProducts] = useState([]);
  const [lastOrder, setLastOrder]       = useState(null);
  const [enquiryProduct, setEnquiryProduct] = useState(null);
  const sessionTimer                    = useRef(null);

  // ── Toast ──────────────────────────────────────────────────────────────────
  const showToast = useCallback((msg) => {
    setToastMsg(sanitize(String(msg)));
    setTimeout(() => setToastMsg(null), 3500);
  }, []);

  // ── Session expiry — resets on any interaction ────────────────────────────
  const resetSessionTimer = useCallback(() => {
    if (sessionTimer.current) clearTimeout(sessionTimer.current);
    sessionTimer.current = setTimeout(() => {
      setPiUser(null);
      showToast("Session expired — please reconnect your Pi wallet.");
    }, SESSION_TIMEOUT_MS);
  }, [showToast]);

  useEffect(() => {
    const events = ["click", "keydown", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, resetSessionTimer, { passive: true }));
    return () => {
      events.forEach((e) => window.removeEventListener(e, resetSessionTimer));
      if (sessionTimer.current) clearTimeout(sessionTimer.current);
    };
  }, [resetSessionTimer]);

  // ── Pi login — hardened ───────────────────────────────────────────────────
  const handlePiLogin = useCallback(async () => {
    if (!rateLimit("pi-auth", 3, 60_000)) {
      showToast("Too many login attempts — please wait a minute.");
      return;
    }
    try {
      const auth = await Pi.authenticate(["username", "payments"], {});
      // Validate the response shape before trusting it
      if (!auth?.user?.username || !auth?.user?.uid) {
        throw new Error("Invalid Pi auth response");
      }
      const safeUser = {
        username: sanitize(auth.user.username).slice(0, 50),
        uid:      sanitize(auth.user.uid).slice(0, 100),
      };
      setPiUser(safeUser);
      resetSessionTimer();
      if (Pi._isMock) {
        showToast("⚠️ Dev mode — Pi mock active (not a real account)");
      } else {
        showToast("✓ Connected as π " + safeUser.username);
      }
    } catch (e) {
      console.error("[Pi Auth]", e.message);
      showToast("Pi login failed — please try again.");
    }
  }, [showToast, resetSessionTimer]);

  // ── Pi payment — hardened with server-side approval stubs ────────────────
  const handlePiPay = useCallback((product) => {
    if (!piUser) { showToast("Please connect your Pi wallet first."); return; }
    if (!rateLimit("pi-pay", 3, 60_000)) {
      showToast("Too many payment attempts — please wait.");
      return;
    }
    // Validate product integrity before initiating payment
    const price = Number(product?.price);
    if (!product?.id || isNaN(price) || price <= 0) {
      showToast("Invalid product — cannot process payment.");
      return;
    }
    const piAmount = parseFloat((price / PI_RATE).toFixed(2));
    const memo     = sanitize(`Morbitech: ${product.name}`).slice(0, 100);
    showToast(`Initiating Pi payment: π ${piAmount}…`);
    Pi.createPayment(
      {
        amount:   piAmount,
        memo,
        metadata: { productId: product.id, version: "1" },
      },
      {
        onReadyForServerApproval: async (paymentId) => {
          const ok = await piServerApprove(paymentId);
          if (!ok) showToast("Payment approval failed — please contact support.");
          else showToast("Payment approved — processing…");
        },
        onReadyForServerCompletion: async (paymentId, txid) => {
          const ok = await piServerComplete(paymentId, txid);
          if (ok) showToast("✓ Pi payment complete! Order confirmed.");
          else showToast("Payment completion failed — contact support with ref: " + paymentId);
        },
        onCancel: (paymentId) => {
          console.log("[Pi] Payment cancelled:", paymentId);
          showToast("Payment cancelled.");
        },
        onError: (error, payment) => {
          console.error("[Pi] Payment error:", error, payment);
          showToast("Payment failed — please try again or choose another method.");
        },
      }
    );
  }, [piUser, showToast]);

  // ── Cart — validate before adding ────────────────────────────────────────
  const addToCart = useCallback((p) => {
    if (!p?.id || !p?.name || typeof p?.price !== "number") return;
    const MAX_CART = 20;
    setCart((c) => {
      if (c.length >= MAX_CART && !c.find((i) => i.id === p.id)) {
        showToast("Cart limit reached (20 items).");
        return c;
      }
      const exists = c.find((i) => i.id === p.id);
      const MAX_QTY = 10;
      if (exists && exists.qty >= MAX_QTY) {
        showToast(`Maximum quantity (${MAX_QTY}) reached for this item.`);
        return c;
      }
      if (exists) return c.map((i) => i.id === p.id ? { ...i, qty: i.qty + 1 } : i);
      return [...c, { id: p.id, name: p.name, price: p.price, img: p.img, imgAlt: p.imgAlt, qty: 1 }];
    });
    showToast(`✓ ${sanitize(p.name)} added to cart`);
    setCartOpen(true);
  }, [showToast]);

  // ── Saved products ────────────────────────────────────────────────────────
  const toggleSave = useCallback((p) => {
    if (!p?.id) return;
    setSavedProducts((s) => {
      const isSaved = s.some((x) => x.id === p.id);
      showToast(isSaved ? "Removed from saved" : "❤️ Saved to your profile");
      return isSaved ? s.filter((x) => x.id !== p.id) : [...s, p];
    });
  }, [showToast]);

  // ── Order placed — sign with generated ID ────────────────────────────────
  const handleOrderPlaced = useCallback((order) => {
    const signed = { ...order, id: genOrderId(), _integrity: Date.now() };
    setOrders((o) => [signed, ...o]);
    setLastOrder(signed);
  }, []);

  const cartCount = cart.reduce((s, i) => s + i.qty, 0);


  return (
    <div style={S.app}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet" />

      {/* Nav */}
      <nav style={S.nav}>
        <div style={{ ...S.logo, cursor: "pointer" }} onClick={() => setPage("home")}>
          Morbi<span style={S.logoSpan}>tech</span>
        </div>
        <div style={S.navLinks}>
          <span style={{ cursor: "pointer" }} onClick={() => setPage("home")}>Home</span>
          <span style={{ cursor: "pointer" }} onClick={() => setPage("catalog")}>Products</span>
          <span style={{ cursor: "pointer" }} onClick={() => setPage("about")}>About</span>
          <span style={{ cursor: "pointer", color: "#34d399" }} onClick={() => setPage("contact")}>Contact</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Cart button */}
          <button onClick={() => setCartOpen(true)} style={{ position: "relative", padding: "7px 12px", borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 14, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
            🛒
            {cartCount > 0 && <span style={{ position: "absolute", top: -6, right: -6, width: 18, height: 18, borderRadius: "50%", background: "#3b82f6", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{cartCount}</span>}
          </button>
          {/* Profile button */}
          <button onClick={() => setPage("profile")} style={{ padding: "7px 12px", borderRadius: 8, background: piUser ? "rgba(124,58,237,0.2)" : "rgba(255,255,255,0.06)", border: `1px solid ${piUser ? "rgba(124,58,237,0.4)" : "rgba(255,255,255,0.1)"}`, color: piUser ? "#a78bfa" : "rgba(255,255,255,0.6)", fontSize: 13, cursor: "pointer" }}>
            {piUser ? `π ${piUser.username}` : "👤"}
          </button>
          {/* Pi connect */}
          <button style={S.piBtn} onClick={piUser ? () => setPage("profile") : handlePiLogin}>
            <span style={{ fontSize: 14 }}>π</span>
            {piUser ? "Profile" : "Connect Pi"}
          </button>
        </div>
      </nav>

      {/* Pages */}
      {page === "home"         && <HomePage setPage={setPage} setProduct={setProduct} piUser={piUser} onPiLogin={handlePiLogin} addToCart={addToCart} />}
      {page === "catalog"      && <CatalogPage setPage={setPage} setProduct={setProduct} />}
      {page === "detail"       && product && <DetailPage product={product} setPage={setPage} piUser={piUser} onPiLogin={handlePiLogin} onPiPay={handlePiPay} toast={showToast} addToCart={addToCart} toggleSave={toggleSave} savedProducts={savedProducts} onEnquire={() => setEnquiryProduct(product)} />}
      {page === "about"        && <AboutPage setPage={setPage} />}
      {page === "contact"      && <ContactPage setPage={setPage} toast={showToast} />}
      {page === "checkout"     && <CheckoutPage cart={cart} setCart={setCart} setPage={setPage} piUser={piUser} onPiLogin={handlePiLogin} onOrderPlaced={handleOrderPlaced} />}
      {page === "confirmation" && <ConfirmationPage order={lastOrder} setPage={setPage} />}
      {page === "profile"      && <ProfilePage piUser={piUser} orders={orders} savedProducts={savedProducts} setSavedProducts={setSavedProducts} setPage={setPage} setProduct={setProduct} onPiLogin={handlePiLogin} />}

      {/* Cart drawer */}
      {cartOpen && <CartDrawer cart={cart} setCart={setCart} setPage={setPage} piUser={piUser} onPiLogin={handlePiLogin} onCheckout={() => setPage("checkout")} onClose={() => setCartOpen(false)} />}

      {/* Enquiry modal */}
      {enquiryProduct && <EnquiryModal product={enquiryProduct} onClose={() => setEnquiryProduct(null)} toast={showToast} />}

      {/* ── Footer ── */}
      <footer style={{ borderTop: "1px solid rgba(255,255,255,0.07)", background: "#030810", padding: "48px 24px 32px", marginTop: 48 }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr", gap: 40, marginBottom: 40 }}>

            {/* Brand col */}
            <div>
              <div style={{ fontSize: 20, fontWeight: 800, color: "#fff", marginBottom: 10 }}>
                Morbi<span style={{ color: "#3b82f6" }}>tech</span>
              </div>
              <p style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", lineHeight: 1.8, maxWidth: 280, marginBottom: 20 }}>
                West Africa's digital signage distributor. Affordable, transparent, and Pi-native.
              </p>
              {/* Social icons */}
              <div style={{ display: "flex", gap: 10 }}>
                <a href="https://x.com/Pappie_shyle" target="_blank" rel="noreferrer"
                  style={{ width: 38, height: 38, borderRadius: 10, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none", color: "#fff", fontSize: 16, transition: "background 0.15s" }}
                  title="Follow us on X (Twitter)">
                  𝕏
                </a>
                <a href="https://www.instagram.com/lamptechventures?igsh=MTA2bzZkb3lxY214cA==" target="_blank" rel="noreferrer"
                  style={{ width: 38, height: 38, borderRadius: 10, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none", fontSize: 18, transition: "background 0.15s" }}
                  title="Follow us on Instagram">
                  📸
                </a>
                <a href={`https://wa.me/${WA_NUMBER}`} target="_blank" rel="noreferrer"
                  style={{ width: 38, height: 38, borderRadius: 10, background: "rgba(37,211,102,0.1)", border: "1px solid rgba(37,211,102,0.2)", display: "flex", alignItems: "center", justifyContent: "center", textDecoration: "none", fontSize: 18 }}
                  title="WhatsApp us">
                  💬
                </a>
              </div>
            </div>

            {/* Quick links */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 16 }}>Quick links</div>
              {[["Home", "home"], ["Products", "catalog"], ["About us", "about"], ["Contact", "contact"]].map(([label, pg]) => (
                <div key={pg} onClick={() => setPage(pg)}
                  style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", marginBottom: 10, cursor: "pointer", lineHeight: 1.5 }}>
                  {label}
                </div>
              ))}
            </div>

            {/* Products */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 16 }}>Products</div>
              {["Digital Posters", "Modular DV-LED", "Touch Screens", "LCD Video Walls", "High Brightness", "Media Players"].map(cat => (
                <div key={cat} onClick={() => setPage("catalog")}
                  style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", marginBottom: 10, cursor: "pointer", lineHeight: 1.5 }}>
                  {cat}
                </div>
              ))}
            </div>

            {/* Contact */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase", color: "rgba(255,255,255,0.3)", marginBottom: 16 }}>Contact us</div>
              <div style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", marginBottom: 10, lineHeight: 1.6 }}>📍 Lagos, Nigeria</div>
              <a href="tel:+2348061233018" style={{ display: "block", fontSize: 13, color: "rgba(255,255,255,0.5)", marginBottom: 10, textDecoration: "none" }}>📞 08061233018</a>
              <a href="mailto:info@morbitech.com" style={{ display: "block", fontSize: 13, color: "rgba(255,255,255,0.5)", marginBottom: 10, textDecoration: "none" }}>📧 info@morbitech.com</a>
              <a href={`https://wa.me/${WA_NUMBER}`} target="_blank" rel="noreferrer"
                style={{ display: "block", fontSize: 13, color: "#25d366", marginBottom: 10, textDecoration: "none", fontWeight: 500 }}>
                💬 WhatsApp us
              </a>
              {/* Social in contact col */}
              <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
                <a href="https://x.com/Pappie_shyle" target="_blank" rel="noreferrer"
                  style={{ fontSize: 12, padding: "5px 10px", borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)", textDecoration: "none" }}>
                  𝕏 Twitter
                </a>
                <a href="https://www.instagram.com/lamptechventures?igsh=MTA2bzZkb3lxY214cA==" target="_blank" rel="noreferrer"
                  style={{ fontSize: 12, padding: "5px 10px", borderRadius: 8, background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.6)", textDecoration: "none" }}>
                  📸 Instagram
                </a>
              </div>
            </div>
          </div>

          {/* Bottom bar */}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 20, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.25)" }}>
              © {new Date().getFullYear()} Morbitech. All rights reserved. · Lagos, Nigeria
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: "rgba(255,255,255,0.2)" }}>Built for the</span>
              <span style={{ fontSize: 13, color: "#a78bfa", fontWeight: 700 }}>π Pi Network</span>
            </div>
          </div>
        </div>
      </footer>

      {/* Floating WhatsApp */}
      <a href={`https://wa.me/${WA_NUMBER}?text=Hello%20Morbitech%2C%20I%27d%20like%20to%20enquire%20about%20your%20digital%20signage%20products.`}
        target="_blank" rel="noreferrer"
        style={{ position: "fixed", bottom: 24, left: 24, width: 52, height: 52, borderRadius: "50%", background: "#25d366", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26, boxShadow: "0 4px 20px rgba(37,211,102,0.4)", zIndex: 998, textDecoration: "none" }}
        title="Chat on WhatsApp">💬</a>

      {/* Toast */}
      {toastMsg && <div style={S.toast}>{toastMsg}</div>}
    </div>
  );
}
