// hooks/usePWA.js
// Drop this file into your hooks/ folder and call usePWA() in your root layout.
// It handles: service worker registration, install prompt, update notifications.

import { useEffect, useState } from 'react';

export default function usePWA() {
  const [installPrompt, setInstallPrompt] = useState(null);
  const [isInstalled, setIsInstalled]     = useState(false);
  const [updateReady, setUpdateReady]     = useState(false);
  const [swReg, setSwReg]                 = useState(null);

  // ── Register service worker ──────────────────────────────────────────────
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!('serviceWorker' in navigator)) return;

    navigator.serviceWorker
      .register('/service-worker.js')
      .then((reg) => {
        console.log('[PWA] Service worker registered:', reg.scope);
        setSwReg(reg);

        // Check for updates every 60 seconds
        const interval = setInterval(() => reg.update(), 60_000);

        // A new SW is waiting — prompt the user to update
        reg.addEventListener('updatefound', () => {
          const newWorker = reg.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              console.log('[PWA] Update available');
              setUpdateReady(true);
            }
          });
        });

        return () => clearInterval(interval);
      })
      .catch((err) => console.warn('[PWA] Service worker registration failed:', err));

    // Check if already installed (standalone mode)
    if (
      window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true
    ) {
      setIsInstalled(true);
    }
  }, []);

  // ── Capture the install prompt (Chrome/Android) ──────────────────────────
  useEffect(() => {
    const handler = (e) => {
      e.preventDefault();
      setInstallPrompt(e);
    };
    window.addEventListener('beforeinstallprompt', handler);
    window.addEventListener('appinstalled', () => {
      setIsInstalled(true);
      setInstallPrompt(null);
      console.log('[PWA] App installed');
    });
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  // ── Trigger the install prompt ────────────────────────────────────────────
  const promptInstall = async () => {
    if (!installPrompt) return false;
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice;
    if (outcome === 'accepted') setIsInstalled(true);
    setInstallPrompt(null);
    return outcome === 'accepted';
  };

  // ── Apply waiting SW update ───────────────────────────────────────────────
  const applyUpdate = () => {
    if (!swReg?.waiting) return;
    swReg.waiting.postMessage({ type: 'SKIP_WAITING' });
    window.location.reload();
  };

  return { installPrompt, isInstalled, promptInstall, updateReady, applyUpdate };
}
