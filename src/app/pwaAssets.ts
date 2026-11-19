// pwaAssets.ts — the manifest and service worker that turn the phone page
// into an installable PWA with real notifications.
//
// Shared between lanServer.ts and bashme-relay/src/worker.ts (which vendors
// this file's exports the same way it vendors phonePage.ts) so a phone gets
// the identical install/notification experience over either transport.

/** Minimal, valid, installable. Icons are inline SVG data URIs -- no asset pipeline. */
export const MANIFEST_JSON = JSON.stringify({
  name: 'bashme',
  short_name: 'bashme',
  description: 'Approve requests from a paired PC.',
  start_url: '.',
  display: 'standalone',
  background_color: '#150e28',
  theme_color: '#150e28',
  icons: [
    {
      src:
        'data:image/svg+xml,' +
        encodeURIComponent(
          '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192">' +
            '<rect width="192" height="192" rx="36" fill="#150e28"/>' +
            '<circle cx="96" cy="96" r="54" fill="#cdb4ff"/>' +
            '</svg>',
        ),
      sizes: '192x192',
      type: 'image/svg+xml',
      purpose: 'any',
    },
  ],
});

/**
 * The service worker. Two jobs: make the page installable (a fetch handler is
 * what qualifies a page as a PWA on most platforms) and show a notification on
 * a push event.
 *
 * Deliberately shows a static notification regardless of push payload -- see
 * core/push.ts for why the payload is always empty. Tapping it focuses an
 * already-open tab if there is one, otherwise opens a new one at the SW's own
 * scope, which for the relay carries no secret (the key lives only in
 * localStorage, already on this device).
 */
export const SW_JS = `
self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', () => {});

self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('bashme', {
      body: 'A request is waiting for approval.',
      icon: 'data:image/svg+xml,' + encodeURIComponent(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192">' +
        '<rect width="192" height="192" rx="36" fill="#150e28"/>' +
        '<circle cx="96" cy="96" r="54" fill="#cdb4ff"/></svg>'
      ),
      tag: 'bashme-request',
      renotify: true,
      requireInteraction: true
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) { if ('focus' in c) return c.focus(); }
    if (self.clients.openWindow) return self.clients.openWindow('./');
  })());
});
`;
