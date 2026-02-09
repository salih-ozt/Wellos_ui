/*
 * =============================================================================
 * AGROLINK SERVICE WORKER - WEB PUSH NOTIFICATIONS
 * =============================================================================
 * Chrome, Firefox, Edge, Safari 16.4+ destekli gerçek Web Push sistemi
 * =============================================================================
 */

const CACHE_VERSION = 'agrolink-v1';
const urlsToCache = [
    '/',
    '/index.html'
];

// ========== KURULUM ==========
self.addEventListener('install', (event) => {
    console.log('✅ Service Worker yüklendi');
    event.waitUntil(
        caches.open(CACHE_VERSION)
            .then((cache) => {
                console.log('📦 Cache açıldı');
                return cache.addAll(urlsToCache);
            })
    );
    self.skipWaiting(); // Hemen aktif et
});

// ========== AKTİVASYON ==========
self.addEventListener('activate', (event) => {
    console.log('🚀 Service Worker aktif edildi');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_VERSION) {
                        console.log('🗑️ Eski cache silindi:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
    return self.clients.claim();
});

// ========== PUSH NOTIFICATION ALGILAMA ==========
self.addEventListener('push', (event) => {
    console.log('🔔 Push bildirimi alındı:', event);
    
    let notificationData = {
        title: 'AgroLink Bildirimi',
        body: 'Yeni bir bildiriminiz var!',
        icon: '/icon-192.png',
        badge: '/badge-72.png',
        vibrate: [200, 100, 200],
        tag: 'agrolink-notification',
        requireInteraction: false,
        data: {
            url: '/',
            timestamp: Date.now()
        }
    };

    // Push data varsa parse et
    if (event.data) {
        try {
            const data = event.data.json();
            notificationData = {
                title: data.title || notificationData.title,
                body: data.body || data.message || notificationData.body,
                icon: data.icon || notificationData.icon,
                badge: data.badge || notificationData.badge,
                vibrate: data.vibrate || notificationData.vibrate,
                tag: data.tag || notificationData.tag,
                requireInteraction: data.requireInteraction || false,
                data: {
                    url: data.url || '/',
                    postId: data.postId,
                    userId: data.userId,
                    type: data.type,
                    timestamp: Date.now()
                },
                actions: data.actions || []
            };
        } catch (e) {
            console.log('📝 Push data text:', event.data.text());
            notificationData.body = event.data.text();
        }
    }

    // Bildirimi göster
    event.waitUntil(
        self.registration.showNotification(notificationData.title, {
            body: notificationData.body,
            icon: notificationData.icon,
            badge: notificationData.badge,
            vibrate: notificationData.vibrate,
            tag: notificationData.tag,
            requireInteraction: notificationData.requireInteraction,
            data: notificationData.data,
            actions: notificationData.actions
        })
    );
});

// ========== BİLDİRİME TIKLAMA ==========
self.addEventListener('notificationclick', (event) => {
    console.log('👆 Bildirime tıklandı:', event.notification.tag);
    
    event.notification.close(); // Bildirimi kapat

    // Action'a tıklanmışsa
    if (event.action) {
        console.log('🎬 Action:', event.action);
        // Burada action'lara göre farklı işlemler yapabilirsin
    }

    // URL'yi aç
    const urlToOpen = event.notification.data?.url || '/';
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                // Zaten açık bir pencere var mı?
                for (let client of clientList) {
                    if (client.url === urlToOpen && 'focus' in client) {
                        return client.focus();
                    }
                }
                // Yoksa yeni pencere aç
                if (clients.openWindow) {
                    return clients.openWindow(urlToOpen);
                }
            })
    );
});

// ========== BİLDİRİM KAPANDI ==========
self.addEventListener('notificationclose', (event) => {
    console.log('❌ Bildirim kapatıldı:', event.notification.tag);
    
    // Analytics veya tracking için kullanılabilir
    event.waitUntil(
        fetch('/api/notification/closed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tag: event.notification.tag,
                timestamp: Date.now()
            })
        }).catch(() => {}) // Hata olursa sessizce devam et
    );
});

// ========== FETCH EVENTI (Offline desteği) ==========
self.addEventListener('fetch', (event) => {
    // Sadece GET isteklerini cache'le
    if (event.request.method !== 'GET') {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then((response) => {
                // Cache'de varsa onu döndür
                if (response) {
                    return response;
                }
                
                // Yoksa network'ten al
                return fetch(event.request).then((response) => {
                    // Geçersiz response ise cache'leme
                    if (!response || response.status !== 200 || response.type === 'error') {
                        return response;
                    }

                    // Response'u cache'e ekle
                    const responseToCache = response.clone();
                    caches.open(CACHE_VERSION).then((cache) => {
                        cache.put(event.request, responseToCache);
                    });

                    return response;
                });
            })
            .catch(() => {
                // Offline durum için fallback
                return caches.match('/offline.html');
            })
    );
});

// ========== SYNC EVENT (Background Sync) ==========
self.addEventListener('sync', (event) => {
    console.log('🔄 Background sync:', event.tag);
    
    if (event.tag === 'sync-posts') {
        event.waitUntil(syncPosts());
    }
});

async function syncPosts() {
    try {
        // Pending post'ları gönder
        const response = await fetch('/api/posts/sync');
        console.log('✅ Post'lar senkronize edildi');
    } catch (error) {
        console.error('❌ Sync hatası:', error);
    }
}

console.log('🎯 Service Worker hazır!');
