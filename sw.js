var CACHE = 'hakika-v2';
var FILES = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/hakika-photos/hakika-face.png',
  '/hakika-photos/hakika-voice.png',
  '/hakika-photos/hakika-finger.png',
  '/hakika-photos/hakika-icon.png',
  '/hakika-photos/hakika-icon-512.png'
];
self.addEventListener('install', function(e){
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(FILES); }).then(function(){ return self.skipWaiting(); }));
});
self.addEventListener('activate', function(e){
  e.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', function(e){
  e.respondWith(caches.match(e.request).then(function(hit){ return hit || fetch(e.request); }));
});
