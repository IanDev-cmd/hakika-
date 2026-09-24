var CACHE = 'hakika-v8';
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
  e.waitUntil(caches.keys().then(function(keys){
    return Promise.all(keys.filter(function(k){ return k !== CACHE; }).map(function(k){ return caches.delete(k); }));
  }).then(function(){ return self.clients.claim(); }));
});
self.addEventListener('fetch', function(e){
  var url = new URL(e.request.url);
  if(url.pathname.indexOf('/api/') === 0) return;
  if(e.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')){
    e.respondWith(fetch(e.request).then(function(res){
      var copy = res.clone();
      caches.open(CACHE).then(function(c){ c.put(e.request, copy); });
      return res;
    }).catch(function(){ return caches.match(e.request); }));
    return;
  }
  e.respondWith(caches.match(e.request).then(function(hit){ return hit || fetch(e.request); }));
});
