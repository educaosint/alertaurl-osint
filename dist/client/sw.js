const CACHE='alertaurl-osint-v1';
const SHELL=['/','/assets/styles.css?v=18','/assets/app.js?v=18','/assets/logo.png','/assets/icon-192.png','/assets/icon-512.png','/manifest.webmanifest','/privacidad/','/terminos/','/creditos/'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET'||new URL(request.url).pathname.startsWith('/api/'))return;
  event.respondWith(fetch(request).then(response=>{
    const copy=response.clone();
    if(response.ok&&new URL(request.url).origin===self.location.origin)caches.open(CACHE).then(cache=>cache.put(request,copy));
    return response;
  }).catch(()=>caches.match(request).then(hit=>hit||caches.match('/'))));
});
