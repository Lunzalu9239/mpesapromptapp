self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET'||/^\/(api|telegram)\//.test(new URL(r.url).pathname))return;
e.respondWith(fetch(r).then(x=>{const c=x.clone();caches.open('v1').then(k=>k.put(r,c));return x}).catch(()=>caches.match(r)))});
