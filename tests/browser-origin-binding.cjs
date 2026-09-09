const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const handlers = {}, inputs = {}, storage = new Map(), cookies = new Map();
const name = '__Host-shinyOAuth_sid-auth', key = name + ':binding';
let blocked = false, silentlyBlocked = false;
const document = {};
Object.defineProperty(document, 'cookie', {
  get: () => Array.from(cookies, ([k, v]) => k + '=' + v).join('; '),
  set: value => {
    const [k, v] = value.split(';')[0].split('=');
    if (/Max-Age=0(?:;|$)/.test(value)) cookies.delete(k);
    else cookies.set(k, v);
  }
});
const Shiny = {addCustomMessageHandler: (k, fn) => handlers[k] = fn,
  setInputValue: (k, v) => inputs[k] = v};
const window = {Shiny, location: {protocol: 'https:', pathname: '/'},
  crypto: require('node:crypto').webcrypto,
  sessionStorage: {
    getItem(k) { if (blocked) throw new Error('blocked'); return storage.get(k) ?? null; },
    setItem(k, v) { if (blocked) throw new Error('blocked'); if (!silentlyBlocked) storage.set(k, v); },
    removeItem(k) { storage.delete(k); }
  }};
vm.runInNewContext(source, {window, document, Shiny});
const payload = {instance: 'auth', inputId: 'sid', ackInputId: 'ack', errorInputId: 'error'};
const send = extra => handlers['shinyOAuth:setBrowserToken']({...payload, ...extra});
send();
const initial = inputs.sid, initialCookie = document.cookie;
assert.match(initial, /^[a-f0-9]{128}$/);
assert.ok(!document.cookie.includes(initial), 'the cookie must not contain the binding token');
send();
assert.equal(inputs.sid, initial, 'an intact origin record survives page loads');
assert.equal(document.cookie, initialCookie);

// Cookie-only values cannot establish the origin record, including legacy
// cookies, a marker from another port, or an otherwise valid token.
for (const saved of [null, '{broken', JSON.stringify({version: 1, token: initial,
  cookie: initialCookie.split('=')[1], expiresAt: Date.now() - 1})]) {
  if (saved === null) storage.delete(key); else storage.set(key, saved);
  cookies.clear(); document.cookie = initialCookie;
  send();
  assert.notEqual(inputs.sid, initial);
  assert.notEqual(document.cookie, initialCookie);
}
const before = inputs.sid;
document.cookie = name + '-' + JSON.parse(storage.get(key)).id + '=' + 'a'.repeat(128);
send();
assert.notEqual(inputs.sid, before);
assert.notEqual(inputs.sid, 'a'.repeat(128));

const selected = 'b'.repeat(128);
cookies.clear(); storage.clear();
send();
send({requestId: 'fresh', token: selected});
assert.equal(inputs.sid, selected);
assert.equal(inputs.ack.requestId, 'fresh');
assert.equal(inputs.ack.token, undefined);
assert.ok(!document.cookie.includes(selected));
assert.equal(cookies.size, 1, 'login removes its idle predecessor');
handlers['shinyOAuth:clearBrowserToken'](payload);
assert.equal(storage.has(key), false);
assert.equal(document.cookie, '');
assert.equal(inputs.sid, null);

const clear = extra => handlers['shinyOAuth:clearBrowserToken']({...payload, ...extra});
for (let cycle = 0; cycle < 3; cycle++) {
  send(); // bootstrap or post-logout idle binding
  send({requestId: 'login', token: selected});
  assert.equal(cookies.size, 1, 'login removes its idle predecessor');
  clear({token: selected});
  assert.equal(cookies.size, 0, 'successful login removes the transaction marker');
  send(); // post-login idle binding
  clear(); // logout
  assert.equal(cookies.size, 0, 'logout removes the idle marker');
  send(); // post-logout idle binding
  assert.equal(cookies.size, 1);
  assert.equal(storage.size, 1);
}

// Simulate a cloned tab by restoring copies of the tab-scoped record while
// keeping the shared cookie jar. Live and legacy predecessors must survive.
for (const legacy of [false, true]) {
  cookies.clear(); storage.clear();
  send({requestId: 'original', token: selected});
  const saved = JSON.parse(storage.get(key));
  if (legacy) delete saved.transaction;
  const originalRecord = JSON.stringify(saved);
  storage.set(key, originalRecord); // clone's copy
  send({requestId: 'clone', token: 'c'.repeat(128)});
  assert.equal(cookies.size, 2, 'a cloned tab preserves the pending predecessor');
  clear({token: selected}); // delayed clear for copied original binding
  assert.equal(cookies.size, 2);
  clear({token: 'c'.repeat(128)});
  assert.equal(cookies.size, 1);
  storage.set(key, originalRecord); // original tab returns for its callback
  send();
  assert.equal(inputs.sid, selected, 'the original pending binding still works');
  clear({token: selected});
  assert.equal(cookies.size, 0);
}

for (const failure of ['throw', 'silent']) {
  blocked = failure === 'throw'; silentlyBlocked = failure === 'silent';
  delete inputs.ack;
  send({requestId: 'blocked', token: selected});
  assert.equal(inputs.ack, undefined);
  assert.equal(inputs.sid, null);
  assert.equal(inputs.error, 'storage_unavailable');
}
