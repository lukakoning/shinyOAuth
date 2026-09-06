const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const handlers = {}, inputs = {}, storage = new Map();
const name = '__Host-shinyOAuth_sid-auth', key = name + ':binding';
let cookie = '', blocked = false, silentlyBlocked = false;
const document = {};
Object.defineProperty(document, 'cookie', {
  get: () => cookie,
  set: value => { cookie = /Max-Age=0(?:;|$)/.test(value) ? '' : value.split(';')[0]; }
});
const Shiny = {addCustomMessageHandler: (k, fn) => handlers[k] = fn,
  setInputValue: (k, v) => inputs[k] = v};
const window = {Shiny, location: {protocol: 'https:', pathname: '/'},
  crypto: require('node:crypto').webcrypto,
  localStorage: {
    getItem(k) { if (blocked) throw new Error('blocked'); return storage.get(k) ?? null; },
    setItem(k, v) { if (blocked) throw new Error('blocked'); if (!silentlyBlocked) storage.set(k, v); },
    removeItem(k) { storage.delete(k); }
  }};
vm.runInNewContext(source, {window, document, Shiny});
const payload = {instance: 'auth', inputId: 'sid', ackInputId: 'ack', errorInputId: 'error'};
const send = extra => handlers['shinyOAuth:setBrowserToken']({...payload, ...extra});
send();
const initial = inputs.sid, initialCookie = cookie;
assert.match(initial, /^[a-f0-9]{128}$/);
assert.ok(!cookie.includes(initial), 'the cookie must not contain the binding token');
send();
assert.equal(inputs.sid, initial, 'an intact origin record survives page loads');
assert.equal(cookie, initialCookie);

// Cookie-only values cannot establish the origin record, including legacy
// cookies, a marker from another port, or an otherwise valid token.
for (const saved of [null, '{broken', JSON.stringify({version: 1, token: initial,
  cookie: initialCookie.split('=')[1], expiresAt: Date.now() - 1})]) {
  if (saved === null) storage.delete(key); else storage.set(key, saved);
  cookie = initialCookie;
  send();
  assert.notEqual(inputs.sid, initial);
  assert.notEqual(cookie, initialCookie);
}
const before = inputs.sid;
cookie = name + '=' + 'a'.repeat(128);
send();
assert.notEqual(inputs.sid, before);
assert.notEqual(inputs.sid, 'a'.repeat(128));

const selected = 'b'.repeat(128);
send({requestId: 'fresh', token: selected});
assert.equal(inputs.sid, selected);
assert.equal(inputs.ack.requestId, 'fresh');
assert.equal(inputs.ack.token, undefined);
assert.ok(!cookie.includes(selected));
handlers['shinyOAuth:clearBrowserToken'](payload);
assert.equal(storage.has(key), false);
assert.equal(cookie, '');
assert.equal(inputs.sid, null);

for (const failure of ['throw', 'silent']) {
  blocked = failure === 'throw'; silentlyBlocked = failure === 'silent';
  delete inputs.ack;
  send({requestId: 'blocked', token: selected});
  assert.equal(inputs.ack, undefined);
  assert.equal(inputs.sid, null);
  assert.equal(inputs.error, 'storage_unavailable');
}
