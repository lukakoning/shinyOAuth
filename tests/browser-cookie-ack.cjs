const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
let now = 0, stored = '', expiry = 0, blocked = false;
const handlers = {}, inputs = {};
const storage = new Map();
const document = {addEventListener() {}};
Object.defineProperty(document, 'cookie', {
  get: () => now < expiry ? stored : '',
  set: value => {
    if (blocked) return;
    stored = value.split(';')[0];
    expiry = now + Number(value.match(/Max-Age=(\d+)/)[1]);
  }
});
const Shiny = {addCustomMessageHandler: (k, fn) => handlers[k] = fn,
  setInputValue: (k, v) => inputs[k] = v};
const window = {Shiny, location: {protocol: 'https:', pathname: '/'},
  localStorage: {getItem: k => storage.get(k) ?? null,
    setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k)},
  crypto: require('node:crypto').webcrypto};
vm.runInNewContext(source, {window, document, Shiny});
const send = () => handlers['shinyOAuth:setBrowserToken']({instance: 'test',
  maxAgeMs: 3000, requestId: 'current', token: require('node:crypto').randomBytes(64).toString('hex'),
  ackInputId: 'ack', inputId: 'sid', errorInputId: 'error'});
send();
const old = inputs.sid;
now = 4; // Cookie expires while its Shiny mirror remains.
assert.equal(document.cookie, '');
send();
assert.notEqual(inputs.sid, old);
assert.equal(inputs.ack.token, undefined);
assert.equal(inputs.ack.requestId, 'current');
expiry = 0; // User deletion also rotates before acknowledgment.
send();
assert.ok(!document.cookie.includes(inputs.sid));
assert.equal(JSON.parse(storage.get('__Host-shinyOAuth_sid-test:binding')).token, inputs.sid);
expiry = 0; blocked = true; delete inputs.ack;
send();
assert.equal(inputs.ack, undefined);
assert.equal(inputs.error, 'cookie_unavailable');
