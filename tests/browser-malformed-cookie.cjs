const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');

for (const protocol of ['http:', 'https:']) {
  for (const malformed of ['%', '%A', '%ZZ', '%C3%28', '%ED%A0%80']) {
    for (const blocked of [false, true]) {
      const base = 'shinyOAuth_sid-auth';
      const name = protocol === 'https:' ? '__Host-' + base : base;
      const cookies = new Map([[base, malformed], ['__Host-' + base, malformed]]);
      const writes = [], inputs = {}, handlers = {}, storage = new Map();
      const document = {};
      Object.defineProperty(document, 'cookie', {
        get: () => Array.from(cookies, ([k, v]) => k + '=' + v).join('; '),
        set: value => {
          writes.push(value);
          if (blocked) return;
          const [k, v] = value.split(';')[0].split('=');
          if (/Max-Age=0(?:;|$)/.test(value)) cookies.delete(k);
          else cookies.set(k, v);
        }
      });
      const Shiny = {addCustomMessageHandler: (k, fn) => handlers[k] = fn,
        setInputValue: (k, v) => inputs[k] = v};
      const window = {Shiny, location: {protocol, pathname: '/app'},
        crypto: require('node:crypto').webcrypto,
        localStorage: {getItem: k => storage.get(k) ?? null,
          setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k)}};
      vm.runInNewContext(source, {window, document, Shiny});
      const send = extra => handlers['shinyOAuth:setBrowserToken']({instance: 'auth',
        path: '/app', inputId: 'sid', ackInputId: 'ack', errorInputId: 'error', ...extra});
      // Bootstrap repairs the malformed marker and creates a fresh binding.
      send();
      assert.ok(writes.some(v => v.startsWith(base + '=; Max-Age=0;')));
      if (protocol === 'https:') {
        assert.ok(writes.some(v => v.startsWith('__Host-' + base + '=; Max-Age=0;')));
      }
      if (!blocked) {
        assert.match(inputs.sid, /^[a-f0-9]{128}$/);
        assert.match(cookies.get(name), /^[a-f0-9]{128}$/);
        assert.notEqual(cookies.get(name), inputs.sid);
      }
      send({requestId: 'current', token: 'b'.repeat(128)});
      if (blocked) {
        assert.equal(inputs.ack, undefined);
        assert.equal(inputs.error, 'cookie_unavailable');
      } else {
        assert.equal(inputs.sid, 'b'.repeat(128));
        assert.equal(inputs.ack.requestId, 'current');
        assert.equal(inputs.error, undefined);
        send();
        assert.equal(inputs.sid, 'b'.repeat(128), 'a repaired marker survives the next read');
      }
    }
  }
}
