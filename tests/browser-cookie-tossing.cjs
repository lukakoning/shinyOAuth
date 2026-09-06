const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
for (const path of ['/', '/app']) {
  const planted = 'a'.repeat(128);
  const writes = [];
  const inputs = {};
  const handlers = {};
  const storage = new Map();
  const document = {addEventListener() {}};
  const cookies = new Map([['shinyOAuth_sid-auth', planted]]);
  Object.defineProperty(document, 'cookie', {
    get: () => Array.from(cookies, ([key, value]) => key + '=' + value).join('; '),
    set: value => {
      writes.push(value);
      const [name, token] = value.split(';')[0].split('=');
      cookies.set(name, token);
    }
  });
  const Shiny = {
    addCustomMessageHandler: (name, fn) => { handlers[name] = fn; },
    setInputValue: (name, value) => { inputs[name] = value; }
  };
  const window = {Shiny, location: {protocol: 'https:', pathname: '/app'},
    localStorage: {getItem: k => storage.get(k) ?? null,
      setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k)},
    crypto: require('node:crypto').webcrypto};
  vm.runInNewContext(source, {window, document, Shiny, console});
  handlers['shinyOAuth:setBrowserToken']({instance: 'auth', path,
    inputId: 'sid', errorInputId: 'error'});
  assert.match(inputs.sid, /^[a-f0-9]{128}$/);
  assert.notEqual(inputs.sid, planted);
  assert.match(writes[0], /^__Host-shinyOAuth_sid-auth=/);
  assert.match(writes[0], /; Path=\/;/);
  assert.match(writes[0], /; Secure$/);
  assert.ok(!writes[0].includes('Domain='));
}
