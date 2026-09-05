const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
for (const path of ['/', '/app']) {
  const planted = 'a'.repeat(128);
  const writes = [];
  const inputs = {};
  const handlers = {};
  const document = {addEventListener() {}};
  Object.defineProperty(document, 'cookie', {
    get: () => 'shinyOAuth_sid-auth=' + planted,
    set: value => writes.push(value)
  });
  const Shiny = {
    addCustomMessageHandler: (name, fn) => { handlers[name] = fn; },
    setInputValue: (name, value) => { inputs[name] = value; }
  };
  const window = {Shiny, location: {protocol: 'https:', pathname: '/app'},
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
