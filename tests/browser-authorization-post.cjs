const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const handlers = {};
let submitted, attached = 0, removed = 0;
const document = { addEventListener() {}, body: { appendChild() { attached++; } },
  createElement(tag) {
    assert.ok(['form', 'input'].includes(tag));
    const node = { children: [], appendChild(input) { this.children.push(input); },
      remove() { removed++; } };
    Object.defineProperty(node, 'innerHTML', { set() { throw Error('Use DOM values'); } });
    return node;
  } };
const Shiny = { addCustomMessageHandler: (name, fn) => handlers[name] = fn };
const window = { Shiny };
const HTMLFormElement = { prototype: { submit() { submitted = this; } } };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'),
  { window, document, Shiny, HTMLFormElement, URL, URLSearchParams });
const send = handlers['shinyOAuth:authorizePost'];
const request = { method: 'POST', url: 'https://provider.example/authorize?tenant=a%2Bb', fields: [
  { name: 'scope', value: 'read write' }, { name: 'resource', value: 'https://api.example/a' },
  { name: 'resource', value: 'https://api.example/b' }, { name: 'login_hint', value: 'A+B & <literal> "quote" é' },
  { name: 'submit', value: 'provider extension' }
] };
send(request);
assert.equal(attached, 1);
assert.equal(removed, 1);
assert.equal(submitted.action, request.url);
assert.equal(submitted.method, 'POST');
assert.equal(submitted.enctype, 'application/x-www-form-urlencoded');
assert.equal(submitted.acceptCharset, 'UTF-8');
assert.equal(submitted.target, '_self');
assert.equal(submitted.children.length, request.fields.length);
request.fields.forEach((field, i) => {
  assert.equal(submitted.children[i].name, field.name);
  assert.equal(submitted.children[i].value, field.value);
  assert.equal(submitted.children[i].type, 'hidden');
});
for (const invalid of [null, {}, { ...request, method: 'GET' },
  { ...request, fields: [{ name: 'login_hint', value: 'line\nbreak' }] },
  { ...request, fields: [{ name: '_charset_', value: 'changed by browser' }] },
  { ...request, fields: [{ name: 'scope', value: 'x'.repeat(131073) }] },
  { ...request, fields: Array(257).fill({ name: 'resource', value: 'x' }) }]) {
  submitted = null;
  send(invalid);
  assert.equal(submitted, null);
  assert.equal(attached, 1);
}
