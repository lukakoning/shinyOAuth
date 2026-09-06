// Loopback-only HTTPS origins for browser storage-isolation regression tests.
const https = require('node:https');
const fs = require('node:fs');
const [source, cert, key] = process.argv.slice(2).map(p => fs.readFileSync(p));
const page = `<!doctype html><title>Binding fixture</title><script>
window.inputs = {};
window.Shiny = {handlers: {},
  addCustomMessageHandler: function(k, fn) { this.handlers[k] = fn; },
  setInputValue: function(k, v) { window.inputs[k] = v; }};
</script><script src="/shinyOAuth.js"></script>`;
async function start() {
  const server = https.createServer({cert, key}, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/shinyOAuth.js') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(source);
    } else if (req.url === '/cookie') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({cookie: req.headers.cookie || ''}));
    } else {
      res.setHeader('Content-Type', 'text/html');
      res.end(page);
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}
Promise.all([start(), start()]).then(ports => console.log(JSON.stringify(ports)));
