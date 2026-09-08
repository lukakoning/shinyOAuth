"""Loopback-only TLS fixture requiring the test CA's client certificate."""
import http.server
from pathlib import Path
import ssl

fixtures = Path(__file__).resolve().parent


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'client certificate accepted'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(fixtures / 'server-cert.pem', fixtures / 'client-key.pem')
context.load_verify_locations(fixtures / 'ca-cert.pem')
context.verify_mode = ssl.CERT_REQUIRED
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
