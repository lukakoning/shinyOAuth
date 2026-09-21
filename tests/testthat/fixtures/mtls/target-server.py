"""Local OAuth target fixture with mandatory TLS client authentication."""
import base64
import hashlib
import http.server
import json
from pathlib import Path
import socketserver
import ssl
from urllib.parse import parse_qs

fixtures = Path(__file__).resolve().parent


class Handler(http.server.BaseHTTPRequestHandler):
    def certificate(self):
        digest = hashlib.sha256(self.connection.getpeercert(binary_form=True)).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def respond(self, body, status=200):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        resource = body["resource"][0]
        target = resource.removeprefix("urn:")
        if target == "secondary" and body.get("refresh_token") != ["primary-rt"]:
            return self.respond({"error": "invalid_grant"}, 400)
        self.server.certificates.append(self.certificate())
        self.server.resources.append(resource)
        self.respond({"access_token": target + "-at", "refresh_token": target + "-rt",
                      "token_type": "Bearer", "scope": body["scope"][0], "expires_in": 3600,
                      "cnf": {"x5t#S256": self.certificate()}})

    def do_GET(self):
        self.respond({"authorization": self.headers.get("Authorization"),
                      "certificate": self.certificate(),
                      "token_certificates": self.server.certificates,
                      "resources": self.server.resources})

    def log_message(self, *args):
        pass


class LoopbackServer(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(fixtures / "server-cert.pem", fixtures / "client-key.pem")
context.load_verify_locations(fixtures / "ca-cert.pem")
context.verify_mode = ssl.CERT_REQUIRED
server = LoopbackServer(("127.0.0.1", 0), Handler)
server.certificates = []
server.resources = []
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
