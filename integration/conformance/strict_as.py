"""Local test AS: independent RS256 JAR, ES256 DPoP, mTLS and signed JARM.

Only the explicitly tested profile is implemented. This is a test fixture,
not an authorization server for deployment or a certification suite.
"""
import base64
import hashlib
import json
import secrets
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.x509.oid import NameOID


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


root = Path(sys.argv[1])
registered_key = serialization.load_pem_public_key((root / 'registered.pem').read_bytes())
ca_key = rsa.generate_private_key(65537, 2048)
server_key = rsa.generate_private_key(65537, 2048)
client_key = rsa.generate_private_key(65537, 2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Conformance test CA')])


def certificate(name, key, ca=False):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if name == 'localhost':
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
    return builder.sign(ca_key, hashes.SHA256())


ca_cert = certificate('Conformance test CA', ca_key, True)
client_cert = certificate('registered-mtls-client', client_key)
for name, cert, key in [('ca', ca_cert, ca_key),
                        ('server', certificate('localhost', server_key), server_key),
                        ('client', client_cert, client_key)]:
    (root / (name + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / (name + '-key.pem')).write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

client_der = client_cert.public_bytes(serialization.Encoding.DER)
seen = set()
codes = {}
pushed = {}
issuer = None


def verify_jar(token):
    require(bool(token), 'signed_request_required')
    h, p, s = token.split('.')
    header, claims = json.loads(unb64(h)), json.loads(unb64(p))
    require(header.get('alg') == 'RS256', 'jar_algorithm')
    registered_key.verify(unb64(s), (h + '.' + p).encode(), padding.PKCS1v15(), hashes.SHA256())
    require(claims.get('iss') == 'client' and claims.get('client_id') == 'client', 'jar_issuer')
    require(claims.get('aud') == issuer, 'jar_audience')
    now = time.time()
    require(isinstance(claims.get('exp'), (int, float)) and claims['exp'] > now, 'jar_expired')
    require(claims.get('iat', now + 60) <= now + 5, 'jar_issued_at')
    require(claims.get('nbf', 0) <= now + 5, 'jar_not_before')
    require(bool(claims.get('jti')) and claims['jti'] not in seen, 'jar_replay')
    require(claims.get('response_type') == 'code', 'response_type')
    require(claims.get('redirect_uri') == 'https://app.example.com/callback', 'redirect_uri')
    require(claims.get('code_challenge_method') == 'S256', 'pkce_required')
    seen.add(claims['jti'])
    return claims


def verify_dpop(token, expected_jkt):
    require(bool(token), 'dpop_required')
    h, p, s = token.split('.')
    header, claims = json.loads(unb64(h)), json.loads(unb64(p))
    require(header.get('typ') == 'dpop+jwt' and header.get('alg') == 'ES256', 'dpop_header')
    jwk = header['jwk']
    require(jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256' and 'd' not in jwk, 'dpop_key')
    thumb = b64(hashlib.sha256(encode({k: jwk[k] for k in ('kty', 'crv', 'x', 'y')})).digest())
    require(thumb == expected_jkt, 'dpop_binding')
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(jwk['x']), 'big'),
        int.from_bytes(unb64(jwk['y']), 'big'), ec.SECP256R1()).public_key()
    signature = unb64(s)
    require(len(signature) == 64, 'dpop_signature')
    key.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'),
        int.from_bytes(signature[32:], 'big')), (h + '.' + p).encode(), ec.ECDSA(hashes.SHA256()))
    require(claims.get('htm') == 'POST' and claims.get('htu') == issuer + '/token', 'dpop_target')
    require(abs(time.time() - claims.get('iat', 0)) < 60, 'dpop_time')
    require(bool(claims.get('jti')) and claims['jti'] not in seen, 'dpop_replay')
    seen.add(claims['jti'])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, data, location=None):
        body = encode(data)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if location:
            self.send_header('Location', location)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def dispatch(self):
        try:
            path = urlsplit(self.path).path
            query = urlsplit(self.path).query
            if self.command == 'POST':
                size = int(self.headers.get('Content-Length', '0'))
                require(0 < size < 65536, 'body_size')
                query = self.rfile.read(size).decode()
            parsed = parse_qs(query, keep_blank_values=True)
            require(all(len(v) == 1 for v in parsed.values()), 'duplicate_parameter')
            params = {k: v[0] for k, v in parsed.items()}
            if path == '/jwks':
                n = server_key.public_key().public_numbers()
                return self.respond(200, {'keys': [{'kty': 'RSA', 'kid': 'as', 'use': 'sig',
                    'alg': 'RS256', 'n': b64(n.n.to_bytes(256, 'big')), 'e': b64(n.e.to_bytes(3, 'big'))}]})
            if path in ('/authorize', '/par'):
                if 'request_uri' in params:
                    require(params['request_uri'] in pushed, 'par_replay')
                    claims = pushed.pop(params['request_uri'])
                else:
                    claims = verify_jar(params.get('request'))
                if path == '/par':
                    handle = 'urn:strict:par:' + secrets.token_urlsafe(24)
                    pushed[handle] = claims
                    return self.respond(201, {'request_uri': handle, 'expires_in': 60})
                require(claims['exp'] > time.time(), 'jar_expired')
                code = secrets.token_urlsafe(24)
                codes[code] = claims
                response = {'code': code, 'state': claims['state'], 'iss': issuer}
                if claims.get('response_mode') == 'query.jwt':
                    payload = dict(response, aud='client', iat=int(time.time()), exp=int(time.time()) + 60)
                    signing = b64(encode({'alg': 'RS256', 'typ': 'oauth-authz-resp+jwt', 'kid': 'as'})) + '.' + b64(encode(payload))
                    response = {'response': signing + '.' + b64(server_key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))}
                return self.respond(302, {}, claims['redirect_uri'] + '?' + urlencode(response))
            if path == '/token':
                require(params.get('code') in codes, 'invalid_code')
                claims = codes[params['code']]
                require(params.get('client_id') == 'client', 'client_id')
                require(params.get('redirect_uri') == claims['redirect_uri'], 'redirect_uri')
                challenge = b64(hashlib.sha256(params.get('code_verifier', '').encode()).digest())
                require(challenge == claims['code_challenge'], 'pkce_mismatch')
                cnf = {}
                if claims.get('dpop_jkt'):
                    verify_dpop(self.headers.get('DPoP'), claims['dpop_jkt'])
                    cnf = {'jkt': claims['dpop_jkt']}
                if 'mtls' in claims.get('scope', '').split():
                    require(self.connection.getpeercert(binary_form=True) == client_der, 'mtls_certificate')
                    cnf = {'x5t#S256': b64(hashlib.sha256(client_der).digest())}
                del codes[params['code']]
                return self.respond(200, {'access_token': secrets.token_urlsafe(32),
                    'token_type': 'DPoP' if 'jkt' in cnf else 'Bearer', 'expires_in': 60,
                    'scope': claims.get('scope', ''), 'cnf': cnf})
            self.respond(404, {'error': 'unknown_endpoint'})
        except Exception as error:
            self.respond(400, {'error': 'invalid_request', 'reason': str(error) or type(error).__name__})


server = HTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'server.pem', root / 'server-key.pem')
context.load_verify_locations(root / 'ca.pem')
context.verify_mode = ssl.CERT_OPTIONAL
server.socket = context.wrap_socket(server.socket, server_side=True)
issuer = 'https://localhost:' + str(server.server_port)
print(json.dumps({'issuer': issuer}), flush=True)
server.serve_forever()
