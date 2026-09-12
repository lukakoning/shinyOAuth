"""Disposable SMART AS and transparent FHIR transport; Microsoft enforces access.

Only synthetic resources are seeded. Never use this fixture as a production AS.
No request URLs, credentials, resource bodies or private keys are logged.
"""
import base64
import datetime as dt
import hashlib
import html
import ipaddress
import json
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path('/runtime')


def init():
    ca = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable SMART test CA')])
    now = dt.datetime.now(dt.timezone.utc)
    common = x509.CertificateBuilder().not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
    cert = common.subject_name(name).issuer_name(name).public_key(ca.public_key()).serial_number(x509.random_serial_number()).add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(ca, hashes.SHA256())
    leaf = common.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'auth')])).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).add_extension(x509.SubjectAlternativeName([x509.DNSName('auth'), x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False).sign(ca, hashes.SHA256())
    (ROOT / 'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ROOT / 'server.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    for filename, value in [('server-key.pem', key), ('signing-key.pem', rsa.generate_private_key(public_exponent=65537, key_size=2048))]:
        (ROOT / filename).write_bytes(value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


class Fixture(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    pending, codes, refresh, access, history = {}, {}, {}, {}, []
    lock = threading.RLock()

    def log_message(self, *_):
        pass

    def send(self, status, body, content_type='application/json', **headers):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode() if content_type == 'application/json' else body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    @classmethod
    def jwt(cls, claims):
        data = b64(json.dumps({'alg': 'RS256', 'kid': 'fixture-key', 'typ': 'JWT'}).encode()) + '.' + b64(json.dumps(claims).encode())
        return data + '.' + b64(cls.key.sign(data.encode(), padding.PKCS1v15(), hashes.SHA256()))

    @classmethod
    def claims(cls, audience):
        now = int(time.time())
        return {'iss': cls.origin + '/fhir', 'aud': audience, 'iat': now, 'exp': now + 300, 'sub': 'synthetic-patient'}

    @classmethod
    def upstream(cls, path, token, method='GET', body=None):
        request = urllib.request.Request('http://fhir:8080' + path, data=body, method=method,
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/fhir+json', 'Content-Type': 'application/fhir+json'})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read(), response.headers.get('Content-Type', 'application/fhir+json')
        except urllib.error.HTTPError as response:
            return response.code, response.read(), response.headers.get('Content-Type', 'application/fhir+json')

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))
        origin = self.origin
        if path == '/health':
            return self.send(200, {'ready': True})
        if path == '/keys':
            numbers = self.key.public_key().public_numbers()
            integer = lambda value: b64(value.to_bytes((value.bit_length() + 7) // 8, 'big'))
            return self.send(200, {'keys': [{'kty': 'RSA', 'kid': 'fixture-key', 'use': 'sig', 'alg': 'RS256', 'n': integer(numbers.n), 'e': integer(numbers.e)}]})
        if path == '/oidc/.well-known/openid-configuration':
            return self.send(200, {'issuer': origin + '/fhir', 'jwks_uri': 'https://auth:8443/keys',
                'authorization_endpoint': origin + '/authorize', 'token_endpoint': origin + '/token',
                'response_types_supported': ['code'], 'subject_types_supported': ['public'], 'id_token_signing_alg_values_supported': ['RS256']})
        if path == '/fhir/.well-known/smart-configuration':
            return self.send(200, {'issuer': origin + '/fhir', 'jwks_uri': origin + '/keys',
                'authorization_endpoint': origin + '/authorize', 'token_endpoint': origin + '/token',
                'capabilities': ['launch-standalone', 'client-public', 'sso-openid-connect', 'permission-v2', 'permission-patient', 'permission-offline', 'context-standalone-patient'],
                'grant_types_supported': ['authorization_code', 'refresh_token'], 'code_challenge_methods_supported': ['S256'],
                'token_endpoint_auth_methods_supported': ['none'], 'scopes_supported': sorted(self.scopes)})
        if path == '/authorize':
            valid = all(query.get(key) == value for key, value in {'client_id': 'permissions', 'redirect_uri': self.callback,
                'response_type': 'code', 'code_challenge_method': 'S256', 'aud': origin + '/fhir'}.items())
            if not valid or set(query.get('scope', '').split()) != self.scopes or not query.get('state') or not query.get('nonce') or not query.get('code_challenge'):
                return self.send(400, {'error': 'invalid_request'})
            ticket = secrets.token_urlsafe(32)
            with self.lock:
                self.pending[ticket] = query
            return self.send(200, '<!doctype html><h1 id="provider">Protected FHIR fixture</h1><a id="approve" href="/approve?ticket=' + html.escape(ticket) + '">Approve synthetic access</a>', 'text/html')
        if path == '/approve':
            with self.lock:
                request = self.pending.pop(query.get('ticket'), None)
                code = secrets.token_urlsafe(32)
                if request:
                    self.codes[code] = request
            if not request:
                return self.send(400, {'error': 'invalid_request'})
            return self.send(302, b'', Location=self.callback + '?' + urllib.parse.urlencode({'code': code, 'state': request['state']}))
        if path == '/test/metrics':
            with self.lock:
                return self.send(200, {'requests': list(self.history)})
        if path.startswith('/fhir/') or path == '/fhir':
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            try:
                status, body, content_type = self.upstream(self.path.removeprefix('/fhir'), token)
            except (OSError, urllib.error.URLError):
                return self.send(503, {'error': 'upstream_unavailable'})
            with self.lock:
                self.history.append({'path': path, 'status': status, 'revision': self.access.get(token), 'method': 'GET'})
            return self.send(status, body, content_type)
        self.send(404, {'error': 'not_found'})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 16384:
            return self.send(400, {'error': 'invalid_request'})
        data = self.rfile.read(length)
        if self.path == '/test/seed':
            claims = self.claims(self.origin + '/fhir')
            claims.update(roles=['globalAdmin'], scope='system/*.cruds')
            token = self.jwt(claims)
            resources = [{'resourceType': 'Patient', 'id': value, 'active': True} for value in ['synthetic-p1', 'synthetic-p2']]
            resources.append({'resourceType': 'Observation', 'id': 'synthetic-observation', 'status': 'final',
                'code': {'text': 'Synthetic test observation'}, 'subject': {'reference': 'Patient/synthetic-p1'}})
            try:
                statuses = [self.upstream('/' + value['resourceType'] + '/' + value['id'], token, 'PUT', json.dumps(value).encode())[0] for value in resources]
                return self.send(200 if all(status in [200, 201] for status in statuses) else 503, {'statuses': statuses})
            except (OSError, urllib.error.URLError):
                return self.send(503, {'error': 'upstream_starting'})
        if self.path != '/token':
            return self.send(404, {'error': 'not_found'})
        body = dict(urllib.parse.parse_qsl(data.decode()))
        if body.get('client_id') != 'permissions' or self.headers.get('Authorization'):
            return self.send(400, {'error': 'invalid_client'})
        with self.lock:
            initial = body.get('grant_type') == 'authorization_code'
            if initial:
                request = self.codes.pop(body.get('code'), None)
                challenge = b64(hashlib.sha256(body.get('code_verifier', '').encode()).digest())
                if not request or body.get('redirect_uri') != self.callback or challenge != request['code_challenge']:
                    return self.send(400, {'error': 'invalid_grant'})
                grant = {'revision': 1, 'nonce': request['nonce'], 'scopes': self.scopes}
                scopes = self.scopes
            elif body.get('grant_type') == 'refresh_token':
                grant = self.refresh.pop(body.get('refresh_token'), None)
                if not grant:
                    return self.send(400, {'error': 'invalid_grant'})
                scopes = set(body.get('scope', ' '.join(grant['scopes'])).split())
                if not scopes or not scopes <= (grant['scopes'] | {'patient/Patient.r'}):
                    return self.send(400, {'error': 'invalid_scope'})
                grant = {**grant, 'revision': grant['revision'] + 1, 'scopes': scopes}
            else:
                return self.send(400, {'error': 'unsupported_grant_type'})
            claims = self.claims(self.origin + '/fhir')
            claims.update(roles=['smartUser'], scope=' '.join(sorted(scopes)), fhirUser=self.origin + '/fhir/Patient/synthetic-p1', jti=secrets.token_urlsafe(16))
            access = self.jwt(claims)
            refresh = secrets.token_urlsafe(32)
            self.access[access] = grant['revision']
            self.refresh[refresh] = grant
            token = {'access_token': access, 'refresh_token': refresh, 'token_type': 'Bearer', 'expires_in': 300,
                'scope': ' '.join(sorted(scopes)), 'patient': 'synthetic-p1'}
            if initial:
                identity = self.claims('permissions')
                identity.update(nonce=grant['nonce'], fhirUser=self.origin + '/fhir/Patient/synthetic-p1')
                token['id_token'] = self.jwt(identity)
            return self.send(200, token)


if __name__ == '__main__':
    if '--init' in sys.argv:
        init()
    else:
        config = json.loads((ROOT / 'config.json').read_text())
        Fixture.origin, Fixture.callback = config['origin'], config['callback']
        Fixture.scopes = {'launch/patient', 'patient/Patient.rs', 'offline_access', 'openid', 'fhirUser'}
        Fixture.key = serialization.load_pem_private_key((ROOT / 'signing-key.pem').read_bytes(), password=None)
        server = ThreadingHTTPServer(('0.0.0.0', 8443), Fixture)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT / 'server.pem', ROOT / 'server-key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
