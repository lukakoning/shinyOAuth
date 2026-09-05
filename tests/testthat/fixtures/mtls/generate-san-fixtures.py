"""Regenerate public SAN fixtures with the existing, test-only client key."""
from pathlib import Path
from datetime import datetime, timezone
from ipaddress import ip_address
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

root = Path(__file__).parent
key = serialization.load_pem_private_key((root / 'client-key.pem').read_bytes(), password=None)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SAN registration test')])
for filename, sans in {
    'numeric-dns-cert.pem': [x509.DNSName('192.0.2.10')],
    'typed-san-cert.pem': [x509.DNSName('client.example.com'),
        x509.IPAddress(ip_address('192.0.2.10')),
        x509.UniformResourceIdentifier('urn:example:client'),
        x509.RFC822Name('client@example.com')]
}.items():
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(100 if filename.startswith('numeric') else 101)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256()))
    (root / filename).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
