"""Regenerate the public, synthetic Ed25519 mTLS registration test fixture."""

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID


directory = Path(__file__).parent
key = ed25519.Ed25519PrivateKey.generate()
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shinyOAuth-test-ed25519")])
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
    .sign(key, algorithm=None)
)
directory.joinpath("ed25519-client-key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
directory.joinpath("ed25519-client-cert.pem").write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)
