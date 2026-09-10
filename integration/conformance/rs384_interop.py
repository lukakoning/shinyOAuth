"""Independent RS384 signature oracle for ephemeral conformance test material.

No shinyOAuth or R/jose code is used to parse, sign, verify or hash these JWTs.
RFC 7518 section 3.3 fixes RS384 to SHA-384 and RSASSA-PKCS1-v1_5.
"""
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode(value):
    return b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def check(condition, reason):
    if not condition:
        raise AssertionError(reason)


def reject_signature(key, signature, data, digest, signature_padding):
    try:
        key.verify(signature, data, signature_padding, digest)
    except InvalidSignature:
        return
    raise AssertionError("Invalid signature unexpectedly verified")


def verify_outbound(root):
    key = serialization.load_pem_private_key((root / "outbound-key.pem").read_bytes(), None)
    public = key.public_key()
    check(public.key_size >= 2048, "RSA key size")
    tokens = json.loads((root / "outbound.json").read_text())
    types = {"assertion": "JWT", "request_object": "oauth-authz-req+jwt", "dpop": "dpop+jwt"}
    check(set(tokens) == set(types), "All outbound signing surfaces must be supplied")
    wrong_key = rsa.generate_private_key(65537, 2048).public_key()
    for name, token in tokens.items():
        h, p, s = token.split(".")
        check(all("=" not in part and b64(unb64(part)) == part for part in (h, p, s)),
              name + ": canonical unpadded base64url")
        header, claims = json.loads(unb64(h)), json.loads(unb64(p))
        check(header["alg"] == "RS384" and header["typ"] == types[name], name + ": JOSE header")
        check(header["kid"] == "rs384-test-key", name + ": registered kid")
        check(bool(claims["jti"]) and abs(time.time() - claims["iat"]) < 60, name + ": freshness")
        if name == "dpop":
            jwk = header["jwk"]
            check(jwk["kty"] == "RSA" and not set(jwk) & {"d", "p", "q", "dp", "dq", "qi", "oth"},
                  "DPoP public key only")
            numbers = public.public_numbers()
            check(int.from_bytes(unb64(jwk["n"]), "big") == numbers.n and
                  int.from_bytes(unb64(jwk["e"]), "big") == numbers.e, "DPoP embedded key")
            check(claims["htm"] == "GET" and claims["htu"] == "https://api.example/records",
                  "DPoP request binding")
            # RFC 9449 section 4.2: ath remains SHA-256 regardless of the JWS alg.
            check(claims["ath"] == b64(hashlib.sha256(b"synthetic-access").digest()), "DPoP ath")
            check(claims["nonce"] == "synthetic-nonce", "DPoP nonce")
        else:
            check(claims["iss"] == "rs384-client", name + ": issuer")
            audience = "https://as.example/token" if name == "assertion" else "https://as.example"
            check(claims["aud"] == audience, name + ": audience")
            check(0 < claims["exp"] - claims["iat"] <= 300, name + ": lifetime")
            if name == "assertion":
                check(claims["sub"] == "rs384-client", "Client assertion subject")
            else:
                check(claims["client_id"] == "rs384-client" and claims["response_type"] == "code",
                      "Request Object client and response type")
        data, signature = (h + "." + p).encode("ascii"), unb64(s)
        check(len(signature) == public.key_size // 8, name + ": signature width")
        public.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())
        # PKCS#1 v1.5 signatures are deterministic: compare the exact bytes to
        # Python's result over R's original signing input, without reserializing.
        check(signature == key.sign(data, padding.PKCS1v15(), hashes.SHA384()),
              name + ": independent signature bytes")
        for digest in (hashes.SHA256(), hashes.SHA512()):
            reject_signature(public, signature, data, digest, padding.PKCS1v15())
        reject_signature(public, signature, data, hashes.SHA384(),
                         padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48))
        reject_signature(wrong_key, signature, data, hashes.SHA384(), padding.PKCS1v15())
        reject_signature(public, signature, (encode(dict(header, kid="changed")) + "." + p).encode(),
                         hashes.SHA384(), padding.PKCS1v15())
        reject_signature(public, signature, (h + "." + encode(dict(claims, jti="changed"))).encode(),
                         hashes.SHA384(), padding.PKCS1v15())
        changed = bytes([signature[0] ^ 1]) + signature[1:]
        reject_signature(public, changed, data, hashes.SHA384(), padding.PKCS1v15())
    return list(tokens)


def inbound_vectors(root, bits):
    # An independently generated issuer key and JWT, not an R round trip.
    key = rsa.generate_private_key(65537, bits)
    public = key.public_key()
    (root / "inbound-public.pem").write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    numbers = public.public_numbers()
    jwk = {"kty": "RSA", "kid": "python-rs384", "alg": "RS384", "use": "sig",
           "n": b64(numbers.n.to_bytes(bits // 8, "big")),
           "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))}
    now = int(time.time())
    header = {"alg": "RS384", "kid": jwk["kid"], "typ": "JWT"}
    claims = {"iss": "https://as.example", "aud": "rs384-client", "sub": "synthetic-user",
              "iat": now - 1, "exp": now + 300, "nonce": "synthetic-nonce",
              # OIDC Core 3.1.3.6: left half of the JWS algorithm's hash.
              "at_hash": b64(hashlib.sha384(b"synthetic-access").digest()[:24])}
    data = (encode(header) + "." + encode(claims)).encode("ascii")

    def sign(signing_key=key, digest=None, signature_padding=None, signing_input=data):
        signature = signing_key.sign(signing_input, signature_padding or padding.PKCS1v15(),
                                     digest or hashes.SHA384())
        return signing_input.decode("ascii") + "." + b64(signature)

    valid = sign()
    h, p, s = valid.split(".")
    signature = unb64(s)
    invalid = {
        "sha256": sign(digest=hashes.SHA256()),
        "sha512": sign(digest=hashes.SHA512()),
        "pss": sign(signature_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)),
        "wrong_key": sign(signing_key=rsa.generate_private_key(65537, bits)),
        "changed_header": encode(dict(header, cty="JWT")) + "." + p + "." + s,
        "changed_payload": h + "." + encode(dict(claims, sub="changed")) + "." + s,
        "changed_signature": h + "." + p + "." + b64(bytes([signature[0] ^ 1]) + signature[1:]),
        "truncated_signature": h + "." + p + "." + b64(signature[:-1]),
    }
    public.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())
    for token in invalid.values():
        vh, vp, vs = token.split(".")
        reject_signature(public, unb64(vs), (vh + "." + vp).encode(), hashes.SHA384(), padding.PKCS1v15())
    wrong_hash = dict(claims, at_hash=b64(hashlib.sha256(b"synthetic-access").digest()[:16]))
    return {"jwks": {"keys": [jwk]}, "valid": valid, "invalid": invalid,
            "wrong_at_hash": sign(signing_input=(h + "." + encode(wrong_hash)).encode())}


if __name__ == "__main__":
    root = Path(sys.argv[1])
    verified = verify_outbound(root)
    result = inbound_vectors(root, int(sys.argv[2]))
    result["verified"] = verified
    (root / "verified.json").write_text(json.dumps(result), encoding="utf-8")
    print("Verified RS384 outbound signatures and generated independent inbound vectors")
