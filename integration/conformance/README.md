# Independent protocol fixture

Run from the repository root:

```sh
python -m pip install -r integration/conformance/requirements.txt
Rscript integration/conformance/run-tests.R
```

The fixture uses Python cryptography, independent of shinyOAuth and R's jose,
to enforce RS256 Request Object signatures, issuer, audience, expiry, replay,
and mandatory signing. It completes JAR+DPoP (with and without PAR), JAR+mTLS
(with and without PAR), and JAR+signed-JARM authorization-code exchanges over
local TLS. DPoP proofs are verified against the signed Request Object's key
thumbprint; mTLS authenticates an actual TLS peer certificate. PKCE is checked
before issuing an access token. All keys and certificates are temporary.

These are focused protocol tests, not OpenID certification or evidence that a
third-party server enforces these policies. The fixture omits user login, ID
tokens, consent, discovery and resource endpoints. Keycloak's separate tests
record its actual capabilities and known claim-validation gaps. Its rejection
canaries must not be counted as successful combination interoperability.
