# Native-provider warm JWKS rotation

```sh
Rscript integration/oidc-provider/run-jwks-rotation.R
```

This dedicated selection uses the pinned, unmodified `oidc-provider` package
with the existing TLS fixture. It requires Docker, the package's development
dependencies and XML parsing support. Setup failures fail the command; they
do not skip the test. The manual provider workflow offers `jwks-rotation` with
sync transport only.

The runner retains one public client, provider and JWKS cache across three
real authorization-code/S256 logins. The first login populates the cache; the
second must reuse the same usable entry without another JWKS request. It then
restarts only its owned provider container at the same issuer and port. The
fixture's normal startup creates a new RSA signing key. The client retains its
old cache entry, and the next real login must refresh once for the unknown key
while that entry is still usable, then validate the new signature.

Native discovery enables PAR, which keeps state inside the pushed request.
The driver binds the returned reference to the exact existing pending-cache
key instead of requiring state on the outer authorization URL. The module
still validates and consumes that record. The proof records the selected PAR
transport and hidden front-channel state without publishing reference values.

The proof binds the provider run/process identities and key IDs, unchanged
cache identity and entry digest, exact native endpoint request counts, login
state consumption, fetched/observed times and the unknown-key throttle record.
Provider-side events corroborate public-client authentication, S256/code
binding and the two real JWKS responses. Rogue signatures with the old and new
key IDs must fail without another endpoint request after the refresh.

The native JWKS response has neither Cache-Control nor Expires. This selection
uses the package's unchanged default one-hour cache backend and records absent
origin freshness explicitly. It does not add a positive origin max-age,
rewrite headers, insert a cache record, replace the backend or override its
lifetime. Pass-through observers wrap the actual package fetch/request
functions and delegate their behavior unchanged; the fixture's optional JWKS
observer records native responses without supplying them.

The authorization interactions use an HTTP cookie jar and `testServer()`.
The package's browser-token check is explicitly bypassed for this headless
protocol fixture. There is no Chrome, cross-site cookie, mirai/shared-cache or
public-certificate-chain claim. The existing raw Keycloak no-cache and OIDF
no-store selections retain their header-specific limitations; this separate
cache-use result cannot change what those providers returned.

The dedicated schema-1 report includes private-installation/source identities,
strict rotation evidence and cleanup verification. It is not an OIDF schema-4
client report and cannot fill a row in the
[OIDF release matrix](../openid/release-matrix.md). Reports belong under ignored
`.artifacts/jwks-rotation-*/evidence.json`; raw tokens, cookies, callback URLs,
keys and diagnostics stay private. The provider workflow retains sanitized
evidence for seven days, without establishing durable release retention or
certification.

Clean local acceptance and fresh hosted Linux
[run 44642151147](https://github.com/lukakoning/shinyOAuth/actions/runs/44642151147)
passed at `4f0708fb1d85f23ce0d55ff6fa634e2609d58364`, including 246
regressions, the complete three-login proof and cleanup. Independent review
checked local physical source/installation files and the hosted artifact's
bytes and recorded identities separately. The
[release review](../openid/release-review.md#cross-site-form-post-and-warm-cache-acceptance-2026-11-20)
records hashes, timings and the earlier failed attempts without passing credit.
