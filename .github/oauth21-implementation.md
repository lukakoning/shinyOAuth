# OAuth 2.0 / OAuth 2.1 implementation decisions

Reviewed 2026-09-08 against clean HEAD `a7ffd606` (version `0.5.0.9000`).
The separately supplied audit snapshots remain historical evidence. Another
agent is working in this checkout; each implementation commit stages only its
own files or hunks.

## Baseline and commit sequence

`tests/run-local.R` with filter
`client-jwt|endpoint-auth|callback-iss|client-bearer|parameter-overrides|prepare-call-url|resource-indicators|callback-query-size`
passed 372 assertions, with no failures/skips and one warning (Shiny built under
R 4.5.2, running R 4.5.1 on Windows with curl's OpenSSL backend). R startup also
reported four unavailable C.UTF-8 locale settings.

1. WP0: record independent review and current baseline (this commit).
2. WP1: compose authorization endpoint queries without ambiguous managed fields.
3. WP2: reject competing access-token transports in resource request builders.
4. WP3: separate present-issuer comparison from required presence.
5. WP4: add assertion typing while retaining audience/type defaults.
6. WP5a: add optional TLS minimum policy across HTTP and async paths.
7. WP5b: centralize callback capacity and increase the default code budget.
8. WP6: add an optional, versioned configuration assessment.
9. WP7: document both configurations and run release validation.

## Findings and decisions

| Finding | Current source and independent decision | Compatibility and validation |
| --- | --- | --- |
| F1 confirmed | `utils__jwt_signing.R`: endpoint audience except existing PAR issuer/alias handling; explicit audience override works. Add `client_assertion_typ`, default `JWT`; include endpoint overrides, printing and state fingerprint. | Preserve legacy JWT output. Test decoded assertions for token, refresh, PAR, introspection/revocation and retries. [RFC7523bis-11 §4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4) makes issuer audience mandatory and explicit typing a recommendation. |
| F2 confirmed | Provider supports S256, plain and confidential no-PKCE. Existing public-client validation requires PKCE. Assess selected policy; retain these choices. | Existing PKCE tests plus checker coverage. [RFC 7636 §4](https://www.rfc-editor.org/rfc/rfc7636.html#section-4) supplies the older contract. |
| F3 revised | `enforce_callback_issuer()` gates presence and comparison. Documentation and `test-callback-iss-validation.R` explicitly promise complete opt-out, including mismatch acceptance. Add `compare_callback_issuer`, with automatic comparison for issuer-configured clients unless explicitly opted out through the existing flag. Explicit comparison can be enabled with absence permitted. Required presence always implies comparison. | Preserve explicit old opt-out and JARM; test helper/raw construction, success/error and callback entry paths. [RFC 9207 §2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) permits nonparticipation, controls absence by local policy, and recognizes validated JARM without redundant outer issuer. |
| F4 confirmed, interpretation narrowed | URL policy permits development HTTP. `add_req_defaults()` has no minimum TLS option. Add `shinyOAuth.tls_min_version = NULL` (runtime default), or `1.2`/`1.3`. Use a pure resolver and preserve stronger supplied settings and trust roots. | Inspect actual selected endpoints, not unused allowances. Test curl minimum/maximum composition and verification options. [RFC 9325 §3.1.1](https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1), [curl SSLVERSION](https://curl.se/libcurl/c/CURLOPT_SSLVERSION.html), [VERIFYPEER](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html). Absent options do not prove obsolete negotiation. |
| F5 confirmed | `finalize_client_bearer_request()` currently preserves query/form credentials alongside managed Authorization. Inspect after shaping, using strict form-name decoding for known representations. | Reject ambiguous transport with redacted errors; preserve JSON business fields and ordinary header behavior. [RFC 6750 §2](https://www.rfc-editor.org/rfc/rfc6750.html#section-2) already prohibits multiple access-token transmission methods. Opaque bodies and later arbitrary request mutations remain outside inspection. |
| F6 confirmed | All direct/PAR/JAR outer URLs use `url_append_query_params()` without managed-name collision handling. Add a context-specific pure helper; retain unrelated query bytes/order and repeated resource indicators. | Matching singleton values appear once; ambiguous/conflicting values fail before publication where resolvable. Core names are case sensitive; signed objects are never rewritten. [RFC 6749 §§3.1, 4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1), [RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2). Token endpoint semantics remain separate. |
| F7 confirmed | `oauth_callback_limits()` defaults code to 4096, duplicated in login and form bridge. Centralize all callback consumers; default code budget 8192 while preserving explicit field/aggregate limits. | Exercise encoded callback envelope, bridge/module/JARM and lower overrides. Proxy request-line limits cannot be proven statically. |
| F8 confirmed | No configuration checker exists. Add stable structured findings without protocol calls or state/cache/option mutations; provider assessment remains partial. | Mandatory configuration failures outrank unknowns; recommendations and external checks do not manufacture failures or certification. Test redaction, side effects, raw/helper parity, overrides and positive configurations. |

## Assessment target and boundaries

Pin [OAuth 2.1 draft 16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16),
published 2026-09-03; it remains an Internet-Draft. Sections 1.8 and 10 support
dual-version operation. Section 4.1.1 requires S256 rather than plain; §7.5.1.1's
no-PKCE exception requires a confidential client and server assurance about
proper OIDC nonce use for the deployment and request. Unknown assurance remains
unknown. Sections 1.5, 1.7.1 and 5 respectively govern transport, recommended
capacity and token transport. Keep the token request's existing `redirect_uri`
for compatibility (§10.2).

Assess code/refresh, enabled PAR and applicable identity retrieval; report
optional introspection/revocation separately unless requested in assessment
context. Future arbitrary resource URLs, server refresh replay policy, browser
TLS, registered redirect matching and deployment secret custody remain external
evidence. Reuse existing topology (`authorization_server_mode`), nonce, identity,
state and extension policies. Manual OAuth-only providers need no invented OIDC
metadata requirement. [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)
and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) remain relevant to
identity and deployment responsibilities.

The checker must avoid `endpoint_auth_client()` if its S7 validation can probe
signing capability; extract a pure effective-settings resolver where necessary.
Async capture already covers `shinyOAuth.*`; verify clearing of absent values in
reused workers and bind effective transport policy into pending transactions.

## Final validation

To be filled with actual completed checks, revisions and unavailable coverage.
