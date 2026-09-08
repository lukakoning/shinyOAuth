# OAuth 2.0 / OAuth 2.1 implementation decisions

Reviewed 2026-09-08 against clean HEAD `a7ffd606` (version
`0.5.0.9000`). The separately supplied audit snapshots remain historical
evidence. Another agent supplied two smaller fixture fixes during
implementation; those commits remain separate. Each implementation
commit stages only its own files or hunks.

## Baseline and commit sequence

`tests/run-local.R` with filter
`client-jwt|endpoint-auth|callback-iss|client-bearer|parameter-overrides|prepare-call-url|resource-indicators|callback-query-size`
passed 372 assertions, with no failures/skips and one warning (Shiny
built under R 4.5.2, running R 4.5.1 on Windows with curl’s OpenSSL
backend). R startup also reported four unavailable C.UTF-8 locale
settings.

1.  WP0 (`c02ef373`): record independent review and current baseline.
2.  WP1 (`8858fbf6`): compose authorization endpoint queries without
    ambiguous managed fields.
3.  WP2 (`350ce6dc`): reject competing access-token transports in
    resource request builders.
4.  WP3 (`dd652181`): separate present-issuer comparison from required
    presence.
5.  WP4 (`5637e94c`): add assertion typing while retaining audience/type
    defaults.
6.  WP5a (`d2818475`): add optional TLS minimum policy across HTTP and
    async paths.
7.  WP5b (`6fad3144`): centralize callback capacity and increase the
    default code budget.
8.  WP6 (`230f7d58`): add an optional, versioned configuration
    assessment.
9.  Validation follow-up (`c6b405d7`): assess effective legacy
    development bypass flags, including numeric values accepted by
    existing runtime conditions.
10. Validation follow-up (`e706969d`): update older callback overflow
    fixtures for the expanded limits and guard the early-rejection test
    against unintended network access.
11. WP7 (this final documentation commit): document both configurations,
    extend independent interoperability fixtures, remove a malformed-key
    test skip, and record release validation.

The other agent’s commits are `fafe3732` (mTLS fixture readiness) and
`332ee892` (browser fixture tab bindings). They are preserved without
rewriting history.

## Findings and decisions

| Finding                               | Current source and independent decision                                                                                                                                                                                                                                                                                                                                                                                                 | Compatibility and validation                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| F1 confirmed                          | `utils__jwt_signing.R`: endpoint audience except existing PAR issuer/alias handling; explicit audience override works. Add `client_assertion_typ`, default `JWT`; include endpoint overrides, printing and state fingerprint.                                                                                                                                                                                                           | Preserve legacy JWT output. Test decoded assertions for token, refresh, PAR, introspection/revocation and retries. [RFC7523bis-11 §4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4) makes issuer audience mandatory and explicit typing a recommendation.                                                                                                          |
| F2 confirmed                          | Provider supports S256, plain and confidential no-PKCE. Existing public-client validation requires PKCE. Assess selected policy; retain these choices.                                                                                                                                                                                                                                                                                  | Existing PKCE tests plus checker coverage. [RFC 7636 §4](https://www.rfc-editor.org/rfc/rfc7636.html#section-4) supplies the older contract.                                                                                                                                                                                                                                                         |
| F3 revised                            | `enforce_callback_issuer()` gates presence and comparison. Documentation and `test-callback-iss-validation.R` explicitly promise complete opt-out, including mismatch acceptance. Add `compare_callback_issuer`, with automatic comparison for issuer-configured clients unless explicitly opted out through the existing flag. Explicit comparison can be enabled with absence permitted. Required presence always implies comparison. | Preserve explicit old opt-out and JARM; test helper/raw construction, success/error and callback entry paths. [RFC 9207 §2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) permits nonparticipation, controls absence by local policy, and recognizes validated JARM without redundant outer issuer.                                                                                     |
| F4 confirmed, interpretation narrowed | URL policy permits development HTTP. `add_req_defaults()` has no minimum TLS option. Add `shinyOAuth.tls_min_version = NULL` (runtime default), or `1.2`/`1.3`. Use a pure resolver and preserve stronger supplied settings and trust roots.                                                                                                                                                                                            | Inspect actual selected endpoints, not unused allowances. Test curl minimum/maximum composition and verification options. [RFC 9325 §3.1.1](https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1), [curl SSLVERSION](https://curl.se/libcurl/c/CURLOPT_SSLVERSION.html), [VERIFYPEER](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html). Absent options do not prove obsolete negotiation. |
| F5 confirmed                          | `finalize_client_bearer_request()` currently preserves query/form credentials alongside managed Authorization. Inspect after shaping, using strict form-name decoding for known representations.                                                                                                                                                                                                                                        | Reject ambiguous transport with redacted errors; preserve JSON business fields and ordinary header behavior. [RFC 6750 §2](https://www.rfc-editor.org/rfc/rfc6750.html#section-2) already prohibits multiple access-token transmission methods. Opaque bodies and later arbitrary request mutations remain outside inspection.                                                                       |
| F6 confirmed                          | All direct/PAR/JAR outer URLs use `url_append_query_params()` without managed-name collision handling. Add a context-specific pure helper; retain unrelated query bytes/order and repeated resource indicators.                                                                                                                                                                                                                         | Matching singleton values appear once; ambiguous/conflicting values fail before publication where resolvable. Core names are case sensitive; signed objects are never rewritten. [RFC 6749 §§3.1, 4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1), [RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2). Token endpoint semantics remain separate.                   |
| F7 confirmed                          | `oauth_callback_limits()` defaults code to 4096, duplicated in login and form bridge. Centralize all callback consumers; default code budget 8192 while preserving explicit field/aggregate limits.                                                                                                                                                                                                                                     | Exercise encoded callback envelope, bridge/module/JARM and lower overrides. Proxy request-line limits cannot be proven statically.                                                                                                                                                                                                                                                                   |
| F8 confirmed                          | No configuration checker exists. Add stable structured findings without protocol calls or state/cache/option mutations; provider assessment remains partial.                                                                                                                                                                                                                                                                            | Mandatory configuration failures outrank unknowns; recommendations and external checks do not manufacture failures or certification. Test redaction, side effects, raw/helper parity, overrides and positive configurations.                                                                                                                                                                         |

## Assessment target and boundaries

Pin [OAuth 2.1 draft
16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16),
published 2026-09-03; it remains an Internet-Draft. Sections 1.8 and 10
support dual-version operation. Section 4.1.1 requires S256 rather than
plain; §7.5.1.1’s no-PKCE exception requires a confidential client and
server assurance about proper OIDC nonce use for the deployment and
request. Unknown assurance remains unknown. Sections 1.5, 1.7.1 and 5
respectively govern transport, recommended capacity and token transport.
Keep the token request’s existing `redirect_uri` for compatibility
(§10.2).

Assess code/refresh, enabled PAR and applicable identity retrieval;
report optional introspection/revocation separately unless requested in
assessment context. Future arbitrary resource URLs, server refresh
replay policy, browser TLS, registered redirect matching and deployment
secret custody remain external evidence. Reuse existing topology
(`authorization_server_mode`), nonce, identity, state and extension
policies. Manual OAuth-only providers need no invented OIDC metadata
requirement. [OIDC
Core](https://openid.net/specs/openid-connect-core-1_0.html) and [RFC
9700](https://www.rfc-editor.org/rfc/rfc9700.html) remain relevant to
identity and deployment responsibilities.

The checker must avoid `endpoint_auth_client()` if its S7 validation can
probe signing capability; extract a pure effective-settings resolver
where necessary. Async capture already covers `shinyOAuth.*`; verify
clearing of absent values in reused workers and bind effective transport
policy into pending transactions.

## Final validation

Completed on 2026-09-08 against implementation HEAD `e706969d` plus the
documentation and integration fixture changes included in this final
commit. The checked-in runners installed the checkout into isolated test
libraries; the Linux workers also used a freshly installed checkout. No
remote deployment or external certification was performed.

| Check                                                      | Result                                       | Scope and qualifications                                                                                                                                                                                                                                              |
|------------------------------------------------------------|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tests/run-local.R`, full Windows suite                    | 8,843 passed; 0 failed; 3 warnings; 26 skips | Warnings report Shiny/future built under newer R patch releases. The 25 opt-in browser skips and one Windows concurrent-state skip were covered by the dedicated runs below.                                                                                          |
| `tests/run-browser-tests.R`, complete browser suite        | 218 passed; 0 failed; 1 warning; 0 skips     | Actual Chrome on Windows; warning is the Shiny build-version warning.                                                                                                                                                                                                 |
| `tests/run-local.R`, Linux async/checker/TLS filter        | 413 passed; 0 failed; 0 warnings; 0 skips    | Filter: `audit-async-options\|async-authorization\|module-server-async\|async-serialization\|check-oauth21\|tls-policy`. Includes actual mirai and future workers.                                                                                                    |
| `tests/run-local.R`, Linux concurrent-state filter         | 19 passed; 0 failed; 0 warnings; 0 skips     | Filter: `state-store-concurrent-replay`; covers the case skipped on Windows because of file-rename semantics.                                                                                                                                                         |
| `integration/conformance/run-tests.R`                      | 76 passed; 0 failed; 1 warning; 0 skips      | Independent local TLS server verifies both legacy and newer JWT profiles across code, refresh, PAR, introspection and revocation, alongside the existing extension cases. Warning is the Shiny build-version warning.                                                 |
| Selected Keycloak integration tests                        | 346 passed; 0 failed; 1 warning; 0 skips     | Local Keycloak 26.6.1: Basic/body/JWT authentication, authorization code, PAR, refresh protection, revocation and browser form-post callbacks. Warning is the Shiny build-version warning. This is selected interoperability coverage, not the entire Keycloak suite. |
| `R CMD build --no-manual`                                  | Passed                                       | Built source package and vignettes.                                                                                                                                                                                                                                   |
| `R CMD check --no-manual --no-tests`                       | 0 errors; 0 warnings; 1 NOTE                 | NOTE: `Initiating curl with CURL_SSL_BACKEND: openssl` during dependency inspection. Examples, documentation, namespace, static checks and vignette rebuilding passed. Tests ran separately as recorded above.                                                        |
| `jarl check .`, `air format . --check`, `git diff --check` | Passed                                       | Full repository lint and formatting, plus patch whitespace validation.                                                                                                                                                                                                |

The Keycloak runner selected test files with
`(keycloak_(auth_styles|code_jwt_auth|par|revocation|refresh_protection)|module_shiny_browser_form_post)$`.
Both the independent protocol server and Keycloak were disposable local
fixtures. Their temporary containers and network were removed after
validation. Negative rejection canaries are not presented as successful
interoperability.

Windows runtime: R 4.5.1 (ucrt), Windows 11 x64 build 26200; S7 0.2.1,
shiny 1.13.0, httr2 1.2.2, curl 7.0.0 with libcurl 8.14.1 and active
OpenSSL 3.5.0, jose 1.2.1, openssl 2.4.0, testthat 3.3.2, mirai 2.7.1
and future 1.70.0. Browser coverage used Chrome 152.0.7977.76, chromote
0.5.1 and shinytest2 0.5.1. The independent server used Python 3.12.10
and cryptography 46.0.5. Package-check child processes explicitly used
`LC_ALL=English_United States.utf8` and `LANG=en_US.UTF-8` to replace
unavailable inherited C.UTF-8 locale settings.

Linux runtime: ephemeral `rocker/r-ver:4.5.1` container, Ubuntu 24.04.2
x86_64, dependencies from the Posit Package Manager 2026-09-08 snapshot;
S7 0.2.2, shiny 1.14.0, httr2 1.3.0, curl 8.0.0 with libcurl
8.5.0/OpenSSL 3.0.13, jose 2.0.0, openssl 2.4.2, testthat 3.3.2, mirai
2.7.2 and future 1.75.0. The Linux runs cover the named filters, not a
second full package or browser suite. Local mTLS tests also exercised
explicit TLS 1.2 and 1.3 minima.

Implementation review found that jose 1.2.1’s HMAC encoder would prepend
a second `typ` header. Assertion construction therefore reuses the
package’s existing explicit-header HMAC signer; tests decode and verify
both HMAC and asymmetric assertions, including fresh retry identifiers.
Checker tests also cover effective identity validation, endpoint
overrides, numeric legacy bypass flags, redacted errors, and absence of
RNG, option, object, cache or protocol side effects. The JWKS cache test
now uses valid keys and checks actual pin validation instead of skipping
after an invalid placeholder key fails.

Local logs are retained under ignored `codex/oauth21-*.log` paths,
including full, browser, conformance, Linux, Keycloak, build and check
outputs. The built source artifact is
`codex/oauth21-build/shinyOAuth_0.5.0.9000.tar.gz`, SHA-256
`0E6D6AEA84D0040A64A8B3E01D14E437435159DF4A230F7BCA453D24CF74758E`. The
optional checker’s positive verdict concerns its pinned mandatory
configuration rules only; authorization-server behavior, external
deployment obligations and future draft changes remain outside that
verdict.
