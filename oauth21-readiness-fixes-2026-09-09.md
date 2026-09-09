# OAuth 2.1 readiness audit: investigation and fixes

All seven findings in the supplied 9 September 2026 audit were confirmed
in the relevant configurations. The target remains [OAuth 2.1 draft
16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16), an
Internet-Draft. The changes preserve OAuth 2.0 configuration support and
keep assessment and optional extensions explicitly selected.

| Finding                         | Investigation and resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| F1: refresh credential lifetime | A refresh could rotate its credential before later validation or delivery failed. Errors now carry `refresh_credential_outcome`: `not_consumed`, `consumed`, `possibly_consumed`, or `rejected`. Only the first allows retrying the old credential. Async replay preserves the outcome. The module removes unsafe renewal credentials while retaining stale session identity when requested; candidates still require full validation. Direct callers must act on the outcome and store successful replacements. |
| F2: encryption key retrieval    | Encrypted Request Objects can fetch provider JWKS when no explicit recipient key is supplied. Pure dependency resolution now covers this operation, distinguishing explicit keys, configured JWKS and unresolved discovery. Runtime encryption selection shares the key-source decision. Assessment performs no key or cache operations.                                                                                                                                                                         |
| F3: DPoP token representation   | The old strict token-type policy additionally required visible binding from parseable JWTs. Token-type enforcement and `dpop_require_observed_cnf` are now independent. Missing binding can await required introspection regardless of representation. `shinyOAuth.access_token_cnf = "opaque"` disables access-token decoding for DPoP and mTLS; the compatibility default remains `"jwt"`. Observed contradictory binding and Bearer fallback remain rejected where the configured policies require it.        |
| F4: multiple callback clients   | Single-client GET wrappers intercept callbacks before nested wrappers can route them. Both UI wrappers now support `clients = list(module_id = client, ...)`. Distinct routes and shared routes with issuer identification select a configured client before the existing full validation and bridge redirect. Module browser/transaction binding remains enforced.                                                                                                                                              |
| F5: UserInfo assessment         | Runtime compares UserInfo with every available validated ID-token baseline, independently of the matching flag. The assessment now recognizes a guaranteed validated baseline for managed flows, excludes active signature bypasses, and leaves separately selected UserInfo calls unresolved when their caller-supplied baseline cannot be established.                                                                                                                                                         |
| F6: HMAC JARM                   | HMAC signature verification uses the client secret and returns before JWKS retrieval. The dependency resolver now uses the same selected JARM algorithm as runtime; HMAC-only JARM has no key-fetch dependency unless another operation requires one.                                                                                                                                                                                                                                                            |
| F7: advice and provenance       | Ruleset `1.1.0` adds `requirement_source`, non-blocking advice for asymmetric client authentication, issuer identification and loopback IPs, separate client/scope/public-client refresh obligations, separate resource-server and application responsibilities, early-invalidation advice, and explicit package-policy labeling for callback capacity and back-channel redirects.                                                                                                                               |

## Compatibility and scope

Basic/body authentication, existing callback choices, token-request
`redirect_uri`, and the process TLS default remain supported.
[`check_oauth21()`](https://lukakoning.github.io/shinyOAuth/reference/check_oauth21.md)
is read-only; it does not enforce its recommendations on OAuth 2.0
clients. Rotation recovery is corrected for both protocol versions,
consistent with [RFC 9700 section
4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2). The
separate DPoP policies follow the distinction between token type and
binding in [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html).

The registry requires explicit multi-server client policies. Shared
routes need distinct configured issuers; encrypted JARM on a shared
route needs an outer `iss` that is checked against the decrypted
response, or distinct routes. Multiple R processes still require
coordinated refresh ownership and shared atomic callback storage. No
replacement refresh credential is recovered from a failed candidate;
unsafe outcomes require reauthorization.

## Validation

Targeted tests cover refresh failure phases and sync/async module
behavior, side-effect-free key dependency assessment, DPoP and mTLS
opacity, two-provider HTTP bridge/module completion for
query/JARM/form-post with distinct/shared routes, effective UserInfo
guarantees, HMAC JARM, and advisory applicability. The callback cleanup
and referrer browser tests also pass with browser tests enabled (114
assertions, zero skips).

On Windows with R 4.5.1 and curl’s OpenSSL backend:

- Full suite (`tests/run-local.R`, `NOT_CRAN=true`, browser tests
  disabled): **9,752 passing assertions, zero failures, three warnings,
  26 skips**. Warnings report installed Shiny/future packages built with
  newer R versions. Skips comprise 25 browser tests and one Windows
  atomic-file-rename test.
- Targeted browser run (`get-callback-bridge|oauth-ui`, browser tests
  enabled): **114 passing assertions, zero failures, zero skips**, with
  the Shiny build version warning. This overlaps the full suite; counts
  are not additive.
- `R CMD check --no-manual --no-tests`: **zero errors, zero warnings,
  one note** from curl’s OpenSSL startup message during dependency
  inspection. Vignettes and examples passed. Tests were run separately
  above. The check used valid child-process locale settings after
  inherited `C.UTF-8` settings caused the initial Windows check attempt
  to fail during metadata inspection.
- `jarl check R`, formatting checks for changed R files, and
  `git diff --check` passed.

Logs are retained locally under `.git/audit-*-tests.log`,
`.git/audit-rcmdcheck.log`, and
`.git/audit-rcmdcheck/shinyOAuth.Rcheck/`. Live provider conformance,
the remaining browser scenarios and deployment TLS/storage guarantees
were not tested.
