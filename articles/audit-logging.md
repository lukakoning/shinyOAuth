# Audit logging and hooks

## Overview

shinyOAuth emits structured audit events for authorization requests,
callbacks, token operations, and changes to the authenticated session.
Configure `shinyOAuth.audit_hook` with an R function to receive these
events as named lists and send them to your application’s logging
system.

## Receiving audit events

Put this near the top of `app.R`, before creating the provider and
client:

``` r
options(shinyOAuth.audit_hook = function(event) {
  cat(sprintf("[shinyOAuth] %s | %s\n", event$type, event$trace_id))
  str(event)
})
```

Run your app and try signing in. You will see event names such as
`audit_redirect_issued` and `audit_login_success`. The `trace_id`
connects related events from the same operation or login attempt.
Several events can describe one failure; they are not necessarily
separate failed logins. For an interactive login, the same `trace_id`
follows redirect preparation, callback validation, token exchange, and
the login result.

To stop receiving events, set `options(shinyOAuth.audit_hook = NULL)`.
Keep hooks fast and avoid throwing errors. A hook that waits for a slow
log service can delay the login operation that called it.

## Authentication outcomes

Use `audit_authenticated_changed` to track the module’s final
authentication state and `audit_session_cleared` to record why a session
ended. Events such as `audit_token_exchange` and `audit_userinfo` report
individual operations; subsequent validation can still fail. Callback
failures include `phase` and `error_class` fields to help identify the
failed check. The event catalog below documents the available names and
fields.

## Event structure

Audit events have `type`, `trace_id`, and a `timestamp` from
[`Sys.time()`](https://rdrr.io/r/base/Sys.time.html), plus fields
specific to the operation. The hook also receives error events such as
`error`, `http_error`, and `transport_error`; their fields are listed at
the end of the catalog. Do not assume every field exists on every event.

When a Shiny session is available, `shiny_session` contains:

- `session_token_digest`: a protected identifier for correlating the
  session.
- `is_async` and `process_id`: whether work ran in a background worker
  and which R process emitted the event. Async context also includes
  `main_process_id`.
- `http`: a summary with request method, path, host, and scheme by
  default.

The session context is a JSON-friendly list suitable for
[`jsonlite::toJSON()`](https://jeroen.r-universe.dev/jsonlite/reference/fromJSON.html);
the raw Shiny `session$request` object is not included. If
`shinyOAuth.audit_include_raw_session_token = TRUE`, the raw session
token is available as `shiny_session$token` in native hook events.

Fields ending in `_digest` allow matching without recording the original
token or identifier. The package’s `trace_id` is separate from
OpenTelemetry trace/span IDs; OTel exports it as `shinyoauth.trace_id`.

## HTTP context and redaction

By default, the HTTP summary omits query strings, headers, and client
addresses. The raw Shiny session token is also omitted. To omit HTTP
context entirely:

``` r
options(shinyOAuth.audit_include_http = FALSE)
```

With this setting, `shiny_session$http` is `NULL`.

For local debugging, `shinyOAuth.audit_redact_http = FALSE` includes raw
request details, and `shinyOAuth.audit_include_raw_session_token = TRUE`
includes the raw session token. These can expose credentials and
personal data; keep the defaults for production logs. Redaction does not
replace your logging system’s access and retention controls.

### Audit events from asynchronous workers

With `oauth_module_server(async = TRUE)`, the hook is passed to
background work too. Use a hook that can run in a separate R process.
Existing database connections or open file handles cannot be safely
carried into a worker; create connections there or use a logging service
designed for multiple writers. Appending to a global R list inside a
worker only changes that worker’s copy.

Worker failures may include `mirai_error_type`: `mirai_error`,
`mirai_timeout`, `mirai_connection_reset`, or `mirai_interrupt`. This
helps distinguish an R error from a timeout, crashed worker, or
cancellation. It can be `NA` for a failure that is not specific to
mirai.

### Digest keys across R processes

Digests use HMAC-SHA256 with a random process key by default. The module
shares that key with its async workers. To match digests across separate
app processes or restarts, configure the same secret key everywhere:

``` r
audit_digest_key <- Sys.getenv("AUDIT_DIGEST_KEY", unset = NA_character_)
if (is.na(audit_digest_key) || !nzchar(audit_digest_key)) {
  stop("AUDIT_DIGEST_KEY must be configured before the app starts")
}
options(shinyOAuth.audit_digest_key = audit_digest_key)
```

Use a string or raw vector containing at least 32 bytes, generated from
at least 32 cryptographically random bytes and stored as a deployment
secret. Invalid or short configured keys cause an error. `FALSE` selects
unkeyed SHA-256 for compatibility, but makes low-entropy identifiers
easier to guess.

For exporting events and timings through OpenTelemetry, see
[OpenTelemetry](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md).

## Event catalog

This is a lookup reference. Start with the event name in your logs;
fields are included when relevant and available.

### Authorization redirect issuance

#### Event: `audit_redirect_issued`

- When: after
  [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
  builds the authorization URL

- Context:

  - `provider`, `issuer`
  - `client_id_digest`
  - `state_digest`
  - `browser_token_digest`
  - `pkce_method` (e.g., `S256`, `plain`, or `NA`)
  - `par_used` (logical)
  - `request_object_used` (logical)
  - `nonce_present` (logical)
  - `scopes_count`
  - `redirect_uri`

### Callback query rejected

#### Event: `audit_callback_query_rejected`

- When: the callback query parameters fail validation (e.g., too large)
- Context: `provider`, `issuer`, `client_id_digest`, `error_class`
- For form_post bridge query rejections, context also includes `phase`,
  `reason`, and `handle_digest`.

### Callback issuer validation

#### Event: `audit_callback_iss_missing`

- When: `enforce_callback_issuer = TRUE` and the callback omits the RFC
  9207 `iss` parameter
- Context: `provider`, `expected_issuer`, `client_id_digest`,
  `error_class`

#### Event: `audit_callback_iss_mismatch`

- When: the callback includes an `iss` query parameter (per RFC 9207)
  that does not match the provider’s expected issuer
- Context: `provider`, `expected_issuer`, `callback_issuer`,
  `client_id_digest`, `error_class`

#### Event: `audit_callback_iss_validation_failed`

- When: callback issuer validation fails before token exchange for a
  reason other than the dedicated missing/mismatch cases above
- Context: `provider`, `expected_issuer`, `callback_issuer` (when
  present), `client_id_digest`, `error_class`

### Callback received

#### Event: `audit_callback_received`

- When: a callback has passed encrypted-state validation; later callback
  checks may still fail
- Context: `provider`, `issuer`, `client_id_digest`, `code_digest`,
  `state_digest`, `browser_token_digest`
- Notes: callbacks that fail before payload validation do not emit this
  event

### Callback validation

Callback validation covers both the sealed-state checks and the later
checks of the values tied to that state, such as the browser token, PKCE
code verifier, and nonce. Each stage emits either a success event or a
failure event.

#### Event: `audit_callback_validation_success`

- When: the callback has passed state, browser-binding, and single-use
  checks
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`

#### Event: `audit_callback_validation_failed`

- When: a validation step fails prior to token exchange
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `phase`, `error_class` (+ `browser_token_digest` when phase is
  `browser_token_validation`)
- Phases include: `payload_validation`, `browser_token_validation`,
  `pkce_verifier_validation`, `nonce_validation`,
  `form_post_request_validation`, `form_post_callback_lookup`,
  `form_post_callback_validation`
- `handle_digest` is included when a form_post callback handle is
  missing, expired, or already consumed.
- Note: Failures related to state store access (lookup/removal) are
  reported as their own events (see below) rather than using the
  `callback_validation_failed` event.

### State store access

These events identify failures when reading or removing a pending login
from the state store.

#### Event: `audit_state_store_lookup_failed`

- When: retrieving the single-use state entry from the configured
  `state_store` fails (missing, malformed, or underlying cache error)
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `error_class`, `phase` (`state_store_lookup` or
  `state_store_atomic_take`)
- Notes: The flow aborts with an invalid state error. The
  `state_store_atomic_take` phase applies when using a store with an
  atomic `$take()` method.

#### Event: `audit_state_store_removal_failed`

- When: removal of the single-use state entry (enforcing one-time use)
  fails
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `error_class`, `phase` (`state_store_removal`)
- Notes: A failure to remove also aborts the flow with an invalid state
  error; the event is emitted best-effort and will never itself throw.

Digest differences: For `audit_callback_validation_failed` during
payload decryption (`phase = "payload_validation"`) the `state_digest`
is computed from the encrypted payload (plaintext not yet available).
For state store events the digest reflects the plaintext state string.

### Token exchange

#### Event: `audit_token_exchange`

- When: authorization code successfully exchanged for tokens
- Context: `provider`, `issuer`, `client_id_digest`, `code_digest`,
  `used_pkce`, `received_id_token`, `received_refresh_token`,
  `expires_in_synthesized`
- `expires_in_synthesized` (logical): `TRUE` when the token response did
  not include a usable `expires_in` value and the package used the
  configured fallback token lifetime

#### Event: `audit_token_exchange_error`

- When: token exchange fails
- Context: `provider`, `issuer`, `client_id_digest`, `code_digest`,
  `error_class`

Detailed sender-constraint diagnostics such as DPoP token-type
inference, DPoP nonce retries, and mTLS endpoint-alias selection are
emitted on the OpenTelemetry spans documented in the [OpenTelemetry
vignette](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md)
rather than on the high-level audit events.

### Token introspection

#### Event: `audit_token_introspection`

- When:
  [`introspect_token()`](https://lukakoning.github.io/shinyOAuth/reference/introspect_token.md)
  reaches a final result (for example during login or refresh when
  `introspect = TRUE`)
- Context:
  - `provider`, `issuer`, `client_id_digest`
  - `which` (“access” or “refresh”)
  - `supported` (logical), `active` (logical\|NA), `status`
  - `sub_digest`, `introspected_client_id_digest`, `scope_digest` (when
    available)
- `status` values include `"ok"`, `"introspection_unsupported"`,
  `"missing_token"`, `"body_too_large"`, `"invalid_json"`,
  `"missing_active"`, `"invalid_active"`, and `"http_<code>"`

### Login result

#### Event: `audit_login_success`

- When: callback handling has completed the configured token, UserInfo,
  and introspection checks and is ready to return the `OAuthToken`
- Context: `provider`, `issuer`, `client_id_digest`, `sub_digest`,
  `sub_source`, `refresh_token_present`, `expires_at`

`sub_source` indicates where `sub_digest` was derived from:

- `userinfo`: subject came from the userinfo response
- `id_token`: subject came from an ID token that was validated
  (signature + claims)
- `id_token_unverified`: subject came from an ID token payload parse
  when ID token validation was not performed

#### Event: `audit_login_failed`

- When: login failure during callback handling in the Shiny module
- Context: `provider`, `issuer`, `client_id_digest`, `phase`,
  `error_class`, `mirai_error_type`
- `phase` currently includes:
  - `sync_token_exchange`
  - `async_token_exchange`
  - `async_payload_validation`
  - `async_state_store_lookup`
- `mirai_error_type` is only present on async failure paths

### Logout and session clears

#### Event: `audit_logout`

- When: `auth$logout()` is called on the module
- Context: `provider`, `issuer`, `client_id_digest`, `reason` (default
  `manual_logout`)

#### Event: `audit_session_cleared`

- When: the module clears the token reactively
- Context: `provider`, `issuer`, `client_id_digest`, `reason`,
  `error_class`, `mirai_error_type`
- Reasons include: `refresh_failed_async`, `refresh_failed_sync`,
  `reauth_window`, `token_expired`
- Note: `error_class` is present on refresh failure reasons
  (`refresh_failed_async`, `refresh_failed_sync`) but absent for
  `reauth_window` and `token_expired`; `mirai_error_type` is only
  present for async refresh-failure clears

### Token revocation

#### Event: `audit_token_revocation`

- When:
  [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
  reaches a final outcome (including early `unsupported` or
  `missing_token` returns) during logout or session end
- Context:
  - `provider`, `issuer`, `client_id_digest`
  - `which` (“access” or “refresh”)
  - `supported` (logical), `revoked` (logical\|NA), `status`
- `status` values include `"ok"`, `"revocation_unsupported"`,
  `"missing_token"`, and `"http_<code>"`

### Refresh failures while keeping the session (indefinite sessions)

#### Event: `audit_refresh_failed_but_kept_session`

- When: a token refresh attempt fails but the module is configured not
  to clear the session (i.e., `indefinite_session = TRUE` in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md))
- Context: `provider`, `issuer`, `client_id_digest`, `reason`
  (`refresh_failed_async`\|`refresh_failed_sync`), `kept_token` (TRUE),
  `error_class`, `mirai_error_type`
- `mirai_error_type` is only present on async refresh failures

### Browser cookie/WebCrypto error

#### Event: `audit_browser_cookie_error`

- When: the browser reports it could not set/read the module cookie or
  WebCrypto is unavailable
- Context: `provider`, `issuer`, `client_id_digest`, `reason`,
  `url_protocol`
- Notes: This typically indicates that third-party cookies are blocked,
  all cookies are disabled, or the WebCrypto API is unavailable in the
  environment (e.g., very old browsers or restrictive embedded
  webviews).

### Invalid browser token

#### Event: `audit_invalid_browser_token`

- When: the module receives an invalid `shinyOAuth_sid` value from the
  browser and requests regeneration
- Context: `provider`, `issuer`, `client_id_digest`, `reason`, `length`

### Token refresh

#### Event: `audit_token_refresh`

- When:
  [`refresh_token()`](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.md)
  successfully refreshes the access token
- Context: `provider`, `issuer`, `client_id_digest`,
  `refresh_token_rotated`, `new_expires_at`, `expires_in_synthesized`
- `expires_in_synthesized` (logical): `TRUE` when the refresh response
  did not include a usable `expires_in` value and the package used the
  configured fallback token lifetime

### Userinfo fetch

#### Event: `audit_userinfo`

- When:
  [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  is called to retrieve user information (emitted on success and various
  failure modes)
- Context: `provider`, `issuer`, `client_id_digest`, `sub_digest`,
  `status`
- `status` values:
  - `"ok"` – userinfo successfully parsed
  - `"parse_error"` – response could not be parsed as JSON or JWT.
    Additional fields: `http_status`, `url`, `content_type`,
    `body_digest`
  - `"userinfo_missing_sub"` – OIDC userinfo response was parsed but
    omitted the required `sub` claim
  - `"userinfo_not_jwt"` – signed JWT required but response was not
    `application/jwt`. Additional fields: `content_type`
  - `"userinfo_jwt_encrypted"` – userinfo response was a JWE, which
    ‘shinyOAuth’ does not decrypt
  - `"userinfo_jwt_header_parse_failed"` – JWT header could not be
    parsed
  - `"userinfo_jwt_header_invalid"` – JWT header parsed but was
    malformed or structurally invalid
  - `"userinfo_jwt_typ_invalid"` – JWT header `typ` did not indicate a
    JWT
  - `"userinfo_jwt_unsigned"` – JWT uses `alg=none`. Additional fields:
    `jwt_alg`
  - `"userinfo_jwt_alg_rejected"` – JWT algorithm not in provider’s
    allowed asymmetric algorithms. Additional fields: `jwt_alg`
  - `"userinfo_jwt_no_issuer"` – provider issuer not configured for JWKS
    verification
  - `"userinfo_jwt_jwks_fetch_failed"` – JWKS fetch failed during
    signature verification
  - `"userinfo_jwt_signature_invalid"` – signature verification failed
    against candidate JWKS keys
  - `"userinfo_jwt_no_matching_key"` – provider JWKS had no compatible
    key for the JWT
  - `"userinfo_jwt_payload_parse_failed"` – JWT payload could not be
    parsed as JSON
  - `"userinfo_jwt_missing_sub"`, `"userinfo_jwt_missing_iss"`,
    `"userinfo_jwt_missing_aud"` – signed JWT omitted a required claim
  - `"userinfo_jwt_iss_mismatch"`, `"userinfo_jwt_aud_mismatch"` –
    signed JWT claims did not match the configured issuer/client
  - `"userinfo_jwt_missing_required_temporal_claims"` – signed JWT
    omitted required temporal claims such as `exp` or `iat`
  - `"userinfo_jwt_invalid_exp"`, `"userinfo_jwt_invalid_iat"`,
    `"userinfo_jwt_invalid_nbf"` – temporal claim was present but not a
    single usable numeric value
  - `"userinfo_jwt_expired"`, `"userinfo_jwt_iat_future"`,
    `"userinfo_jwt_nbf_future"` – temporal claim failed time validation

### State parsing failures

State parsing failures occur while decoding and validating the encrypted
wrapper prior to extracting the logical state value, and also when
deriving a cache key from a malformed logical state string.

#### Event: `audit_state_parse_failure`

- When: the encrypted state wrapper or its components fail
  validation/decoding, or cache-key derivation receives an invalid
  logical state string
- Context: includes `phase` (`decrypt` or `cache_key`), a `reason` code,
  and either `token_digest` (`phase = decrypt`) or `state_digest`
  (`phase = cache_key`), plus any additional details (such as lengths).
  Emitted best-effort from parsing utilities and never interferes with
  control flow.

### Error response state consumption

Provider error callbacks still need valid login state and browser
binding. The events below report the one-time state consumption, not the
outcome of all callback checks. Browser mismatches use
`audit_callback_validation_failed` with
`phase = "browser_token_validation"`.

#### Event: `audit_error_state_consumed`

- When: state from an error response is successfully consumed
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`

#### Event: `audit_error_state_consumption_failed`

- When: consumption of state from an error response fails
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `error_class`, `error_message`

Digest note: when the callback `state` can be decrypted, these events
use the logical plaintext state digest so they correlate with
`audit_redirect_issued` and the normal callback validation/store events.
If decryption fails, the digest falls back to the encrypted callback
payload because the logical state is unknown.

### Module/session lifecycle

#### Event: `audit_session_started`

- When: the authentication module
  ([`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md))
  is initialized for a Shiny session
- Context: `module_id`, `ns_prefix`, `client_provider`, `client_issuer`,
  `client_id_digest`, plus the standard `shiny_session` context
  described above

#### Event: `audit_session_ended`

- When: a Shiny session ends (always emitted by `onSessionEnded`,
  regardless of configuration)
- Context: `provider`, `issuer`, `client_id_digest`, `was_authenticated`

#### Event: `audit_session_ended_revoke`

- When: a Shiny session ends with `revoke_on_session_end = TRUE` and a
  token was present
- Context: `provider`, `issuer`, `client_id_digest`; the actual
  revocation attempt is logged separately as `audit_token_revocation`
  events

### Authentication state changes

#### Event: `audit_authenticated_changed`

- When: the `$authenticated` reactive value changes (TRUE ↔︎ FALSE)
- Context: `provider`, `issuer`, `client_id_digest`, `authenticated`,
  `previous_authenticated`, `reason`
- Reasons include: `login` (when becoming authenticated), or the error
  code/state that caused de-authentication (e.g., `token_expired`,
  `logged_out`, `token_cleared`)

### Error events

In addition to the `audit_*` events above, the hook also receives error
events emitted just before the package raises an R error condition.
These let you log failures to the same sink as audit events.

#### Event: `error`

- When: a package error is raised during package processing (state
  validation, PKCE, token, ID token, userinfo, configuration, input,
  parse errors)
- Fields:
  - `type` (`"error"`), `trace_id`, `message`,
  - Plus any `context` fields from the call site (typically `provider`,
    `issuer`, `client_id_digest`, `phase`, `error_class`)

#### Event: `http_error`

- When: an outbound HTTP request to a provider endpoint returns a
  non-success status
- Fields:
  - `type` (`"http_error"`), `trace_id`, `message`
  - `status`: HTTP status code (integer, or `NA` if unavailable)
  - `url`: the request URL without userinfo, query, or fragment
  - `body_digest`: HMAC-SHA-256 hex digest of the response body using
    the configured or per-process audit digest key (for correlation
    without leaking content)
  - `oauth_error`, `oauth_error_uri`: RFC 6749 §5.2 structured error
    fields extracted from JSON error responses (e.g., from the token
    endpoint)
  - `oauth_error_description`: included only when
    `options(shinyOAuth.expose_error_body = TRUE)` is enabled for
    debugging, because provider-controlled text can contain
    request-specific details
  - Plus any `context` fields from the call site

#### Event: `transport_error`

- When: an outbound HTTP request fails before receiving a response (DNS
  failure, timeout, connection reset, etc.)
- Fields:
  - `type` (`"transport_error"`), `trace_id`, `message`
  - Plus any `context` fields from the call site
