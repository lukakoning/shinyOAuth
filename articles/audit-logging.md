# Audit logging and hooks

## Overview

‘shinyOAuth’ emits structured audit events at key steps in the OAuth
2.0/OIDC flow. These may help detect anomalous activity (e.g., brute
force, replay, or configuration errors).

This vignette covers: - How to register audit hooks to export/store
events - Which audit events are emitted & what fields are included in
each event - Best practices

## Receiving audit events

There are two hook options you can set. Both receive the same event
object (a named list). The functions you should register under these
options should be fast, non-blocking, and never throw errors.

- `options(shinyOAuth.audit_hook = function(event) { ... })` - intended
  for audit-specific sinks
- `options(shinyOAuth.trace_hook = function(event) { ... })` - a more
  general-purpose tracing hook used for both audit events and error
  traces

Example of printing audit events to console:

``` r
options(shinyOAuth.audit_hook = function(event) {
    cat(sprintf("[AUDIT] %s %s\n", event$type, event$trace_id))
    str(event)
})
```

To stop receiving events, unset the option:

``` r
options(shinyOAuth.audit_hook = NULL)
```

## Event structure

All audit events share the following base shape:

- `type`: a string starting with `audit_...`
- `trace_id`: a short correlation id for linking related records
- `timestamp`: POSIXct time when the event was created (from
  [`Sys.time()`](https://rdrr.io/r/base/Sys.time.html))
- Additional key/value fields depending on the event (see event catalog)

When events are emitted from within a Shiny session, a JSON-friendly
`shiny_session` list is attached to every event to correlate audit
activity with the HTTP request and session. The structure is designed to
be directly serializable with
[`jsonlite::toJSON()`](https://jeroen.r-universe.dev/jsonlite/reference/fromJSON.html):

- `shiny_session$token`: the Shiny per-session token (`session$token`)
  when available.
- `shiny_session$is_async`: a logical indicating whether the event was
  emitted from the main R process (`FALSE`) or from an async worker
  (`TRUE`). This helps distinguish logs produced by background tasks
  (e.g., async token exchange or refresh) from those in the main
  reactive flow.
- `shiny_session$process_id`: the process ID (PID) of the R process that
  emitted the event.
- `shiny_session$main_process_id`: (async events only) the PID of the
  main R process that spawned the async worker. This allows you to
  correlate events from workers back to the originating main process.
- `mirai_error_type`: (async failure events only) classifies mirai
  transport-level failures separately from application-level errors.
  Present on `login_failed`, `session_cleared`, and
  `refresh_failed_but_kept_session` events:
  - `"mirai_error"` — code threw an R error inside the worker
  - `"mirai_timeout"` — the task exceeded its timeout and was cancelled
    by dispatcher
  - `"mirai_connection_reset"` — the daemon process crashed or was
    terminated
  - `"mirai_interrupt"` — the task was interrupted/cancelled via
    `stop_mirai()`
  - `NA` — not a mirai-specific error (e.g., sync path or future
    backend)
- `shiny_session$http`: a compact HTTP summary with fields:
  - `method`, `path`, `query_string`, `host`, `scheme`, `remote_addr`
  - `headers`: a list of request headers derived from `HTTP_*`
    environment variables, with lowercase names (e.g., `user_agent`).

Note: the raw `session$request` from Shiny is not included to keep the
event JSON-serializable and concise.

### HTTP context sanitization

For safety, the `shiny_session$http` summary is automatically sanitized
before being attached to events. This prevents accidental secret leakage
when forwarding events to log sinks:

- **OAuth query parameters are redacted**: `code`, `state`,
  `access_token`, `refresh_token`, `id_token`, `token`, `session_state`,
  `code_verifier`, and `nonce` are replaced with `[REDACTED]`.
- **Sensitive headers are removed**: `Cookie`, `Set-Cookie`,
  `Authorization`, `Proxy_Authorization`, `Proxy_Authenticate`, and
  `WWW-Authenticate` headers are stripped entirely.
- **Proxy headers are redacted**: Headers starting with `x_` (e.g.,
  `x_forwarded_for`, `x_real_ip`) are replaced with `[REDACTED]` to
  avoid leaking internal infrastructure details.

This means you can safely forward the `shiny_session$http` object to
external logging systems without manually stripping secrets.

If you need the raw, unsanitized HTTP context in audit events, you can
disable redaction:

``` r
options(shinyOAuth.audit_redact_http = FALSE)
```

### Excluding HTTP context entirely

To completely exclude HTTP request details from audit events:

``` r
options(shinyOAuth.audit_include_http = FALSE)
```

This means that the `shiny_session$http` field will be `NULL` in all
audit events.

### Audit events from async workers (mirai daemons)

When `async = TRUE` is configured in
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
and when you have set daemon workers
[`mirai::daemons()`](https://mirai.r-lib.org/reference/daemons.html),
token exchange, refresh, and revocation run in background mirai daemon
processes. The package automatically propagates your
`shinyOAuth.audit_hook` and `shinyOAuth.trace_hook` options to these
workers, so audit events fire also in the async worker processes and
your hooks apply there.

Note that your audit hook function (and any objects referenced in its
closure) must be serializable. If your hook writes to a database
connection, file handle, or other non-serializable resource, it will
fail silently in the worker process. Use hooks that create connections
on demand (e.g., open a database connection inside the hook body) rather
than capturing an existing connection in the closure.

### Digest fields and keying

Many audit events include digest fields such as `client_id_digest`,
`state_digest`, `code_digest`, `browser_token_digest`, and `sub_digest`.
These are intended to let you correlate events without emitting raw
sensitive values.

By default, these digests use HMAC-SHA256 with an auto-generated
per-process key. This reduces the risk of correlation or dictionary
reidentification if logs leak.

If you run multiple workers/processes and want digests to be comparable
across them, configure a shared key:

``` r
options(shinyOAuth.audit_digest_key = Sys.getenv("AUDIT_DIGEST_KEY"))
```

To disable keying (legacy deterministic SHA-256 digests):

``` r
options(shinyOAuth.audit_digest_key = FALSE)
```

Note: unkeyed digests are pseudonymous, not anonymized—low-entropy
identifiers (like email addresses) can be dictionary-attacked.

## Event catalog

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
  - `nonce_present` (logical)
  - `scopes_count`
  - `redirect_uri`

### Callback query rejected

#### Event: `audit_callback_query_rejected`

- When: the callback query parameters fail validation (e.g., too large)
- Context: `provider`, `issuer`, `client_id_digest`, `error_class`

### Callback issuer mismatch

#### Event: `audit_callback_iss_mismatch`

- When: the callback includes an `iss` query parameter (per RFC 9207)
  that does not match the provider’s expected issuer
- Context: `provider`, `expected_issuer`, `client_id_digest`

### Callback received

#### Event: `audit_callback_received`

- When:
  [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
  begins processing a callback
- Context: `provider`, `issuer`, `client_id_digest`, `code_digest`,
  `state_digest`, `browser_token_digest`

### Callback validation

Callback validation spans decryption + freshness + binding of the
encrypted payload as well as subsequent checks of values bound to the
state (browser token, PKCE code verifier, nonce). Each check emits
either a success (only once for the payload) or a failure audit event.

#### Event: `audit_callback_validation_success`

- When: the encrypted `state` payload has been decrypted and verified
  for freshness and client/provider binding (emitted from
  [`state_payload_decrypt_validate()`](https://lukakoning.github.io/shinyOAuth/reference/state_payload_decrypt_validate.md))
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`

#### Event: `audit_callback_validation_failed`

- When: a validation step fails prior to token exchange
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `phase`, `error_class` (+ `browser_token_digest` when phase is
  `browser_token_validation`)
- Phases include: `payload_validation`, `browser_token_validation`,
  `pkce_verifier_validation`, `nonce_validation`
- Note: Failures related to state store access (lookup/removal) are
  reported as their own events (see below) rather than using the
  `callback_validation_failed` event.

### State store access

State retrieval and removal of the single-use state entry are emitted as
separate events by
[`state_store_get_remove()`](https://lukakoning.github.io/shinyOAuth/reference/state_store_get_remove.md).

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
  `used_pkce`, `received_id_token`, `received_refresh_token`

#### Event: `audit_token_exchange_error`

- When: token exchange fails
- Context: `provider`, `issuer`, `client_id_digest`, `code_digest`,
  `error_class`

### Token introspection

#### Event: `audit_token_introspection`

- When:
  [`introspect_token()`](https://lukakoning.github.io/shinyOAuth/reference/introspect_token.md)
  is called (e.g., during login if `introspect = TRUE`)
- Context:
  - `provider`, `issuer`, `client_id_digest`
  - `which` (“access” or “refresh”)
  - `supported` (logical), `active` (logical\|NA), `status`
  - `sub_digest`, `introspected_client_id_digest`, `scope_digest` (when
    available)

### Login result

#### Event: `audit_login_success`

- When: token set is verified and an `OAuthToken` is created
- Context: `provider`, `issuer`, `client_id_digest`, `sub_digest`,
  `sub_source`, `refresh_token_present`, `expires_at`

`sub_source` indicates where `sub_digest` was derived from:

- `userinfo`: subject came from the userinfo response
- `id_token`: subject came from an ID token that was validated
  (signature + claims)
- `id_token_unverified`: subject came from an ID token payload parse
  when ID token validation was not performed

#### Event: `audit_login_failed`

- When: surface-level login failure during callback handling in the
  Shiny module
- Context: `provider`, `issuer`, `client_id_digest`, `phase`
  (`sync_token_exchange`\|`async_token_exchange`), `error_class`,
  `mirai_error_type`

### Logout and session clears

#### Event: `audit_logout`

- When: `values$logout()` is called on the module
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
  `reauth_window` and `token_expired`

### Token revocation

#### Event: `audit_token_revocation`

- When:
  [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
  is called (e.g., during logout or session end)
- Context:
  - `provider`, `issuer`, `client_id_digest`
  - `which` (“access” or “refresh”)
  - `supported` (logical), `revoked` (logical\|NA), `status`

### Refresh failures while keeping the session (indefinite sessions)

#### Event: `audit_refresh_failed_but_kept_session`

- When: a token refresh attempt fails but the module is configured not
  to clear the session (i.e., `indefinite_session = TRUE` in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md))
- Context: `provider`, `issuer`, `client_id_digest`, `reason`
  (`refresh_failed_async`\|`refresh_failed_sync`), `kept_token` (TRUE),
  `error_class`, `mirai_error_type`

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
  `refresh_token_rotated`, `new_expires_at`

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
  - `"userinfo_not_jwt"` – signed JWT required but response was not
    `application/jwt`. Additional fields: `content_type`
  - `"userinfo_jwt_header_parse_failed"` – JWT header could not be
    parsed
  - `"userinfo_jwt_unsigned"` – JWT uses `alg=none`. Additional fields:
    `jwt_alg`
  - `"userinfo_jwt_alg_rejected"` – JWT algorithm not in provider’s
    allowed asymmetric algorithms. Additional fields: `jwt_alg`
  - `"userinfo_jwt_no_issuer"` – provider issuer not configured for JWKS
    verification

### State parsing failures

State parsing failures occur while decoding and validating the encrypted
wrapper prior to extracting the logical state value.

#### Event: `audit_state_parse_failure`

- When: the encrypted state wrapper or its components fail
  validation/decoding
- Context: includes `phase = decrypt`, a `reason` code (e.g.,
  `token_b64_invalid`, `iv_missing`, `tag_len_invalid`), `token_digest`,
  and any additional details (such as lengths). Emitted best-effort from
  parsing utilities and never interferes with control flow.

### Error response state consumption

When the provider returns an error response (e.g., `access_denied`) but
includes the `state` parameter, the module attempts to consume the state
to prevent replay and clean up the store.

#### Event: `audit_error_state_consumed`

- When: state from an error response is successfully consumed
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`

#### Event: `audit_error_state_consumption_failed`

- When: consumption of state from an error response fails
- Context: `provider`, `issuer`, `client_id_digest`, `state_digest`,
  `error_class`, `error_message`

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

## Where to find these in code

- Redirect and login audits are emitted from `R/methods__login.R`
- Module lifecycle/session audits are emitted from
  `R/oauth_module_server.R`
- All events flow through `audit_event()` defined in `R/errors.R`, which
  delegates to the hook options

## Best practices for audit hooks

- Keep hooks fast and never throw; wrap internals with
  `try(..., silent = TRUE)` if needed
- Export to your logging backend in JSON for easy parsing
- Do not attempt to reverse digests; use them only for correlation
- Consider adding a host/app identifier to the record before exporting
- If you also want error traces, set
  `options(shinyOAuth.trace_hook=...)`

Example of a JSON export hook:

``` r
json_hook <- function(event) {
    try({
        line <- jsonlite::toJSON(event, auto_unbox = TRUE, null = "null")
        cat(line, "\n", file = "shinyOAuth-audit.log", append = TRUE)
    }, silent = TRUE)
}

options(shinyOAuth.audit_hook = json_hook)
```
