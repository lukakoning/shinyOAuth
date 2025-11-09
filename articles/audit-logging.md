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
- `shiny_session$http`: a compact HTTP summary with fields:
  - `method`, `path`, `query_string`, `host`, `scheme`, `remote_addr`
  - `headers`: a list of request headers derived from `HTTP_*`
    environment variables, with lowercase names (e.g., `user_agent`,
    `x_forwarded_for`).

Note: the raw `session$request` from Shiny is not included to keep the
event JSON-serializable and concise.

Note: the `shiny_session$http` summary intentionally captures all
`HTTP_*` headers and the raw `QUERY_STRING` from the active Shiny
request. If you forward events to a log sink, this may include sensitive
material such as the authorization code, `state`, and every request
header (including `Cookie`, `Authorization`, and other bearer tokens).
Consider stripping or redacting sensitive headers and query parameters
in your hook before exporting.

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
  `error_class`, `phase` (`state_store_lookup`)
- Notes: The flow aborts with an invalid state error.

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

### Login result

#### Event: `audit_login_success`

- When: token set is verified and an `OAuthToken` is created
- Context: `provider`, `issuer`, `client_id_digest`, `sub_digest`,
  `refresh_token_present`, `expires_at`

#### Event: `audit_login_failed`

- When: surface-level login failure during callback handling in the
  Shiny module
- Context: `provider`, `issuer`, `client_id_digest`, `phase`
  (`sync_token_exchange`\|`async_token_exchange`), `error_class`

### Logout and session clears

#### Event: `audit_logout`

- When: `values$logout()` is called on the module
- Context: `provider`, `issuer`, `client_id_digest`, `reason` (default
  `manual_logout`)

#### Event: `audit_session_cleared`

- When: the module clears the token reactively
- Context: `provider`, `issuer`, `client_id_digest`, `reason`
- Reasons include: `refresh_failed_async`, `refresh_failed_sync`,
  `reauth_window`, `token_expired`

### Refresh failures while keeping the session (indefinite sessions)

#### Event: `audit_refresh_failed_but_kept_session`

- When: a token refresh attempt fails but the module is configured not
  to clear the session (i.e., `indefinite_session = TRUE` in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md))
- Context: `provider`, `issuer`, `client_id_digest`, `reason`
  (`refresh_failed_async`\|`refresh_failed_sync`), `kept_token` (TRUE),
  `error_class`

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
  `had_refresh_token`, `new_expires_at`

### Userinfo fetch

#### Event: `audit_userinfo`

- When:
  [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  successfully retrieves user information
- Context: `provider`, `issuer`, `client_id_digest`, `sub_digest`

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

### Module/session lifecycle

#### Event: `audit_session_started`

- When: the authentication module
  ([`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md))
  is initialized for a Shiny session
- Context: `module_id`, `ns_prefix`, `client_provider`, `client_issuer`,
  `client_id_digest`, plus the standard `shiny_session` context
  described above

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
