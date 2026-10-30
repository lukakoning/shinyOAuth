# Package options reference

## What package options are for

Package options control settings shared by the whole R process,
including network timeouts and diagnostic logging. Most apps can use the
defaults; adjust them for a specific need, such as a provider that
responds slowly.

Use
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
and
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
arguments for settings that belong to one app registration or module.
Start with
[Usage](https://lukakoning.github.io/shinyOAuth/articles/usage.md) if
you have not configured login yet.

## Set an option at app startup

For example, give a slow provider up to ten seconds per network request.
Put this near the top of `app.R`, before creating the provider and
client:

``` r

options(shinyOAuth.timeout = 10)
```

A longer timeout gives a slow provider more time to respond, but delays
failure when the service is unavailable. Restore the default with
`options(shinyOAuth.timeout = NULL)`.

Options affect other sessions sharing that R process. Configure them
once at startup instead of changing them for individual users.

Times use seconds unless a setting explicitly says milliseconds.

## Logging

Use these options to send diagnostic events to your logging service and
control which request details it receives.

- `options(shinyOAuth.audit_hook = function(event){ ... })` – receive
  structured audit and error events

- `options(shinyOAuth.audit_include_http = FALSE)` – exclude HTTP
  request details from audit events (default: `TRUE`)

- `options(shinyOAuth.audit_include_raw_session_token = TRUE)` – include
  the raw `shiny_session[["token"]]` in native audit-hook payloads. By
  default, hooks receive only `shiny_session[["session_token_digest"]]`

- `options(shinyOAuth.audit_redact_http = FALSE)` – disable automatic
  redaction of sensitive data in audit events (default: `TRUE`). Debug
  only: raw mode can expose cookies, authorization headers, codes, state
  values, and client IP addresses

- `options(shinyOAuth.telemetry_path_scrubber = function(path) NULL)` –
  return approved route labels for audit and OTel paths, which are
  omitted by default. Return `NULL` for unknown routes, remove
  identifying segments, and make the function idempotent.

- `options(shinyOAuth.audit_digest_key = ...)` – shared HMAC-SHA256 key
  of at least 32 bytes for audit/OTel correlation. The default is a
  random per-process key; invalid configured keys cause an error.

- `options(shinyOAuth.otel_tracing_enabled = FALSE)` – disable
  ‘shinyOAuth’ OpenTelemetry span creation and async trace-context
  propagation. Default: `TRUE`

- `options(shinyOAuth.otel_logging_enabled = FALSE)` – disable
  ‘shinyOAuth’ OpenTelemetry log emission. Default: `TRUE`

- `options(shinyOAuth.otel_include_authorization_details = TRUE)` –
  include raw scope names, claim targets, and ACR values in telemetry.
  Default: `FALSE` (counts only). These fields can reveal private
  information and produce many distinct telemetry values.

See [Audit
logging](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)
for R hook examples and
[OpenTelemetry](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md)
for log and trace exporter setup.

## HTTP settings (timeout, retries, user agent)

Network settings control how long requests may wait and how much data
they may return. Adjust them for a specific provider or API; larger
limits also allow a failing request to use more time or memory.

- `options(shinyOAuth.tls_min_version = "1.2")` - require TLS 1.2 or
  later for package HTTPS requests (the default). Use `"1.3"` for a
  higher minimum; an absent option or `NULL` restores TLS 1.2. Set this
  before discovery or login. It applies to async workers too; browser
  and reverse-proxy TLS must be configured separately.

- `options(shinyOAuth.timeout = 5)` – default HTTP timeout (seconds)
  applied to all outbound requests (discovery, JWKS, token exchange,
  userinfo). Increase if your provider/network is slow. Values beyond
  curl’s supported timeout range are capped

- `options(shinyOAuth.retry_max_tries = 3L)` – maximum attempts after
  network errors or HTTP 408, 429 or 5xx responses. Code exchange and
  refresh skip automatic retries, apart from one DPoP nonce-challenge
  retry.

- `options(shinyOAuth.dpop_nonce_max_bytes = 4096L)` – maximum DPoP
  nonce size in bytes; supported range 1 to 65536. Increase it only when
  the provider issues larger nonces.

- `options(shinyOAuth.retry_backoff_base = 0.5)` – base backoff in
  seconds used for exponential backoff with jitter

- `options(shinyOAuth.retry_backoff_cap = 5)` – per‑attempt cap on
  backoff seconds (before jitter)

- `options(shinyOAuth.retry_after_cap = 60)` – maximum synchronous sleep
  in seconds for a server-provided `Retry-After` value; this is separate
  from the client-side backoff cap

- `options(shinyOAuth.retry_status = c(408L, 429L, 500:599))` – HTTP
  statuses considered transient and retried

- `options(shinyOAuth.user_agent = "shinyOAuth/<version> R/<version> httr2/<version>")`
  – override the HTTP User-Agent. The default includes the installed
  package and R versions; set a custom value if your organization
  requires one.

- `options(shinyOAuth.allow_redirect = FALSE)` – keep `FALSE` for
  sensitive provider requests. Enabling redirects can forward codes,
  tokens or credentials to another destination; the opt-in applies in
  all sessions.

- `options(shinyOAuth.max_body_bytes = 1048576)` - maximum response size
  (default 1 MiB) for package requests and connection calls. Increase it
  if an API legitimately returns more data. Use
  [`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
  for prepared requests as well as URLs to retain this limit.

## Async timeout (mirai)

A task timeout limits how long background work may run. Configure
workers first, as shown in
[Usage](https://lukakoning.github.io/shinyOAuth/articles/usage.html#asynchronous-execution).

- `options(shinyOAuth.async_timeout = 10000)` – per-task timeout in
  milliseconds for mirai async tasks. When using mirai with dispatcher
  (the default), timed-out tasks are automatically cancelled and resolve
  as a mirai error. Use `NULL` (the default) for no timeout, or a whole
  number from 0 to 2147483647. Ignored when falling back to the ‘future’
  backend

## Async condition replay

Background workers can return warnings and messages to the app. Turn
replay off if another logging system already handles those diagnostics.

- `options(shinyOAuth.replay_async_conditions = FALSE)` – when `FALSE`,
  warnings and messages captured from async workers are silently
  discarded instead of being re-emitted on the main R process. Default
  is `TRUE` (replay all captured conditions). Useful if worker
  diagnostics are too noisy or handled separately via `audit_hook`

## Token lifetime fallback

Some providers omit the token lifetime. This fallback lets ordinary
OAuth clients track expiry in that case.

- `options(shinyOAuth.default_expires_in = 3600)` – fallback token
  lifetime (in seconds) when the provider omits `expires_in` from the
  token response

## Validation and URL policy

These settings affect which responses and addresses the app accepts.
Keep the defaults unless your provider or development setup requires a
specific change.

- `options(shinyOAuth.access_token_cnf = "opaque")` – use `"opaque"` to
  avoid decoding access-token binding data. The compatibility default
  `"jwt"` reads `cnf` without signature verification. DPoP and mTLS
  still check available binding and present their configured
  credentials. Requiring visible confirmation is a separate client
  policy.

- `options(shinyOAuth.leeway = 30)` – default clock skew leeway
  (seconds) for ID token `exp`/`iat`/`nbf` checks and state payload
  `issued_at` future check

- `options(shinyOAuth.max_id_token_lifetime = 86400)` – maximum ID token
  lifetime in seconds (`exp - iat`). This is an additional package check
  beyond the OIDC expiry check. Default `86400` (24 hours). Set to `Inf`
  to disable the check

- `options(shinyOAuth.allowed_non_https_hosts = c("localhost", "127.0.0.1", "::1", "[::1]"))` -
  allows these hosts to use `http://` in non-OIDC URL checks; it does
  not relax OIDC discovery

- `options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)` –
  development-only opt-in for OIDC issuer and endpoint URLs on HTTP
  loopback origins; production OIDC metadata URLs must use HTTPS

- `options(shinyOAuth.allowed_hosts = c())` – when non-empty, restricts
  accepted hosts to this list

- `options(shinyOAuth.allow_hs = TRUE)` – opt‑in HMAC validation for ID
  tokens (HS256/HS384/HS512). Requires a strictly server‑side
  `client_secret` and exactly one HS algorithm in
  `id_token_allowed_algs`, binding the shared key to one algorithm (RFC
  8725 section 3.1)

- `options(shinyOAuth.client_assertion_ttl = 120L)` – lifetime in
  seconds for JWT client assertions used with `client_secret_jwt` or
  `private_key_jwt` token endpoint authentication. Finite values below
  60 seconds are coerced to 60 seconds, finite values above 300 seconds
  are clamped to 300 seconds, and `NA` or non-finite values fall back to
  the 120-second default

- `options(shinyOAuth.state_fail_delay_ms = 0)` – delay before
  state-validation failures, in milliseconds. Default `0` adds no delay;
  one positive number sets a fixed delay, two set random bounds.
  Positive delays block R even with `async = TRUE`; they add timing
  noise rather than constant-time validation.

`allowed_hosts` patterns support globs (`*`, `?`). A catch-all such as
`"*"` accepts any host; scheme restrictions still apply. Restrict access
to your domains, for example `c(".example.com")`, unless you intend to
accept any host.

## State store

Pending login records let the app recognize the returning browser.
Shared stores must consume each record only once, even when several R
processes handle requests.

- `options(shinyOAuth.allow_non_atomic_state_store = TRUE)` – allow
  separate reads and deletes in a shared store. Default `FALSE` requires
  atomic `[["take"]]()`. Enabling this can let concurrent requests reuse
  a login record; use an atomic store in production. See
  [custom_cache()](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.html).

## Size caps

### State envelope

- `options(shinyOAuth.state_max_token_chars = 8192)` – maximum allowed
  length of the base64url-encoded `state` query parameter
- `options(shinyOAuth.state_max_wrapper_bytes = 8192)` – maximum decoded
  byte size of the outer JSON wrapper (before parsing)
- `options(shinyOAuth.state_max_ct_b64_chars = 8192)` – maximum allowed
  length of the base64url-encoded ciphertext inside the wrapper
- `options(shinyOAuth.state_max_ct_bytes = 8192)` – maximum decoded byte
  size of the ciphertext before attempting AES-GCM decrypt

These limits keep oversized state parameters from using excessive CPU or
memory during decoding and decryption.

### Callback query

- `options(shinyOAuth.callback_max_code_bytes = 8192)` – maximum decoded
  authorization-code bytes. Oversized values are rejected without
  truncation.

- `options(shinyOAuth.callback_max_state_bytes = 8192)` – maximum byte
  length of the `state` query parameter (outer token string)

- `options(shinyOAuth.callback_max_error_bytes = 256)` – maximum byte
  length of the `error` query parameter

- `options(shinyOAuth.callback_max_error_description_bytes = 4096)` –
  maximum byte length of the `error_description` query parameter

- `options(shinyOAuth.callback_max_error_uri_bytes = 2048)` – maximum
  byte length of the `error_uri` query parameter

- `options(shinyOAuth.callback_max_iss_bytes = 2048)` – maximum byte
  length of the `iss` query parameter (RFC 9207 issuer identification)

- `options(shinyOAuth.callback_max_query_bytes = <derived>)` – maximum
  raw query bytes. Applies before parsing to app queries, callbacks and
  hosted Request Objects.

- `options(shinyOAuth.callback_max_browser_token_bytes = 256)` – maximum
  byte length of the `browser_token` argument accepted by
  [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)

- `options(shinyOAuth.callback_max_form_post_body_bytes = <derived>)` –
  maximum byte length of the raw `form_post` callback body before
  parsing

- `options(shinyOAuth.callback_max_form_post_handle_bytes = 128)` –
  maximum byte length of the transient `shinyOAuth_form_post` handle
  query parameter

- `options(shinyOAuth.callback_max_form_post_id_bytes = 256)` – maximum
  byte length of the transient `shinyOAuth_form_post_id` module-id query
  parameter

These limits reject oversized callback URLs and POST bodies before they
cause excessive processing or logging. Keep the defaults unless a
legitimate provider response needs more space.

Generated login state must fit both
`shinyOAuth.callback_max_state_bytes` and the state envelope limits
above. Their outer-token defaults both allow 8192 bytes (base64url state
is ASCII). Lowering either limit can restrict ordinary logins with many
scopes or other state metadata.
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
checks both budgets before storing pending login state, publishing a
Request Object, or sending PAR. Increasing only one limit does not
override the other.

## Configuration assessments

Use `check_oauth21(client)` to review settings without making requests
or changing the app. The report separates configuration problems,
recommendations and things that need deployment testing. See
[check_oauth21()](https://lukakoning.github.io/shinyOAuth/reference/check_oauth21.html)
for an example and the specification revision assessed.

## Local debugging

- `options(shinyOAuth.skip_browser_token = TRUE)` – skip browser cookie
  binding in tests or interactive sessions
- `options(shinyOAuth.skip_id_sig = TRUE)` – skip ID token signature
  verification in tests or interactive sessions
- `options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)` – accept
  unsigned (`alg=none`) UserInfo JWTs in tests or interactive sessions;
  outside those contexts ‘shinyOAuth’ errors instead of honoring it
- `options(shinyOAuth.debug = TRUE)` – re‑raise errors during token
  exchange
- `options(shinyOAuth.expose_error_body = TRUE)` – enable sanitized
  diagnostic text for local debugging. Fields are capped at 512 UTF-8
  bytes and can still contain private provider data. Production
  processes keep this disabled.

Don’t enable these options in production. They disable key security
checks or alter error behavior, and are intended for local
testing/debugging only.

## Advanced transport constraints

The TLS policy preserves stronger supplied minima and custom CA
settings, while rejecting incompatible maxima or disabled certificate
checks. It does not enable HTTP development exceptions or configure
browser and proxy TLS.

Response limits cover both downloaded and decoded gzip data; other
encodings are rejected. Use `perform_resource_req(token, request)` to
retain the decoded size limit, adding `client` for DPoP or mTLS. Direct
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html)
uses httr2’s transport settings instead.

## Advanced parameter overrides

Prefer the named client and provider arguments. Overrides are for
integrations that need an explicit exception to the normal parameter
policy.

By default, shinyOAuth blocks security-critical parameters in
`extra_auth_params`, `extra_token_params`, and `extra_token_headers` to
protect state binding, PKCE and client authentication from accidental
overrides.

Set the callback format with `oauth_client(response_mode = ...)`.

To override a blocked parameter, use the options below. Some parameters
cannot be unblocked.

- `options(shinyOAuth.unblock_auth_params = c("redirect_uri"))` – allow
  selected authorization-parameter overrides. Transaction, credential
  and PKCE fields remain protected.

- State, nonce, credentials, PKCE and protocol transaction fields remain
  protected. Allowed overrides replace names case-insensitively without
  adding duplicates.

- `options(shinyOAuth.unblock_token_params = c(...))` – allow selected
  token-exchange parameter overrides, subject to protected transaction
  and credential fields.

- `options(shinyOAuth.unblock_token_headers = c("authorization"))` –
  allow selected token-header overrides, matched case-insensitively.
  `Authorization` and `Cookie` are blocked by default.
