# Audit logging and hooks

## Overview

An audit log records login attempts, token operations and session
changes. Use it to investigate a failed sign-in or find out why a
session ended.

shinyOAuth sends each event to an R function called a hook. Your hook
decides where to write it: the console for local testing, or your
application’s logging service in a deployment. For timings and
monitoring dashboards, see
[OpenTelemetry](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md).

## Receiving audit events

Put this near the top of `app.R`, before creating the provider and
client:

``` r

options(shinyOAuth.audit_hook = function(event) {
  cat(sprintf("[shinyOAuth] %s | %s\n", event[["type"]], event[["trace_id"]]))
  str(event)
})
```

Run the app and sign in. Events such as `audit_redirect_issued` and
`audit_login_success` describe the steps taken. The `trace_id` connects
events from the same login attempt, so use it to follow a failure across
several steps. Several error events can describe one failed login.

Set `options(shinyOAuth.audit_hook = NULL)` to stop receiving events.
Keep hooks fast: waiting for a slow logging service can delay the
operation being recorded.

## Authentication outcomes

Start with `audit_authenticated_changed` for the module’s authentication
state and `audit_session_cleared` for why a session ended. A successful
token exchange is an intermediate step; later identity checks can still
reject the login.

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
- `http`: a summary with request method, host, and scheme by default.

The session context is a JSON-friendly list suitable for
[`jsonlite::toJSON()`](https://jeroen.r-universe.dev/jsonlite/reference/fromJSON.html);
the raw Shiny `session[["request"]]` object is not included. If
`shinyOAuth.audit_include_raw_session_token = TRUE`, the raw session
token is available as `shiny_session[["token"]]` in native hook events.

Fields ending in `_digest` allow matching without recording the original
token or identifier. The package’s `trace_id` is separate from
OpenTelemetry trace/span IDs; OTel exports it as `shinyoauth.trace_id`.

## HTTP context and redaction

Logs can have a wider audience and longer retention than private app
data. Keep the default redaction settings in production. They omit raw
session tokens, request paths, query strings, headers, and client
addresses from the HTTP summary.

To omit HTTP context entirely:

``` r

options(shinyOAuth.audit_include_http = FALSE)
```

If you need route names, configure `shinyOAuth.telemetry_path_scrubber`
to replace identifying path segments with safe labels, such as
`/users/:id`. Keep credentials and patient or account identifiers out of
those labels. Your logging service still needs appropriate access and
retention controls.

## Audit events from asynchronous workers

With `async = TRUE`, the hook also runs in background R processes. Use a
logging service that supports several writers, or open the logging
connection inside each worker. A worker cannot safely reuse a database
connection from the main process, and appending to a global list changes
only that worker’s copy.

## Digest keys across R processes

Digest fields let you match events without logging the original
identifier. The default key lasts for one R process and its async
workers. If you need to match records across app processes or restarts,
load the same secret key in each:

``` r

audit_digest_key <- Sys.getenv("AUDIT_DIGEST_KEY", unset = NA_character_)
if (is.na(audit_digest_key) || !nzchar(audit_digest_key)) {
  stop("AUDIT_DIGEST_KEY must be configured before the app starts")
}
options(shinyOAuth.audit_digest_key = audit_digest_key)
```

Generate the secret from at least 32 cryptographically random bytes and
keep it in deployment secret storage. The key is for log correlation; it
does not restore login sessions.

## Event catalog

Match the event name from your log to the operation below. Use
`trace_id` to follow the same attempt, then inspect `phase`, `reason`,
`status` or `error_class` when present. A successful intermediate step
does not establish final login.

### Login and callbacks

| Name | What it tells you |
|----|----|
| `audit_redirect_issued` | The authorization URL is ready. |
| `audit_callback_received` | Encrypted-state validation passed; later checks can still fail. |
| `audit_callback_query_rejected` | Callback parameters are malformed or too large. |
| `audit_callback_routing_rejected` | The callback could not be assigned to a configured client. |
| `audit_callback_iss_missing` | The callback omitted a required provider identifier. |
| `audit_callback_iss_mismatch` | The provider identifier does not match the expected issuer. |
| `audit_callback_iss_validation_failed` | Another issuer check failed. |
| `audit_callback_validation_success` | State, browser binding and single-use checks passed. |
| `audit_callback_validation_failed` | A callback check failed; inspect `phase` and `error_class`. |
| `audit_state_parse_failure` | Login state could not be decoded or validated. |
| `audit_state_store_lookup_failed` | The pending login record could not be read. |
| `audit_state_store_removal_failed` | The pending record could not be consumed safely. |
| `audit_error_state_consumed` | State from a provider error response was consumed; other checks can still fail. |
| `audit_error_state_consumption_failed` | State from a provider error response could not be consumed. |
| `audit_browser_cookie_error` | Browser cookie setup failed or Web Crypto is unavailable. |
| `audit_invalid_browser_token` | The browser sent an invalid binding token; the module requests a replacement. |
| `audit_login_success` | Callback handling completed its configured checks. |
| `audit_login_failed` | Login failed during callback handling. |

### Tokens and profiles

| Name | What it tells you |
|----|----|
| `audit_token_exchange` | An authorization code was exchanged for tokens. |
| `audit_token_exchange_error` | Token exchange failed. |
| `audit_token_refresh` | The access token was refreshed. |
| `audit_token_introspection` | A token-activity check finished; inspect `active` and `status`. |
| `audit_token_revocation` | A revocation attempt finished, or was unsupported or missing a token. |
| `audit_userinfo` | Profile retrieval or validation finished; `status` describes the result. |

### Sessions and saved connections

| Name | What it tells you |
|----|----|
| `audit_session_started` | The authentication module started for a Shiny session. |
| `audit_authenticated_changed` | The module authentication state changed. |
| `audit_logout` | The module received a logout request. |
| `audit_session_cleared` | Local login state was cleared; `reason` explains why. |
| `audit_refresh_failed_but_kept_session` | Refresh failed, but `indefinite_session = TRUE` retained local login state. |
| `audit_connection_disconnected` | One retained connection was removed locally. |
| `audit_connections_disconnected` | A bulk local removal finished, including an empty batch. |
| `audit_session_ended` | The Shiny session ended. |
| `audit_session_ended_revoke` | Session end triggered configured token-revocation cleanup. |

### Error records

| Name | What it tells you |
|----|----|
| `error` | The package raised an R error; inspect the error class and available context. |
| `http_error` | A provider returned an unsuccessful HTTP status. |
| `transport_error` | A request failed before a response arrived, for example after a timeout. |

Disconnect events confirm local removal even if remote revocation fails.
The per-connection `remote_refresh_outcome` and `remote_access_outcome`
describe the remote attempts; an accepted request does not prove the
provider recognized the token. Ending a Shiny session leaves browser-
and account-retained connections in place.

For `audit_userinfo`, `status` distinguishes successful parsing from
invalid JSON, missing identity fields, and signature or claim failures.
Inspect that status before enabling detailed error output. HTTP error
records can also include `status` and structured `oauth_error` fields;
keep provider-controlled messages out of production logs.

For DPoP nonce handling and mTLS endpoint selection, inspect the related
[OpenTelemetry
spans](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.html#span-catalog).
