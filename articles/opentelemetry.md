# OpenTelemetry logs and traces

## Overview

shinyOAuth exports diagnostic logs and traces through OpenTelemetry
(OTel), using the `otel` R package. Logs record events such as a failed
token exchange. Traces group related operations into spans, which record
their duration and outcome. This allows authentication diagnostics to be
collected alongside other application telemetry.

An exporter sends the records to a console, file, or monitoring service.
The `otel` package is a dependency of shinyOAuth; install `otelsdk` for
its exporters. For R callbacks that receive events directly, see [Audit
logging and
hooks](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md).

## Exporter configuration

Install `otelsdk`, then set these variables in a fresh R session before
loading shinyOAuth or starting the app:

``` r
# install.packages("otelsdk")
Sys.setenv(
  OTEL_TRACES_EXPORTER = "console",
  OTEL_LOGS_EXPORTER = "console",
  OTEL_LOG_LEVEL = "debug"
)
library(shinyOAuth)
```

Authenticate with the [example Shiny
app](https://lukakoning.github.io/shinyOAuth/articles/usage.html#minimal-shiny-module-example).
The console exporter prints the emitted records. To send them to a
monitoring service instead, follow the [otelsdk exporter
setup](https://otelsdk.r-lib.org/reference/collecting.html) and your
service’s endpoint and credential instructions.

If nothing appears, check that an exporter is configured before the
package first creates a logger or tracer, and that the logging and
tracing options below are enabled. Restart R after changing exporter
configuration.

## Traces and event correlation

Filter by instrumentation scope `io.github.lukakoning.shinyOAuth` in
your monitoring system. Start with `shinyOAuth.login.request` and
`shinyOAuth.callback`, then inspect token exchange or userinfo spans to
see where time was spent. The package’s `shinyoauth.trace_id` attribute
also connects related logs and spans; it is separate from OTel’s own
trace/span IDs.

The logs come from the same events as the audit hook. See the [audit
event
catalog](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.html#event-catalog)
for their meaning. The span catalog below lists names and attributes for
detailed lookup.

## Logging and tracing options

Both options default to `TRUE`; an exporter is still needed to collect
the data. Disable either signal without changing your app’s other
telemetry:

``` r
options(
  shinyOAuth.otel_logging_enabled = FALSE,
  shinyOAuth.otel_tracing_enabled = FALSE
)
```

### Asynchronous workers

For async work managed by shinyOAuth, exporter environment settings
(`OTEL_*` and `OTEL_R_*`), logging and tracing options, and trace
context are propagated to workers. SDK setup performed through R code is
not replayed automatically; run that setup in each worker or recreate
workers after changing it.

### Error attributes and redaction

- Successful operations have status `ok`; failures have status `error`
  and an `exception` event containing the error class. Condition
  messages are omitted by default and are included only with
  `options(shinyOAuth.expose_error_body = TRUE)`; those messages may
  contain provider details and should be handled as sensitive data.
- Tokens, authorization codes, state payloads, and browser tokens are
  not included as ordinary span attributes. Digest fields support
  correlation without the raw value. Keep debugging options off for
  production exports.
- Top-level package spans often start as roots so that they remain easy
  to find alongside Shiny’s reactive-update spans.

## Span catalog

Use this as a reference for a span you see in your tracing system.
Attributes are included when relevant and available; their presence can
differ between main-process and worker spans.

#### Span: `shinyOAuth.module.init`

- When: when
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  initializes for a Shiny session
- Represents: module startup and the initial `session_started` audit
  emission
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "module.init"`
  - `oauth.auto_redirect`, `oauth.refresh_proactively`,
    `oauth.revoke_on_session_end`, `oauth.indefinite_session`
  - `oauth.reauth_after_seconds`, `oauth.refresh_lead_seconds`
  - `oauth.browser_cookie_samesite`, `oauth.browser_cookie_path_root`
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.login.request`

- When: when ‘shinyOAuth’ prepares the authorization redirect in
  [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
- Represents: generation of state, PKCE material, nonce, state-store
  write, and construction of the authorization URL
- Parenting: this span is started as a root span so it remains visible
  even when login is triggered from within a Shiny reactive update
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase = "login.request"`
  - `oauth.used_pkce`
  - `oauth.nonce_enabled`
  - `oauth.scopes.requested`, `oauth.scopes.requested_count`
  - `oauth.claims.requested`
  - `oauth.claims.targets`
  - `oauth.required_acr_values`, `oauth.required_acr_values_count`
  - `oauth.max_age.requested`
  - `oauth.request_object_used`
  - `oauth.extra_auth_params_count`
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.login.par`

- When: during pushed authorization request (PAR) submission when the
  provider exposes `par_url`
- Represents: PAR request construction, client authentication, PAR
  response validation, and extraction of `request_uri`
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase = "login.par"`
  - `oauth.client_auth_style`
  - `oauth.extra_auth_params_count`
  - `oauth.extra_token_headers_count`
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.login.par.http`

- When: for outbound PAR HTTP calls
- Represents: the actual POST to the configured PAR endpoint
- Main attributes:
  - `http.request.method = "POST"`
  - `server.address`
  - `oauth.phase = "login.par"`
  - `http.response.status_code`, `http.response.content_type` after a
    response is available
- Notes:
  - this is used as a client span (`kind = "client"`)
  - redirects are rejected before client credentials or PAR parameters
    can leak

#### Span: `shinyOAuth.callback`

- When: during callback handling
- Represents:
  - synchronous callback handling in
    [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
  - the parent callback span created on the main process before async
    dispatch
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async`
  - `oauth.phase = "callback"`
  - `oauth.introspect`, `oauth.introspect_elements_count`
  - `oauth.userinfo.required`
  - `oauth.userinfo.id_token_match_required`
  - `oauth.id_token.validation_enabled`
  - Shiny session/process metadata when available
- Notes:
  - synchronous
    [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
    spans also include the joined `oauth.introspect_elements` attribute
  - the async parent callback span created on the main process carries
    only `oauth.introspect_elements_count`
- Parenting:
  - when the callback can recover the original login span context from
    the encrypted state payload, it becomes a child of that
    `shinyOAuth.login.request`
  - otherwise it is started as a root span instead of inheriting Shiny’s
    `reactive_update`

#### Span: `shinyOAuth.form_post`

- When: while the pre-session `response_mode = "form_post"` or
  `response_mode = "form_post.jwt"` POST callback is validated and
  bridged into Shiny
- Represents: form POST envelope validation, JARM validation when
  applicable, state payload validation, issuer validation, single-use
  state consumption, and transient handle storage
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "form_post.post"`
  - `oauth.response_mode = "form_post"` for plain form POST callbacks
  - `oauth.response_mode = "form_post.jwt"` for JARM POST callbacks
- Notes:
  - after state decryption succeeds, the span receives the recovered
    `shinyoauth.trace_id`
  - invalid envelopes that cannot expose a trusted state value remain
    root spans

#### Span: `shinyOAuth.form_post.bridge`

- When: when the Shiny module consumes the one-time form_post handle
  from the GET bridge query
- Represents: transient form_post handle lookup and single-use
  consumption
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "form_post.callback_lookup"`
  - `oauth.form_post.handle_digest`

#### Span: `shinyOAuth.form_post.callback.consume_state`

- When: when a resumed form-post callback must consume its sealed state
  from the state store because the pre-session bridge did not supply
  stored state values
- Represents: single-use state lookup and removal before callback
  validation
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "form_post.callback_state_consume"`

#### Span: `shinyOAuth.callback.validate`

- When: during callback validation sub-steps
- Represents multiple validation stages; distinguish them through
  `oauth.phase`
- Emitted phases currently include:
  - `callback.state_payload` and `callback.state_store_consume`
    - emitted during normal synchronous callback handling, and also on
      the main process before worker dispatch in async callback mode
  - `callback.browser_token_validation`
  - `callback.pkce_verifier_validation`
  - `callback.nonce_validation`
    - emitted during the normal synchronous callback path and, in async
      mode, inside the worker after parent context restoration
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase` set to the specific validation stage
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.callback.worker`

- When: when async callback processing restores parent trace context in
  a worker
- Represents: the worker-side child span for async callback execution
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.async = TRUE`
  - `oauth.phase = "callback.worker"`
  - propagated Shiny session/process metadata

#### Span: `shinyOAuth.token.exchange`

- When: during the authorization-code exchange
- Represents: construction of the token request, token endpoint call,
  response parsing, and token-response validation prior to deeper ID
  token verification
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase = "token.exchange"`
  - `oauth.used_pkce`
  - `oauth.client_auth_style`
  - `oauth.dpop.configured`, `oauth.dpop.bound`,
    `oauth.dpop.token_type_inferred`
  - `oauth.mtls.client_auth`, `oauth.mtls.certificate_bound_tokens`,
    `oauth.mtls.bound`
  - `oauth.extra_token_params_count`
  - `oauth.extra_token_headers_count`
  - `oauth.token_type`
  - `oauth.received_id_token`, `oauth.received_refresh_token`
  - `oauth.expires_in_present`, `oauth.expires_in_synthesized`
  - `oauth.scope.present`, `oauth.scopes.granted`
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.token.exchange.http`

- When: for outbound token endpoint HTTP calls
- Represents:
  - authorization-code token exchange HTTP request
  - refresh-token exchange HTTP request
- Distinguish the two cases with `oauth.phase`
- Emitted phases currently include:
  - `token.exchange`
  - `refresh`
- Main attributes:
  - `http.request.method = "POST"`
  - `server.address`
  - `oauth.phase`
  - `oauth.mtls.endpoint_alias` when an RFC 8705 alias URL is selected
  - `oauth.dpop.nonce_challenge`, `oauth.dpop.nonce_retry` when a DPoP
    nonce challenge occurs
  - `http.response.status_code`, `http.response.content_type` after a
    response is available
- Notes:
  - this is used as a client span (`kind = "client"`)
  - redirects are rejected before credentials can leak

#### Span: `shinyOAuth.token.verify`

- When: after a token response is available and ‘shinyOAuth’ verifies
  the token set
- Represents:
  - scope reconciliation
  - token type allowlist validation
  - ID token validation or refresh-time ID token continuity checks
  - userinfo/ID token subject matching during refresh when applicable
- Distinguish login and refresh verification through `oauth.phase`
- Emitted phases currently include:
  - `callback.verify`
  - `refresh.verify`
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase`
  - `oauth.dpop.bound`, `oauth.dpop.token_type_inferred`
  - `oauth.mtls.bound`
  - `oauth.received_id_token`
  - `oauth.received_refresh_token`
  - `oauth.id_token.required`, `oauth.id_token.present`,
    `oauth.id_token.validated`
  - `oauth.nonce.required`
  - `oauth.scope.validation_mode`
  - `oauth.scopes.requested`, `oauth.scopes.requested_count`
  - `oauth.scopes.granted`, `oauth.scopes.granted_count`
  - `oauth.required_acr_values`, `oauth.required_acr_values_count`
  - `oauth.refresh_flow`

#### Span: `shinyOAuth.userinfo`

- When: when
  [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  is called
- Represents: userinfo request orchestration, response parsing,
  JWT-vs-JSON handling, and userinfo-level validation/auditing
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.phase = "userinfo"`
  - `oauth.dpop.bound`, `oauth.dpop.token_type_inferred`
  - `oauth.mtls.client_certificate`,
    `oauth.mtls.certificate_bound_tokens`, `oauth.mtls.bound`
  - `oauth.userinfo.jwt_required`
  - `oauth.userinfo.jwt_response`
  - `oauth.userinfo.subject_present`
  - Shiny session/process metadata when available

#### Span: `shinyOAuth.userinfo.http`

- When: for the outbound userinfo HTTP call
- Represents: the actual request to the configured userinfo endpoint
- Main attributes:
  - `http.request.method = "GET"`
  - `server.address`
  - `oauth.phase = "userinfo"`
  - `oauth.mtls.endpoint_alias` when an RFC 8705 alias URL is selected
  - `oauth.dpop.nonce_challenge`, `oauth.dpop.nonce_retry` when a DPoP
    nonce challenge occurs
  - `http.response.status_code`, `http.response.content_type` after a
    response is available
- Notes:
  - this is used as a client span (`kind = "client"`)
  - redirects are rejected to avoid bearer-token leakage

#### Span: `shinyOAuth.refresh`

- When: during refresh-token processing
- Represents:
  - synchronous refresh execution in
    [`refresh_token()`](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.md)
  - the parent refresh span created on the main process before async
    dispatch
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async`
  - `oauth.phase = "refresh"`
  - `oauth.client_auth_style`
  - `oauth.dpop.configured`, `oauth.dpop.bound`,
    `oauth.dpop.token_type_inferred`
  - `oauth.mtls.client_auth`, `oauth.mtls.certificate_bound_tokens`,
    `oauth.mtls.bound`
  - `oauth.extra_token_params_count`
  - `oauth.extra_token_headers_count`
  - `oauth.token_type`
  - `oauth.received_id_token`, `oauth.received_refresh_token`
  - `oauth.expires_in_present`, `oauth.expires_in_synthesized`
  - `oauth.scope.present`, `oauth.scopes.granted`
  - current or propagated Shiny session/process metadata

#### Span: `shinyOAuth.refresh.worker`

- When: when async refresh processing restores parent trace context in a
  worker
- Represents: the worker-side child span for async refresh execution
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async = TRUE`
  - `oauth.phase = "refresh.worker"`
  - propagated Shiny session/process metadata
- Notes:
  - the actual worker-side refresh logic then runs inside a nested
    `shinyOAuth.refresh` span beneath this bridge span

#### Span: `shinyOAuth.logout`

- When: when `auth$logout()` is called from the module
- Represents: best-effort token revocation kickoff, local token/session
  clear, browser-token reset, and logout audit emission
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "logout"`

#### Span: `shinyOAuth.session.end.revoke`

- When: when a Shiny session ends with `revoke_on_session_end = TRUE`
  and ‘shinyOAuth’ starts best-effort token revocation
- Represents: the session-end revocation orchestration span around the
  paired
  [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
  calls
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `shiny.module_id`
  - `oauth.phase = "session.end.revoke"`
  - propagated Shiny session/process metadata from the ended session
    when available

#### Span: `shinyOAuth.token.revoke`

- When: during token revocation via
  [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
- Represents:
  - synchronous revocation execution
  - the parent revocation span created on the main process before async
    dispatch
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async`
  - `oauth.phase = "token.revoke"`
  - `oauth.token.which` (`"access"` or `"refresh"`)
  - `oauth.client_auth_style`
  - `oauth.extra_token_params_count`
  - `oauth.extra_token_headers_count`
  - `oauth.supported`, `oauth.revoked`, `oauth.status` after completion
  - current or propagated Shiny session/process metadata

#### Span: `shinyOAuth.token.revoke.http`

- When: for the outbound revocation endpoint HTTP call
- Represents: the actual request to the configured revocation endpoint
- Main attributes:
  - `http.request.method = "POST"`
  - `server.address`
  - `oauth.phase = "token.revoke"`
  - `http.response.status_code`, `http.response.content_type` after a
    response is available
- Notes:
  - this is used as a client span (`kind = "client"`)
  - redirects are rejected to prevent credential leakage

#### Span: `shinyOAuth.token.revoke.worker`

- When: when async revocation processing restores parent trace context
  in a worker
- Represents: the worker-side child span for async revocation execution
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async = TRUE`
  - `oauth.phase = "token.revoke.worker"`
  - `oauth.token.which` (`"access"` or `"refresh"`)
  - propagated Shiny session/process metadata
- Notes:
  - the actual worker-side revocation logic then runs inside a nested
    `shinyOAuth.token.revoke` span beneath this bridge span

#### Span: `shinyOAuth.token.introspect`

- When: during token introspection via
  [`introspect_token()`](https://lukakoning.github.io/shinyOAuth/reference/introspect_token.md)
- Represents:
  - synchronous introspection execution
  - the parent introspection span created on the main process before
    async dispatch
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async`
  - `oauth.phase = "token.introspect"`
  - `oauth.token.which` (`"access"` or `"refresh"`)
  - `oauth.client_auth_style`
  - `oauth.extra_token_params_count`
  - `oauth.extra_token_headers_count`
  - `oauth.supported`, `oauth.active`, `oauth.status` after completion
  - current or propagated Shiny session/process metadata

#### Span: `shinyOAuth.token.introspect.http`

- When: for the outbound introspection endpoint HTTP call
- Represents: the actual request to the configured introspection
  endpoint
- Main attributes:
  - `http.request.method = "POST"`
  - `server.address`
  - `oauth.phase = "token.introspect"`
  - `http.response.status_code`, `http.response.content_type` after a
    response is available
- Notes:
  - this is used as a client span (`kind = "client"`)
  - redirects are rejected to prevent credential leakage

#### Span: `shinyOAuth.token.introspect.worker`

- When: when async introspection processing restores parent trace
  context in a worker
- Represents: the worker-side child span for async introspection
  execution
- Main attributes:
  - `oauth.provider.name`, `oauth.provider.issuer`
  - `oauth.client_id_digest`
  - `oauth.async = TRUE`
  - `oauth.phase = "token.introspect.worker"`
  - `oauth.token.which` (`"access"` or `"refresh"`)
  - propagated Shiny session/process metadata
- Notes:
  - the actual worker-side introspection logic then runs inside a nested
    `shinyOAuth.token.introspect` span beneath this bridge span
