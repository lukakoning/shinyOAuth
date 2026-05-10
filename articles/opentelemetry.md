# OpenTelemetry

## Overview

‘shinyOAuth’ can emit OpenTelemetry (OTel) logs and traces for key login
steps. If you already collect OTel data in your apps, this lets
shinyOAuth fit into the same observability setup.

The `otel` package is installed automatically with `shinyOAuth`. Install
`otelsdk` as well if you want to use the SDK helpers and exporters shown
in the examples below.

OpenTelemetry is an open standard for telemetry data (logs, traces,
metrics) that many backends can collect. If you do not use it, you can
skip this vignette and rely on the package’s native R hooks for auditing
and tracing instead (see
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)).

Please refer to the
‘[otelsdk](https://otelsdk.r-lib.org/reference/collecting.html)’ package
to learn more about configuring exporters in R. Once that is set up,
‘shinyOAuth’ will automatically emit OTel signals.

All signals are emitted under the instrumentation scope
`io.github.lukakoning.shinyOAuth`. Use this identifier when configuring
collector routing rules or filtering ‘shinyOAuth’ telemetry in your
backend.

This vignette describes the OTel signals emitted by ‘shinyOAuth’, their
content, and how to enable/disable them.

## Logs

OTel log records are generated from the same structured events that
shinyOAuth emits to its native R hook (`shinyOAuth.audit_hook`). The log
content and event types mirror what is described in
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md),
so refer there for full details about the various events and their
content.

The package’s own audit correlation id is exported as the scalar
attribute `shinyoauth.trace_id`. This is different from OpenTelemetry’s
trace/span ids. When a shinyOAuth operation-level correlation id is
available, spans also carry the same `shinyoauth.trace_id` attribute so
you can connect the pieces of one login flow more easily.

When `options(shinyOAuth.otel_logging_enabled = FALSE)` is set,
‘shinyOAuth’ stops emitting all OTel logs.

## Traces

‘shinyOAuth’ also emits OpenTelemetry spans from key operations in the
OAuth flows. All spans share these behaviors:

- Successful operations are marked with status `ok`; errors are marked
  `error` and include an `exception` event with the error class and
  message
- Top-level shinyOAuth operation spans are often started as roots so
  they stay visible instead of being buried under Shiny’s internal
  `reactive_update` spans
- Sensitive values (tokens, codes, state payloads, browser tokens) are
  never attached as span attributes

When `options(shinyOAuth.otel_tracing_enabled = FALSE)` is set,
‘shinyOAuth’ stops emitting all OTel spans.

### Span catalog

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

- When: when shinyOAuth prepares the authorization redirect in
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

- When: after a token response is available and shinyOAuth verifies the
  token set
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
  and shinyOAuth starts best-effort token revocation
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
