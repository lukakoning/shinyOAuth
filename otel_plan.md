# OpenTelemetry Plan for `shinyOAuth`

## Goal

Add OpenTelemetry instrumentation to `shinyOAuth` so that:

- the important steps inside and around `oauth_module_server()` are traceable with spans,
- the existing audit events and error/log output can be exported as OpenTelemetry logs,
- a small set of useful metrics is emitted,
- sync and async work stay correlated within the same trace.

This plan is intentionally shaped around the package's current architecture:

- audit and trace events already flow through `audit_event()` / `emit_trace_event()`,
- async work already captures Shiny session context and options for workers,
- most OAuth flow boundaries are already centralized in a small set of functions.

## Current state in this repo

The main observability touchpoints already exist:

- `R/errors.R`
  - `audit_event()` creates structured audit events with auto-generated `trace_id` (12-byte URL-safe random), timestamp, and optional pre-injected Shiny session context (for async workers).
  - `emit_trace_event()` fans out to `options(shinyOAuth.trace_hook)` and `options(shinyOAuth.audit_hook)`; enriches events via `augment_with_shiny_context()` (session token digest, HTTP summary, process_id) before dispatch; wraps hook calls in `tryCatch`.
  - `err_abort()` and specialized `err_*()` helpers centralize error creation with trace IDs, structured rlang conditions, and classes like `shinyOAuth_http_error`, `shinyOAuth_state_error`, etc.
  - `err_http()` extracts HTTP status, URL, body digest (SHA256), and RFC 6749 §5.2 structured error fields from responses.
  - `string_digest()` provides keyed SHA256 hashing for PII redaction in audit trails.
- `R/oauth_module_server.R`
  - owns module lifecycle, login request flow, callback handling, session end, logout, proactive refresh, expiry/reauth,
  - emits `audit_session_started`, `audit_authenticated_changed`, `audit_logout`, `audit_session_cleared`; enforces browser cookie/token validation; fires `audit_browser_cookie_error`, `audit_invalid_browser_token`.
- `R/methods__login.R`
  - owns `prepare_call()`, `handle_callback()`, `handle_callback_internal()`,
  - emits `audit_redirect_issued`, `audit_callback_received`, `audit_callback_validation_failed`, `audit_token_exchange`, `audit_token_exchange_error`, `audit_login_success`.
- `R/methods__token.R`
  - owns `refresh_token()`, `revoke_token()`, `introspect_token()`,
  - emits refresh/revocation/introspection audit events; all three support `async = TRUE` via `async_dispatch()` with full session-context and options propagation.
- `R/utils__shiny.R`
  - `capture_shiny_session_context()` captures session token, HTTP summary, and main_process_id for async workers.
  - `capture_async_options()` / `with_async_options()` propagate `shinyOAuth.*` options into workers.
  - `async_dispatch()` wraps mirai/future execution with `withCallingHandlers()` to capture warnings/messages; `replay_async_conditions()` replays them on the main thread.
  - `augment_with_shiny_context(event)` enriches events from reactive domain, pre-captured async context, or fallback worker context.

That is the main reason the recommended implementation is:

- add a thin OpenTelemetry helper layer,
- instrument the major flow boundaries with spans,
- bridge the existing event stream into OpenTelemetry logs,
- add metrics only at stable state transitions.

## Recommended dependency strategy

### Package dependency

Add `otel` to `Imports`.

Reason:

- the official `otel` guidance recommends a hard dependency for instrumented packages because it is lightweight,
- this avoids repeated `requireNamespace("otel")` checks everywhere,
- `otel` is designed to be cheap and no-op when exporters are not configured — all `otel::` API calls (spans, logs, metrics) are zero-cost when no exporter environment variables are set.

Implication: **do not add `is_tracing_enabled()` / `is_logging_enabled()` / `is_measuring_enabled()` guards** around `otel::` calls in business logic. Since all otel API functions are already no-ops without exporters, guard checks are unnecessary overhead and code noise. The only exception: if constructing attributes requires expensive computation (e.g., digesting large payloads), wrap that computation in an `is_tracing_enabled()` check — but the `otel::` call itself needs no guard.

> **Implementation note:** The actual implementation added `otel_tracing_enabled()` and `otel_logging_enabled()` option gates (`shinyOAuth.otel_tracing_enabled`, `shinyOAuth.otel_logging_enabled`). These serve a different purpose than the "guard against no-op" case above: they let operators **explicitly disable** shinyOAuth's OTel instrumentation even when exporters *are* configured (e.g., to reduce noise from a specific package while keeping other packages' telemetry active). This is an intentional user-facing control, not a performance guard.

Do **not** make `otelsdk` a runtime dependency of `shinyOAuth`.

Reason:

- instrumentation belongs in the package,
- exporter selection belongs in the app/runtime environment,
- `otelsdk` currently has stricter platform support than this package on Windows.

Important compatibility note:

- `otelsdk` currently supports R 3.6+ on Unix, but R 4.3+ on Windows.
- `shinyOAuth` currently depends on R >= 4.1.
- So tests/examples that require `otelsdk` must stay conditional and `Suggests`-only.

### Namespace import safety

**Never import `otel::log` unqualified.** It masks `base::log()` (the logarithm function).

Instead:

- always use fully qualified calls: `otel::log_info()`, `otel::log_warn()`, `otel::log_error()`, etc.,
- or use `otel::log()` with explicit severity — always via `otel::` prefix,
- in `NAMESPACE`, import only specific functions that don't collide: `otel::start_span`, `otel::start_local_active_span`, `otel::end_span`, `otel::counter_add`, `otel::up_down_counter_add`, `otel::histogram_record`, `otel::as_attributes`, `otel::pack_http_context`, `otel::extract_http_context`, `otel::get_active_span_context`, `otel::local_active_span`, `otel::with_active_span`.

## Recommended instrumentation scope

Define `otel_tracer_name` in a package source file (e.g., `R/telemetry.R`):

```r
otel_tracer_name <- "io.github.lukakoning.shinyOAuth"
```

The `otel` package auto-detects this symbol when the calling package's namespace is resolved via `topenv()`. It is used as the shared scope for tracer, logger, and meter. No need to export this symbol.

Keep one scope for the package unless a later need appears to split module/server and low-level HTTP/token flows.

## High-level design

### 1. Add a dedicated telemetry helper layer

Create a new internal file: `R/telemetry.R`, with helpers for:

- defining the instrumentation scope (`otel_tracer_name`),
- creating sanitized OpenTelemetry attributes from client/session/event data,
- starting local spans for sync work,
- starting manual spans that survive async dispatch,
- capturing and propagating OpenTelemetry parent context into workers via HTTP header serialization,
- mapping audit/error events to OpenTelemetry logs,
- emitting metrics.

This keeps raw `otel::` calls out of most business logic and avoids duplicating:

- attribute names,
- redaction rules,
- severity mapping,
- metric names.

### 2. Reuse the existing audit stream for OpenTelemetry logs

Do not create a second parallel audit system.

Instead:

- keep `audit_event()` and `emit_trace_event()` as the canonical event pipeline,
- add an OpenTelemetry log bridge inside `emit_trace_event()` (or just below it),
- continue supporting the existing `trace_hook` and `audit_hook` options unchanged.

This gives three benefits:

- existing package behavior stays backward-compatible,
- current audit redaction and digests are reused,
- async workers automatically participate because the same event pipeline already runs there.

### 3. Use spans only at the main flow boundaries

Do not add spans to every helper.

Instrument only the boundaries that matter for operator visibility:

- login request initiation,
- callback processing,
- token exchange,
- token verification,
- userinfo fetch,
- introspection,
- refresh,
- logout,
- token revocation,
- session end revocation.

Small pure helpers such as digest, URL, or parser utilities should remain untraced unless they represent a separately observable external call.

## Trace model

Prefer operation-scoped traces over a single long-lived session span.

Why:

- Shiny sessions can be long-lived,
- long spans are noisy and awkward in most backends,
- the interesting units here are login, refresh, logout, and revocation operations.

Represent session lifecycle mainly as:

- OpenTelemetry logs,
- metrics,
- span attributes/events on the relevant operation spans.

## Span naming

Use stable, low-cardinality names such as:

- `shinyOAuth.module.init`
- `shinyOAuth.login.request`
- `shinyOAuth.callback`
- `shinyOAuth.callback.validate`
- `shinyOAuth.token.exchange`
- `shinyOAuth.token.verify`
- `shinyOAuth.userinfo`
- `shinyOAuth.token.introspect`
- `shinyOAuth.refresh`
- `shinyOAuth.logout`
- `shinyOAuth.token.revoke`
- `shinyOAuth.session.end.revoke`
- `shinyOAuth.audit.emit`

Do not embed provider names, user ids, session ids, or route ids in span names.
Those belong in attributes.

## Span attributes

Only add low-cardinality, sanitized attributes. Use dotted namespaced names consistent with OpenTelemetry semantic conventions:

Good attributes:

- `oauth.provider.name`
- `oauth.provider.issuer`
- `oauth.client_id_digest`
- `oauth.async`
- `oauth.phase`
- `oauth.used_pkce`
- `oauth.received_refresh_token`
- `oauth.received_id_token`
- `oauth.refresh_token_rotated`
- `shiny.module_id`
- `shiny.session_token_digest`
- `shiny.session.is_async`
- `shiny.session.main_process_id`
- `http.request.method` (aligned with OTel HTTP semantic conventions)
- `http.response.status_code` (aligned with OTel HTTP semantic conventions)
- `server.address` (URL host only)
- `error.type`

Do not emit raw values for:

- access tokens,
- refresh tokens,
- ID tokens,
- authorization codes,
- state,
- browser token,
- raw user identifiers.

Keep using the package's existing `string_digest()` and HTTP redaction rules.

Cardinality note: attributes like `oauth.provider.name` and `shiny.module_id` are fine for span attributes. For **metric** attributes, only use the lowest-cardinality subset (provider name, async flag, outcome) to avoid metric explosion.

## Where to create spans

### `oauth_module_server()`

Add small spans for:

- module initialization: `shinyOAuth.module.init`
- manual or automatic login request path: `shinyOAuth.login.request`
- logout path: `shinyOAuth.logout`
- session-end revocation path: `shinyOAuth.session.end.revoke`

Do not create a span that stays open for the entire Shiny session.

### Callback handling

This is the most important trace in the package.

Recommended shape:

1. In `.handle_callback()`, create a parent span `shinyOAuth.callback`.
2. Use child spans for:
   - callback query validation,
   - state payload validation,
   - state store consume,
   - browser token validation.
3. Inside `handle_callback_internal()`, use child spans for:
   - token exchange,
   - token verification,
   - userinfo,
   - optional introspection.

For sync mode, this is straightforward with `otel::start_local_active_span()`. The span auto-ends when the function exits.

For async mode, use a manual parent span created on the main thread (`otel::start_span()`) and close it only in the promise `then()` / `catch()` handlers. See the async propagation section below.

### Token methods

Inside `R/methods__token.R`:

- `refresh_token()` gets a parent span `shinyOAuth.refresh`
- `revoke_token()` gets `shinyOAuth.token.revoke`
- `introspect_token()` gets `shinyOAuth.token.introspect`

These should exist in both sync and async paths.

### HTTP request child spans

For outbound HTTP requests, add child spans with `kind = "client"` around calls to:

- token endpoint,
- userinfo endpoint,
- introspection endpoint,
- revocation endpoint.

The package centralizes outbound HTTP through `add_req_defaults()` and `req_with_retry()`. The cleanest place for HTTP spans is at the call site in `swap_code_for_token_set()`, `get_userinfo()`, etc. — not inside the low-level request modifiers.

Do not scatter HTTP spans across `add_req_defaults()` or `req_with_retry()`.

## Async trace propagation

This is the most important implementation detail.

### What to avoid

Do not rely on the currently active span automatically carrying over into:

- `mirai` workers,
- `future` workers,
- promise continuation handlers.

Active spans are thread-local / process-local. They do not survive serialization across process boundaries.

### Recommended pattern: HTTP header serialization

For async callback, refresh, revoke, and introspection flows, use `otel::pack_http_context()` / `otel::extract_http_context()` for cross-process context propagation. This is the otel-recommended approach for distributed tracing and produces simple named character vectors that survive R serialization reliably.

Pattern:

1. **Main thread** — create a parent span and capture its context as serializable headers:
   ```r
   parent_span <- otel::start_span("shinyOAuth.callback")
   otel::local_active_span(parent_span)
   otel_headers <- otel::pack_http_context()
   # otel_headers is a named character vector: c(traceparent = "...", tracestate = "...")
   ```

2. **Pass to worker** — include `otel_headers` as an argument to `async_dispatch()` (alongside the existing `shiny_session_ctx` and `captured_opts`).

3. **In the worker** — extract the parent context and create a child span:
   ```r
   parent_ctx <- otel::extract_http_context(otel_headers)
   child_span <- otel::start_span(
     "shinyOAuth.callback.worker",
     options = list(parent = parent_ctx)
   )
   otel::local_active_span(child_span)
   # Work happens here — child spans created by otel::start_local_active_span()
   # inside the worker are automatically children of this span.
   otel::end_span(child_span)
   ```

4. **Main thread promise handler** — end the parent span with status:
   ```r
   promise$then(
     onFulfilled = function(result) {
       parent_span$set_status("ok")
       otel::end_span(parent_span)
     },
     onRejected = function(err) {
       parent_span$set_status("error", description = conditionMessage(err))
       otel::end_span(parent_span)
     }
   )
   ```

Why `pack_http_context()` / `extract_http_context()` instead of passing `otel_span_context` objects directly:

- `otel_span_context` is a reference-style object that may not survive R serialization across process boundaries (mirai, future, callr all serialize arguments),
- HTTP headers are a named character vector — trivially serializable,
- this is the documented otel approach for distributed tracing,
- it matches the W3C Trace Context standard (`traceparent` header).

### Worker otel availability

Since `otel` is in `Imports`, it is available in mirai/future workers (they load the installed package). For exporter configuration: `otelsdk` resolves exporters from environment variables (`OTEL_TRACES_EXPORTER`, `OTEL_LOGS_EXPORTER`, etc.). Environment variables are inherited by child processes, so workers automatically export telemetry to the same collector if the env vars are set at the process level. No extra configuration needed in workers.

## Helper shape

Add explicit helpers in `R/telemetry.R`:

- `otel_capture_context()` — calls `otel::pack_http_context()` when tracing is active; returns serializable named character vector, or `NULL` if no active span or if the result is an empty vector (which `pack_http_context()` returns when tracing is disabled)
- `otel_start_async_parent(name, attributes = NULL)` — creates a manual span, activates it, captures context via `pack_http_context()`, returns both span and headers
- `otel_restore_parent_in_worker(otel_headers, name)` — if `otel_headers` is `NULL` or empty, returns `NULL` (no-op); otherwise calls `extract_http_context()`, creates and activates child span; returns the span for manual end
- `otel_end_async_parent(span, status, error = NULL)` — if `span` is `NULL`, returns invisibly (no-op for the case where tracing was disabled); otherwise ends span with status, adding error attributes if applicable. Centralizes span-end logic to prevent missed `$end()` calls. Note: `span$end()` is idempotent per the otel API — calling it multiple times is not an error; only the first call has any effect.

Additionally, code inside helper functions that needs to enrich the current span (e.g., adding events or late attributes) can use `otel::get_active_span()` to obtain the active span object directly, without receiving it as a function parameter. This is useful for non-critical enrichment from deeply nested code paths.

Keep this separate from `capture_shiny_session_context()`:

- Shiny session context is JSON/log oriented,
- OpenTelemetry parent context is trace-oriented,
- mixing them would make the current audit event payload less clean.

Integration point: `async_dispatch()` should accept an optional `otel_headers` argument and thread it through to the worker expression alongside `captured_opts` and `shiny_session_ctx`.

## Promise continuation handling

For parent spans that stay open across async work:

- set status `ok` on success,
- set status `error` on failure,
- add failure attributes like `error.type` and `oauth.phase`,
- always end the span in both success and error branches.

Do not depend on implicit `on.exit()` cleanup for spans that outlive the current stack frame.

## OpenTelemetry logs bridge

### Source of truth

Use the existing event objects emitted by:

- `audit_event()`,
- `emit_trace_event()`,
- the `err_*()` helpers.

That is already the package's normalized event model.

### Bridge strategy

Add an internal bridge function (e.g., `otel_emit_log(event)`) called inside `emit_trace_event()`. It converts each event object into an OpenTelemetry log record.

Recommended severity mapping:

| Event type pattern | OTel severity |
|---|---|
| `audit_session_started`, `audit_session_ended`, `audit_authenticated_changed`, `audit_redirect_issued`, `audit_callback_received`, `audit_token_exchange`, `audit_token_refresh`, `audit_login_success`, `audit_logout`, `audit_token_revocation` (status=ok) | `"info"` |
| `audit_callback_validation_failed`, `audit_invalid_browser_token`, `audit_browser_cookie_error`, `audit_callback_iss_mismatch`, `audit_callback_query_rejected`, `audit_refresh_failed_but_kept_session` | `"warn"` |
| `error`, `http_error`, `transport_error`, `audit_token_exchange_error` | `"error"` |

Implementation for each log record:

```r
otel_emit_log <- function(event) {
  severity <- map_event_severity(event$type)

  # Flatten event to safe log attributes
  attrs <- otel::as_attributes(compact_list(list(
    event.type = event$type,
    shinyoauth.trace_id = event$trace_id,
    oauth.provider.name = event$provider,
    oauth.provider.issuer = event$issuer,
    # ... other safe fields, filtered through existing redaction
  )))

  # otel::log() automatically correlates with the active span context.
  # No need to pass span_context explicitly in the common case.
  otel::log(
    msg = event$type,
    severity = severity,
    attributes = attrs
  )
}
```

Key points:

- Use `otel::log()` (always qualified with `otel::` prefix to avoid masking `base::log()`).
- **Automatic span correlation**: `otel::log()` automatically uses the active span context for log/span correlation. In sync code this is the span hierarchy created by `start_local_active_span()`. In async workers this is the worker child span created by `otel_restore_parent_in_worker()`. There is no need to fetch and pass `span_context` explicitly.
- When no span is active (e.g., events during startup), logs are emitted uncorrelated — they still carry the package's `trace_id` as an attribute for manual correlation.
- **`otel::log()` pass-through**: the `attributes` parameter (and others like `span_context`, `timestamp`) are not top-level named arguments of `otel::log()` — they are forwarded through `...` to `logger$log()`, which accepts them directly. This is the intended API design. The same applies to the severity-specific helpers (`otel::log_info()`, `otel::log_warn()`, etc.).
- Never include raw tokens, codes, or state payloads in log attributes.

### Log emission placement

Emit otel logs from `emit_trace_event()` on both main thread and workers:

- Main thread: the active span context is automatically picked up by `otel::log()` from the sync span hierarchy.
- Workers: the active span context is automatically picked up from the worker child span set up by `otel_restore_parent_in_worker()`.
- No active span: logs are emitted uncorrelated (they still carry the package's `trace_id` as an attribute for manual correlation).

Since environment variables control otel exporter configuration and are inherited by workers, logs from both processes reach the same collector.

### Existing hooks

Do not remove or repurpose:

- `options(shinyOAuth.audit_hook)`
- `options(shinyOAuth.trace_hook)`

OpenTelemetry logging is additive — hooks and otel logs coexist.

## Metrics

### Principles

Start with a very small metric set.

Good first metrics are those backed by stable state transitions already present in the code.

Avoid metrics that require expensive recomputation over all sessions.

### Recommended first metrics

#### Up/down counters

Use `otel::up_down_counter_add()` for:

- `shinyoauth.sessions.active`
  - `+1` on module session start (`audit_session_started`)
  - `-1` on session end (`onSessionEnded`)
- `shinyoauth.sessions.authenticated`
  - `+1` when `authenticated` changes `FALSE -> TRUE`
  - `-1` when it changes `TRUE -> FALSE`

This is better than gauges here because the package already observes the transitions directly.

#### Counters

Use `otel::counter_add()` for:

- `shinyoauth.login.attempts`
- `shinyoauth.login.success`
- `shinyoauth.login.failure`
- `shinyoauth.refresh.success`
- `shinyoauth.refresh.failure`
- `shinyoauth.logout.total`
- `shinyoauth.token.revocation.attempts`
- `shinyoauth.token.revocation.success`
- `shinyoauth.browser_cookie_error.total`

Counter attributes (low-cardinality only):

- `oauth.provider.name`
- `oauth.async` (TRUE/FALSE)

Do **not** put high-cardinality fields (session digests, user digests, module IDs) in metric attributes — they cause metric explosion in backends like Prometheus.

#### Histograms

Use `otel::histogram_record()` for durations only if you want aggregated SLO-style views independent of traces:

- `shinyoauth.callback.duration_s` (seconds, not ms — OTel convention)
- `shinyoauth.token_exchange.duration_s`
- `shinyoauth.refresh.duration_s`
- `shinyoauth.userinfo.duration_s`

These are optional in phase 1 because traces already carry duration.

Note: OTel semantic conventions prefer seconds over milliseconds for duration metrics (the unit is encoded in metric metadata, not the name).

### Metric state correctness

The active/authenticated counts must not double-count.

Add a small per-session bookkeeping flag (e.g., in environment or reactiveValues) to track whether the session has already contributed to:

- active session count,
- authenticated session count.

That prevents incorrect decrements when:

- a session ends without ever authenticating,
- `authenticated` flips multiple times,
- errors occur during login or refresh.

Specifically: the `onSessionEnded` callback should only decrement `shinyoauth.sessions.authenticated` if the session was in authenticated state at cleanup time. Use the existing `rv$authenticated` reactive value for this check.

### Multi-worker metric considerations

When running multiple Shiny workers (e.g., behind a load balancer), each worker maintains its own metric state. Up/down counters will be per-worker. The aggregation (sum across workers) happens at the collector/backend level, which is the standard OTel model. No special handling needed in the package.

## Recommended implementation phases

### Phase 1: tracing foundation

- Add `otel` to `Imports`, `otelsdk` to `Suggests`.
- Create `R/telemetry.R` with:
  - `otel_tracer_name` definition,
  - sanitized attribute builder helpers,
  - async context propagation helpers (`otel_capture_context`, `otel_start_async_parent`, `otel_restore_parent_in_worker`, `otel_end_async_parent`).
- Instrument sync paths with `otel::start_local_active_span()`:
  - login request,
  - callback,
  - token exchange,
  - token verification,
  - userinfo,
  - refresh,
  - logout,
  - revoke,
  - introspect.
- Implement async parent-context propagation for callback and refresh:
  - Thread `otel_headers` through `async_dispatch()`,
  - create child spans in workers.

### Phase 2: OTel logs

- Add `otel_emit_log()` bridge function.
- Call it from `emit_trace_event()`.
- Map event severity consistently (see table above).
- Rely on automatic span-context correlation (otel handles this internally for the active span).
- Ensure worker-emitted events get correlated with worker child spans (via `otel_restore_parent_in_worker()` activating the span).
- Keep existing hooks untouched.

### Phase 3: first metrics

- Add up/down counters for active and authenticated sessions.
- Add counters for login/refresh/logout/revoke outcomes.
- Add per-session bookkeeping to prevent double-counting.
- Add optional duration histograms for callback, token exchange, refresh.

### Phase 4: docs and examples

- Add a vignette section or new vignette showing:
  - local collector setup (`otel-tui` or similar),
  - required OTLP environment variables (`OTEL_TRACES_EXPORTER=http`, `OTEL_LOGS_EXPORTER=http`, `OTEL_METRICS_EXPORTER=http`),
  - how package audit events appear as OpenTelemetry logs,
  - how async login and refresh appear in one trace,
  - `OTEL_ENV=dev` for development.
- Add a playground example demonstrating OTel trace visualization.

## Testing

### Phase-testing matrix

Different otel signals require different testing approaches:

| Phase | Signal | Testing tool | Notes |
|---|---|---|---|
| Phase 1 | Traces (spans) | `otelsdk::with_otel_record()` | Works for span creation, parent-child relationships, span attributes |
| Phase 2 | Logs | `otelsdk::logger_provider_file` / `logger_provider_stdstream` with temp file | `with_otel_record()` does **not** record logs yet |
| Phase 3 | Metrics | `otelsdk::with_otel_record()` | Verify coverage; use file-based provider as fallback if not supported |

Guard all otelsdk-dependent tests with `testthat::skip_if_not_installed("otelsdk")` and platform checks for Windows (otelsdk requires R >= 4.3 on Windows).

### Traces and metrics

Use `otelsdk::with_otel_record()` for unit tests of:

- span creation,
- parent-child relationships,
- span attributes,
- metrics emission.

### Logs

Since `with_otel_record()` does not record logs yet, use one of:

- `otelsdk::logger_provider_file` with a temp file,
- `otelsdk::logger_provider_stdstream` redirected to a temp file,
- a small integration test that inspects exported log records.

### Specific tests to add

- sync callback creates a `shinyOAuth.callback` trace with expected child spans,
- async callback keeps one trace across main thread and worker (verify `traceparent` propagation),
- async refresh keeps one trace across main thread and worker,
- `audit_*` events produce OpenTelemetry logs with preserved sanitized fields,
- log records carry the correct `span_context` when emitted inside an active span,
- session/authenticated metrics increment and decrement exactly once,
- session end without authentication only decrements active count (not authenticated count),
- failure paths set span status to `error`,
- no `otel::` calls break when exporters are not configured (verify no-op behavior).

## Risks and constraints

### 1. Windows exporter support

Because `otelsdk` support on Windows starts at R 4.3, package tests/examples that require exporter runtime must remain optional and skip gracefully on unsupported platforms.

### 2. High-cardinality attributes

It is easy to accidentally overload traces and metrics with:

- session token,
- state digest,
- client id digest,
- user digests.

These are fine for **logs** (individual records), acceptable for **span attributes** (bounded by operation count), but must be kept out of **metric attributes** (causes cardinality explosion).

### 3. Duplicating audit logs and span events

Do not initially emit every audit event both as:

- an OpenTelemetry log,
- and a span event.

Pick logs first. Add selected span events later only if trace readability needs it. Span events are useful for inline visibility in trace viewers, but most backends handle logs better for search/filter.

### 4. Async span lifetime bugs

The biggest correctness risk is forgetting to end manual parent spans in all async branches.

Implementation should centralize this in the `otel_end_async_parent()` helper, not duplicate `span$end()` logic inline. The helper should be defensive: calling `end()` on an already-ended span should be safe. This is guaranteed by the otel API: *"Calling the `span$end()` method on a span multiple times is not an error, the first call ends the span, subsequent calls do nothing."*

### 5. otel package maturity

The `otel` and `otelsdk` packages are relatively new. Pin to a minimum version in DESCRIPTION once the API stabilizes. Watch for breaking changes in pre-1.0 releases.

### 6. `otel::log()` name collision

As noted above, `otel::log()` shadows `base::log()`. Always qualify with `otel::` prefix. Never add `log` to `importFrom(otel, ...)` in NAMESPACE.

## Concrete recommendation

The best implementation path for this package is:

1. make `otel` a hard dependency,
2. add a small internal telemetry helper layer (`R/telemetry.R`),
3. create operation-scoped spans around callback/login/refresh/logout/revoke paths,
4. propagate context into async workers via `pack_http_context()` / `extract_http_context()`,
5. bridge the existing audit/error event stream as OpenTelemetry logs in `emit_trace_event()`,
6. add only two stateful metrics first: active sessions and authenticated sessions,
7. then add login/refresh outcome counters.

That gives you useful traces quickly, preserves the current audit model, and fits the existing sync/async architecture without a large refactor.

## References

- otel getting started: https://otel.r-lib.org/reference/gettingstarted.html
- otel reference index: https://otel.r-lib.org/reference/
- `start_span()`: https://otel.r-lib.org/reference/start_span.html
- `start_local_active_span()`: https://otel.r-lib.org/reference/start_local_active_span.html
- `local_active_span()`: https://otel.r-lib.org/reference/local_active_span.html
- `with_active_span()`: https://otel.r-lib.org/reference/with_active_span.html
- `end_span()`: https://otel.r-lib.org/reference/end_span.html
- `otel_span_context`: https://otel.r-lib.org/reference/otel_span_context.html
- `pack_http_context()` / `extract_http_context()`: https://otel.r-lib.org/reference/pack_http_context.html / https://otel.r-lib.org/reference/extract_http_context.html
- `log()` / `log_info()` / `log_error()` / `log_warn()`: https://otel.r-lib.org/reference/log.html
- `otel_logger`: https://otel.r-lib.org/reference/otel_logger.html
- `counter_add()`: https://otel.r-lib.org/reference/counter_add.html
- `up_down_counter_add()`: https://otel.r-lib.org/reference/up_down_counter_add.html
- `histogram_record()`: https://otel.r-lib.org/reference/histogram_record.html
- `as_attributes()`: https://otel.r-lib.org/reference/as_attributes.html
- `get_active_span()`: https://otel.r-lib.org/reference/get_active_span.html
- `get_active_span_context()`: https://otel.r-lib.org/reference/get_active_span_context.html
- `gauge_record()`: https://otel.r-lib.org/reference/gauge_record.html
- `default_tracer_name()`: https://otel.r-lib.org/reference/default_tracer_name.html
- `is_tracing_enabled()`: https://otel.r-lib.org/reference/is_tracing_enabled.html
- `is_logging_enabled()`: https://otel.r-lib.org/reference/is_logging_enabled.html
- `is_measuring_enabled()`: https://otel.r-lib.org/reference/is_measuring_enabled.html
- Environment variables: https://otel.r-lib.org/reference/environmentvariables.html
- otelsdk collecting docs: https://otelsdk.r-lib.org/reference/collecting.html
- otelsdk testing helper: https://otelsdk.r-lib.org/reference/with_otel_record.html
- otelsdk project status / platform support: https://otelsdk.r-lib.org/
