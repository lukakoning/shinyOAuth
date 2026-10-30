# OpenTelemetry logs and traces

## Overview

OpenTelemetry sends diagnostic information to a monitoring service. Logs
record events such as failed logins, while traces time the operations
involved so you can locate a slow token exchange or other provider
request. A span is one timed operation within a trace.

For an R callback that receives events directly, see [Audit
logging](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md).

shinyOAuth uses the `otel` package to create records. An exporter sends
those records to the console or your monitoring service; install
`otelsdk` to provide one.

## Exporter configuration

Start with console output to check the setup locally. Run this in a
fresh R session, before loading shinyOAuth or starting the app:

``` r

# install.packages("otelsdk")
Sys.setenv(
  OTEL_TRACES_EXPORTER = "console",
  OTEL_LOGS_EXPORTER = "console",
  OTEL_LOG_LEVEL = "debug"
)
library(shinyOAuth)
```

Sign in with the [example
app](https://lukakoning.github.io/shinyOAuth/articles/usage.html#minimal-shiny-module-example)
and look for login and callback records in the console. If nothing
appears, check that logging and tracing are enabled and restart R after
changing the exporter.

Once that works, follow the [otelsdk exporter
setup](https://otelsdk.r-lib.org/reference/collecting.html) and your
monitoring service’s endpoint and credential instructions.

## Traces and event correlation

Filter by instrumentation scope `io.github.lukakoning.shinyOAuth`. Start
with `shinyOAuth.login.request` and `shinyOAuth.callback`, then inspect
token exchange or profile-fetch spans to find the slow or failing
operation.

The `shinyoauth.trace_id` attribute connects logs and spans from the
same package operation. It is separate from OpenTelemetry’s own trace
and span IDs. Logs describe the same events as the audit hook.

## Logging and tracing options

shinyOAuth enables logging and tracing by default; an exporter collects
the records. If your monitoring service only needs one, disable the
other:

``` r

options(
  shinyOAuth.otel_logging_enabled = FALSE,
  shinyOAuth.otel_tracing_enabled = FALSE
)
```

## Protecting diagnostic data

By default, shinyOAuth omits raw tokens, detailed error messages, URL
paths, query strings, and scope or claim names. Counts remain available.
`shinyOAuth.telemetry_path_scrubber` adds approved route labels, while
`shinyOAuth.expose_error_body` separately controls diagnostic text.

### Authorization metadata privacy

Permission names can help explain a failed authorization. This option
adds those names to the exported records:

``` r

options(shinyOAuth.otel_include_authorization_details = TRUE)
```

The added names can identify privileges, tenants or data categories.
This option is independent of detailed error-message exposure.

## Asynchronous workers

shinyOAuth passes exporter environment variables and trace context to
its background workers. It does not replay R setup code, so exporters
configured through R require their initialization in each worker.

## Advanced diagnostic fields

### Error attributes and redaction

Successful operations normally have status `ok`, and failures have
status `error`. For revocation and introspection, missing tokens or
unsupported endpoints leave status unset. An inactive token is a
successful introspection response (`oauth.active = FALSE`). Thrown
errors also record an `exception` event with the error class.

Log messages default to the event type. `shinyOAuth.expose_error_body`
can add sanitized diagnostic text during debugging. That text can still
contain private provider data. URLs omit paths unless an approved path
scrubber supplies a route label. Tokens, codes and raw login state stay
out of ordinary span attributes.

These protections cover records emitted through shinyOAuth. Direct SDK
calls and requests sent with
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html)
follow their own telemetry settings.
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
applies shinyOAuth’s request handling.

## Span catalog

HTTP spans time network calls; worker spans identify background
processing. Attributes appear only when relevant and available. Useful
fields include `oauth.phase`, `server.address` and
`http.response.status_code`, alongside provider and session digests.

| Name | What it tells you |
|----|----|
| `shinyOAuth.module.init` | Authentication module startup. |
| `shinyOAuth.login.request` | Preparing the authorization request and pending login state. |
| `shinyOAuth.login.par` | Preparing and validating a pushed authorization request. |
| `shinyOAuth.login.par.http` | The HTTP request to the PAR endpoint. |
| `shinyOAuth.callback` | Processing the returning login response. |
| `shinyOAuth.form_post` | Validating a POST callback before the Shiny session receives it. |
| `shinyOAuth.form_post.bridge` | Consuming the one-time POST callback handle. |
| `shinyOAuth.callback.validate` | Callback checks; `oauth.phase` identifies the check. |
| `shinyOAuth.callback.worker` | Callback processing in an asynchronous worker. |
| `shinyOAuth.token.exchange` | Exchanging an authorization code for tokens. |
| `shinyOAuth.token.exchange.http` | The HTTP token request for code exchange or refresh. |
| `shinyOAuth.token.verify` | Token type, scope and identity checks after a token response. |
| `shinyOAuth.userinfo` | Fetching, parsing and validating the user profile. |
| `shinyOAuth.userinfo.http` | The HTTP request to the profile endpoint. |
| `shinyOAuth.refresh` | Refreshing tokens, including work dispatched to a worker. |
| `shinyOAuth.refresh.worker` | The worker-side part of an asynchronous refresh. |
| `shinyOAuth.logout` | Local logout and the start of token cleanup. |
| `shinyOAuth.session.end.revoke` | Token cleanup requested when a Shiny session ends. |
| `shinyOAuth.token.revoke` | A token-revocation operation. |
| `shinyOAuth.token.revoke.http` | The HTTP request to the revocation endpoint. |
| `shinyOAuth.token.revoke.worker` | The worker-side part of asynchronous revocation. |
| `shinyOAuth.token.introspect` | A token-activity check. |
| `shinyOAuth.token.introspect.http` | The HTTP request to the introspection endpoint. |
| `shinyOAuth.token.introspect.worker` | The worker-side part of asynchronous introspection. |
