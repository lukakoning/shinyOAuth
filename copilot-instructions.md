# AI Coding Guide

## Project Snapshot

- shinyOAuth is an S7-based OAuth/OIDC toolkit for Shiny; top-level flow
  lives in R/oauth_module_server.R with supporting UI glue in
  R/use_shinyOAuth.R.
- Core domain objects are S7 classes in R/classes\_\_OAuthProvider.R,
  R/classes\_\_OAuthClient.R, R/classes\_\_OAuthToken.R; prefer helper
  constructors (`oauth_provider_*()`,
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md))
  over manual `new_class` calls.
- S7 is a modern OOP system in R; follow existing patterns for generics,
  methods, and validation when extending or adding classes. Access
  properties with `@` (e.g., `client@state_key`), define with
  [`S7::new_property()`](https://rconsortium.github.io/S7/reference/new_property.html),
  and add class-level checks with `validator` arguments. See
  <https://rconsortium.github.io/S7/> for documentation.

## File Organization & Naming

- **Classes**: `R/classes__*.R` - S7 class definitions with
  [`S7::new_class()`](https://rconsortium.github.io/S7/reference/new_class.html),
  validators, and properties
- **Methods**: `R/methods__*.R` - S7 generic implementations (login,
  token, userinfo, client_bearer_req)
- **Utilities**: `R/utils__*.R` - Topic-organized helpers (http, jwt,
  jwks, crypt, state, url, scopes, shiny, random, base64url)
- **Providers**: `R/providers.R` and `R/providers__oidc_discovery.R` -
  Built-in provider configs and OIDC discovery
- **Development**: `playground/*.R` - Full working examples for manual
  provider testing (not shipped with package)
- **Examples**: `inst/examples/*.R` - Minimal code snippets illustrating
  specific features (shipped with package)
- Common R idioms: use `%||%` for null coalescing, `compact_list()` to
  drop NULL/NA from lists, `is_valid_string()` for non-empty string
  checks

## Core Code Paths

- [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  orchestrates redirect→callback→token→refresh, exposing a
  reactiveValues API (`request_login()`, `logout()`, `build_auth_url()`)
  and watchdogs for missing JS/browser tokens.
- Token exchange, refresh, and userinfo logic live in
  R/methods\_\_login.R, R/methods\_\_token.R, R/methods\_\_userinfo.R;
  these rely on `swap_code_for_token_set()` and expect httr2 requests to
  pass through `add_req_defaults()` and `req_with_retry()`.
- UI resources ship via inst/www/shinyOAuth.js and must be loaded once
  per app via
  [`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md);
  the watchdog warning fires if
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  runs before this helper sets the flag.

## Security & State

- OAuthClient instances seal state payloads with AES-GCM using
  `client@state_key` and single-use cache entries
  ([`state_store_get_remove()`](https://lukakoning.github.io/shinyOAuth/reference/state_store_get_remove.md));
  share both key and cache across workers in production deployments.
- Host validation is centralized in
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  and enforced by OAuthProvider validators; always pipe new endpoints
  through these helpers and avoid bypassing the checks.
- Provider objects gate PKCE/nonce/id-token policies and `token_type`
  enforcement; align new provider helpers with existing defaults in
  R/providers.R (e.g., `allowed_algs`, `allowed_token_types`).

## HTTP & External Providers

- Every outbound call should wrap
  [`httr2::request()`](https://httr2.r-lib.org/reference/request.html)
  with `add_req_defaults()` for timeout/UA and `req_with_retry()` for
  transient handling; tune via
  `options(shinyOAuth.timeout, shinyOAuth.retry_*)`.
- [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
  intersects discovery metadata with caller `allowed_algs` and infers
  `token_auth_style`; surface configuration failures with
  `err_config()`/`err_http()` to retain trace ids.
- Built-in providers (`oauth_provider_github/google/microsoft/...`)
  illustrate `extra_token_headers`, JWKS pinning, and fingerprinting;
  mirror their structure when adding providers so tests can stub with
  `with_mocked_bindings()`.

## Shiny Integration

- Module cookies bind browser sessions using Web Crypto; tests and
  headless contexts can skip the requirement with
  `options(shinyOAuth.skip_browser_token = TRUE)` or by stubbing values
  via helper functions.
- Async flows require promises, future, and later; configure a plan
  (e.g., `future::plan(multisession)`) when enabling `async = TRUE` or
  tests will degrade to synchronous warnings.
- Tab title cleanup, cookie scope, and proactive refresh are all
  configurable arguments to
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md);
  document new parameters with roxygen comments and guard them with
  `stopifnot` validations.

## Auditing & Diagnostics

- `audit_event()`/`emit_trace_event()` in R/errors.R send redacted
  telemetry to `options(shinyOAuth.trace_hook)` and
  `options(shinyOAuth.audit_hook)`; preserve hashed identifiers via
  `string_digest()` when logging new fields.
- All error paths should raise via `err_abort` wrappers (`err_token()`,
  `err_invalid_state()`, `err_userinfo()`, etc.) so trace ids and
  structured context propagate to Shiny logs and audit hooks.
- Options like `shinyOAuth.print_errors` and
  `shinyOAuth.print_traceback` let operators tune verbosity; respect
  these flags instead of printing directly.

## Error Handling

- Throw failures with the typed helpers in R/errors.R (`err_abort()`
  plus `err_token()`/`err_invalid_state()`/`err_http()`, etc.); they
  wrap [`rlang::abort`](https://rlang.r-lib.org/reference/abort.html)
  with package-specific classes and inject trace ids, so avoid base
  [`stop()`](https://rdrr.io/r/base/stop.html).
- For recoverable notices use
  [`rlang::warn()`](https://rlang.r-lib.org/reference/abort.html)/`inform()`
  with cli-style bullet vectors and frequency guards (see
  `warn_about_missing_js_dependency()` and
  `client_state_store_max_age()`) instead of
  [`message()`](https://rdrr.io/r/base/message.html)/[`warning()`](https://rdrr.io/r/base/warning.html);
  surface structured context via `context = list()`.
- Prefer adding new `err_*` or `warn_*` helpers next to existing ones so
  tests can assert on condition classes and message formats.
- Default to rlang/cli idioms for developer messaging: use
  [`cli::cli_warn()`](https://cli.r-lib.org/reference/cli_abort.html)/`cli_inform()`
  or
  [`rlang::warn()`](https://rlang.r-lib.org/reference/abort.html)/`inform()`
  with cli bullets, and avoid
  [`cat()`](https://rdrr.io/r/base/cat.html)/[`print()`](https://rdrr.io/r/base/print.html)/[`message()`](https://rdrr.io/r/base/message.html)
  unless tests explicitly stub those paths.

## Testing Workflow

- Run tests: `Rscript -e "testthat::test_local()"` from the repo root.
- Tests extensively mock network calls with
  [`testthat::with_mocked_bindings()`](https://testthat.r-lib.org/reference/local_mocked_bindings.html)
  and spin up webfakes servers for HTTP integration tests; keep new HTTP
  helpers injectable and return httr2 responses so mocks remain simple.
- Use the existing test helpers in tests/testthat/helper-login.R:
  `make_test_client()`, `make_test_provider()`, `valid_browser_token()`,
  `parse_query_param()` instead of reimplementing fixtures.
- Async module tests reset `future::plan(future::sequential)` and use
  `poll_for_async()` helper to flush
  [`later::run_now()`](https://later.r-lib.org/reference/run_now.html)
  and `session$flushReact()` until conditions are met; timeout/interval
  configurable via `SHINYOAUTH_TEST_POLL_TIMEOUT` and
  `SHINYOAUTH_TEST_POLL_INTERVAL` env vars.
- Set `NOT_CRAN=true` environment variable to enable
  security/timing/webfakes tests that are skipped on CRAN (this is set
  automatically in CI workflows).
- Ensure state-store logic exposes `get`/`set`/`remove`/`missing`
  signatures so duck-typing checks in OAuthClient/OAuthProvider
  validators pass; use
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  wrapper for non-cachem backends.
- Integration tests (Docker-based Keycloak, GCP) live in integration/;
  these are separate from unit tests and run via CI workflows
  (.github/workflows/integration-tests.yml).

## Documentation & Examples

- Roxygen comments in R/ generate man/ via
  `Rscript -e "devtools::document()"`; never hand-edit .Rd files.
- Example Shiny integrations live in inst/examples/ (shipped with
  package) and playground/ (development only, not shipped); long-form
  guidance in vignettes/\*.Rmd.
- Vignettes: `usage.Rmd` (comprehensive guide),
  `authentication-flow.Rmd` (security deep-dive), `audit-logging.Rmd`
  (logging/auditing), `example-spotify.Rmd` (provider example).
- Update examples and vignettes alongside API changes so pkgdown docs
  stay accurate
- `.onLoad()` already registers S7 methods (R/zzz.R); when adding
  generics ensure
  [`S7::methods_register()`](https://rconsortium.github.io/S7/reference/methods_register.html)
  is triggered and namespace imports remain consistent.
- Linting: run `jarl check .` to check for errors; use
  `jarl check . --fix --allow-dirty` to check & fix
- Formatting: run `air format .` to format all files

## Backwards Compatibility

- Pre-release stage: no previous release to maintain backwards
  compatibility with. Breaking changes are acceptable; do not leave
  leftover compatibility shims.
- If you think backwards compatibility code is needed, discuss first.

## Global Options

- Do not add new global options unless specifically requested. All
  options must be documented in the ‘usage’ vignette.
