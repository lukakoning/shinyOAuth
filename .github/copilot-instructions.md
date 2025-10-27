# AI Coding Guide
## Project Snapshot
- shinyOAuth is an S7-based OAuth/OIDC toolkit for Shiny; top-level flow lives in R/oauth_module_server.R with supporting UI glue in R/use_shinyOAuth.R.
- Core domain objects are S7 classes in R/classes__OAuthProvider.R, R/classes__OAuthClient.R, R/classes__OAuthToken.R; prefer helper constructors (oauth_provider_*(), oauth_client()) over manual new_class calls.
- S7 is a new OOP system in R; follow existing patterns for generics, methods, and validation when extending or adding new classes. If you
need more information about S7, refer to .github/copilot-instructions-S7.md
## Core Code Paths
- oauth_module_server() orchestrates redirect→callback→token→refresh, exposing a reactiveValues API (request_login(), logout(), build_auth_url()) and watchdogs for missing JS/browser tokens.
- Token exchange, refresh, and userinfo logic live in R/methods__login.R, R/methods__token.R, R/methods__userinfo.R; these rely on swap_code_for_token_set() and expect httr2 requests to pass through add_req_defaults() and req_with_retry().
- UI resources ship via inst/www/shinyOAuth.js and must be loaded once per app via use_shinyOAuth(); the watchdog warning is triggered if oauth_module_server() runs before this helper sets the flag.
## Security & State
- OAuthClient instances seal state payloads with AES-GCM using client@state_key and single-use cache entries (state_store_get_remove()); share both key and cache across workers in production deployments.
- Host validation is centralized in is_ok_host() and enforced by OAuthProvider validators; always pipe new endpoints through these helpers and avoid bypassing the checks.
- Provider objects gate PKCE/nonce/id-token policies and token_type enforcement; align new provider helpers with existing defaults in R/providers.R (e.g., allowed_algs, allowed_token_types).
## HTTP & External Providers
- Every outbound call should wrap httr2::request() with add_req_defaults() for timeout/UA and req_with_retry() for transient handling; tune via options(shinyOAuth.timeout, shinyOAuth.retry_*).
- oauth_provider_oidc_discover() intersects discovery metadata with caller allowed_algs and infers token_auth_style; surface configuration failures with err_config()/err_http() to retain trace ids.
- Built-in providers (oauth_provider_github/google/microsoft/...) illustrate extra_token_headers, JWKS pinning, and fingerprinting; mirror their structure when adding providers so tests can stub with with_mocked_bindings().
## Shiny Integration
- Module cookies bind browser sessions using Web Crypto; tests and headless contexts can skip the requirement with options(shinyOAuth.skip_browser_token = TRUE) or by stubbing values via helper functions.
- Async flows require promises, future, and later; configure a plan (e.g., future::plan(multisession)) when enabling async=TRUE or tests will degrade to synchronous warnings.
- Tab title cleanup, cookie scope, and proactive refresh are all configurable arguments to oauth_module_server(); document new parameters with roxygen comments and guard them with stopifnot validations.
## Auditing & Diagnostics
- audit_event()/emit_trace_event() in R/errors.R send redacted telemetry to options(shinyOAuth.trace_hook) and options(shinyOAuth.audit_hook); preserve hashed identifiers via string_digest() when logging new fields.
- All error paths should raise via err_abort wrappers (err_token(), err_invalid_state(), err_userinfo(), etc.) so trace ids and structured context propagate to Shiny logs and audit hooks.
- Options like shinyOAuth.print_errors, shinyOAuth.print_traceback, and shinyOAuth.disable_watchdog_warning let operators tune verbosity; respect these flags instead of printing directly.
## Error Handling
- Throw failures with the typed helpers in R/errors.R (err_abort() plus err_token()/err_invalid_state()/err_http(), etc.); they wrap rlang::abort with package-specific classes and inject trace ids, so avoid base stop().
- For recoverable notices use rlang::warn()/inform() with cli-style bullet vectors and frequency guards (see warn_about_missing_js_dependency() and client_state_store_max_age()) instead of message()/warning(); surface structured context via context = list().
- Prefer adding new err_* or warn_* helpers next to existing ones so tests can assert on condition classes and message formats.
- Default to rlang/cli idioms for developer messaging: use cli::cli_warn()/cli_inform() or rlang::warn()/inform() with cli bullets, and avoid cat()/print()/message() unless tests explicitly stub those paths.
## Testing Workflow
- Run tests with mcp_r-mcp-server_run_testthat(mode = "all") when available or Rscript -e "testthat::test_local()" from the repo root.
- testthat suites under tests/testthat/ intensively mock network calls (with_mocked_bindings) and spin up webfakes servers; keep new HTTP helpers injectable and return httr2 responses so mocks remain simple.
- Async module tests reset future::plan(future::sequential) and poll later::run_now(); use the existing helpers (make_test_client(), valid_browser_token()) instead of reimplementing fixtures.
- When adding state-store logic, ensure cache backends expose get/set/remove/missing signatures so duck-typing checks in OAuthClient/OAuthProvider validators keep passing.
## Documentation & Examples
- Roxygen comments in R/ generate man/ via Rscript -e "devtools::document()"; never hand-edit .Rd files.
- Example Shiny integrations live in inst/examples/ and long-form guidance in vignettes/*.Rmd; update these alongside API changes so pkgdown docs (docs/) stay accurate.
- .onLoad() already registers S7 methods (R/zzz.R); when adding generics ensure S7::methods_register() is triggered and namespace imports remain consistent.
## Backwards compatibility
- I am working towards a first release. There is no previous release to maintain backwards compatibility with.
Do not code for backwards compatibility unless instructed specifically instructed to do so. Breaking changes
are acceptable at this stage of the project; do not leave leftover compatibility shims. If you ever
think you need to add backwards compatibility code, please discuss with me first.
## Global options
- Do not add new global options unless specifially requested by me. If you do for some reason
think that a new global option is needed, please discuss with me first.
- Should a global option ever be added, note that all must be documented in the 'usage' vignette.