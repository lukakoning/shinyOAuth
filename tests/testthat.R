# This file is part of the standard devtools workflow.
# See `?devtools::test()` for more information.

# The mTLS request fixtures use separate PEM certificate/key files. Select the
# backend before loading curl through Shiny/httr2. test-mtls-backend separately
# checks the fresh Windows default. Keep this out of the package-check process
# so curl's backend startup diagnostic does not create a check NOTE.
if (
  .Platform[["OS.type"]] == "windows" && !nzchar(Sys.getenv("CURL_SSL_BACKEND"))
) {
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
}

library(testthat)
library(shiny)
library(shinyOAuth)
helper_otel <- file.path("testthat", "helper-otel.R")
if (file.exists(helper_otel)) {
  source(helper_otel, local = TRUE)
}

# CRAN runs a representative regression suite with small fixtures. The full suite
# covers larger adversarial matrices, subprocesses, browser flows and telemetry.
# Keep the selection here so devtools::test()/testthat::test_local() continue to
# discover every test file. CI and tests/run-local.R explicitly set NOT_CRAN=true.
cran_tests <- c(
  # Public constructors, provider defaults and input validation.
  "basic",
  "defaults-and-validation",
  "provider-helpers",
  "public-argument-aliases",
  "coerce-expires-in",
  "scope-validation",
  "utils-url-and-scopes",
  # State encryption, PKCE, callback binding and single-use state.
  "base64url-helpers",
  "constant-time-compare",
  "key-normalization",
  "pkce-s256-encoding",
  "state-envelope-roundtrip",
  "state-payload-tamper",
  "state-store-atomic-take",
  "state-record-consistency",
  "login-callback",
  "callback-fixed-query",
  "callback-route-validation",
  "cookie-tossing",
  # Token responses, refresh, scopes and safe resource requests.
  "token-type-and-scopes",
  "token-type-policy",
  "token-validation-flag",
  "missing-token-type",
  "token-extra-fields",
  "missing-expires-in",
  "refresh-token",
  "refresh-single-flight",
  "client-bearer-req-url-validation",
  "resource-binding",
  "userinfo-sub-claim",
  # Successful signature verification plus malformed tokens and claim checks.
  "jwt-positive-algs",
  "jwt-malformed-and-claims",
  "jwt-at-hash",
  "id-token-audience",
  "oidc-standard-claim-types",
  "jwk-selection",
  "jwt-jwe-roundtrip",
  # Retained credentials, SMART permissions and Shiny module wiring.
  "connection-credentials",
  "connection-store",
  "connection-strict-callbacks",
  "smart-client",
  "smart-scopes",
  "smart-exact-members",
  "smart-property-policy",
  "module-test-exports",
  # Redaction, diagnostics and telemetry unit tests.
  "print-redaction",
  "errors-and-audit",
  "otel-unit"
)

if (identical(Sys.getenv("NOT_CRAN"), "true")) {
  test_check("shinyOAuth")
} else {
  # Fail if a selected file is removed or renamed instead of silently reducing
  # coverage (or letting a stale filter match no files).
  stopifnot(
    !anyDuplicated(cran_tests),
    all(file.exists(file.path("testthat", paste0("test-", cran_tests, ".R"))))
  )
  message("Running CRAN regression suite (", length(cran_tests), " test files).")
  cran_filter <- paste0("^(", paste(cran_tests, collapse = "|"), ")$")
  test_check("shinyOAuth", filter = cran_filter)
}
