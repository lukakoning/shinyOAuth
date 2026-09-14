testthat::test_that("smart_discover identifies the pinned Launcher's missing algorithm metadata", {
  urls <- smart_sandbox_urls()
  metadata <- smart_sandbox_json(paste0(
    urls$fhir,
    "/.well-known/smart-configuration"
  ))
  testthat::expect_true(
    "client-confidential-asymmetric" %in% metadata$capabilities
  )
  testthat::expect_true(
    "private_key_jwt" %in% metadata$token_endpoint_auth_methods_supported
  )
  testthat::expect_null(
    metadata$token_endpoint_auth_signing_alg_values_supported
  )
  # This is evidence of correct rejection, not a passing interoperability gate.
  # Upstream revision and running image both omit the required algorithm list.
  # Keep the response unchanged; do not strip the capability or inject RS384.
  for (base in c(urls$fhir, paste0(urls$fhir, "/"))) {
    testthat::expect_error(
      shinyOAuth::smart_discover(base, allow_http_loopback = TRUE),
      "token_endpoint_auth_signing_alg_values_supported",
      class = "shinyOAuth_parse_error"
    )
  }
  testthat::expect_error(
    shinyOAuth::smart_discover(urls$fhir),
    "HTTPS"
  )
  testthat::expect_error(
    shinyOAuth::smart_discover(
      urls$fhir,
      endpoint_hosts = "127.0.0.1",
      allow_http_loopback = TRUE
    ),
    "endpoint_hosts"
  )
})

testthat::test_that("SMART discovery validates real HTTP fixtures before accepting metadata", {
  minimal <- list(
    token_endpoint = "https://approved.example/token",
    authorization_endpoint = "https://approved.example/authorize",
    capabilities = list("launch-standalone", "client-public"),
    grant_types_supported = list("authorization_code"),
    code_challenge_methods_supported = list("S256")
  )
  documents <- list(valid = minimal)
  documents$missing <- minimal
  documents$missing$grant_types_supported <- NULL
  documents$plain <- minimal
  documents$plain$code_challenge_methods_supported <- list("S256", "plain")
  documents$sso <- minimal
  documents$sso$capabilities <- c(minimal$capabilities, "sso-openid-connect")
  documents$relative <- minimal
  documents$relative$token_endpoint <- "/token"
  documents$offhost <- minimal
  documents$offhost$token_endpoint <- "https://unapproved.example/token"
  documents <- lapply(documents, jsonlite::toJSON, auto_unbox = TRUE)
  documents$duplicate <- '{"token_endpoint":"one","token_endpoint":"two"}'
  documents$oversized <- paste(rep("x", 2048L), collapse = "")
  app <- webfakes::new_app()
  app$locals$documents <- documents
  app$locals$redirect_hits <- 0L
  app$locals$credential_headers <- FALSE
  app$get(
    "/:scenario/fhir/R4/.well-known/smart-configuration",
    function(req, res) {
      req$app$locals$credential_headers <- req$app$locals$credential_headers ||
        any(
          tolower(names(req$headers)) %in% c("authorization", "cookie", "dpop")
        )
      scenario <- req$params$scenario
      if (scenario == "redirect") {
        return(res$set_status(302L)$set_header(
          "Location",
          "/redirect-target"
        )$send(""))
      }
      res$set_type("application/json")$send(req$app$locals$documents[[
        scenario
      ]])
    }
  )
  app$get("/redirect-target", function(req, res) {
    req$app$locals$redirect_hits <- req$app$locals$redirect_hits + 1L
    res$send("Unexpected follow")
  })
  app$get("/metrics", function(req, res) {
    res$send_json(
      list(
        redirect_hits = req$app$locals$redirect_hits,
        credential_headers = req$app$locals$credential_headers
      ),
      auto_unbox = TRUE
    )
  })
  server <- webfakes::new_app_process(
    app,
    opts = webfakes::server_opts(
      remote = TRUE,
      interfaces = "127.0.0.1",
      port = 0L,
      num_threads = 2L,
      access_log_file = FALSE,
      error_log_file = FALSE
    )
  )
  withr::defer(server$stop())
  discover <- function(scenario) {
    shinyOAuth::smart_discover(
      paste0(server$url(), scenario, "/fhir/R4"),
      endpoint_hosts = "approved.example",
      allow_http_loopback = TRUE
    )
  }
  testthat::expect_identical(discover("valid")$metadata, minimal)
  for (scenario in c("missing", "plain", "sso", "duplicate")) {
    testthat::expect_error(discover(scenario), class = "shinyOAuth_parse_error")
  }
  for (scenario in c("relative", "offhost")) {
    testthat::expect_error(
      discover(scenario),
      class = "shinyOAuth_config_error"
    )
  }
  # A global generic softener cannot allow SMART discovery to follow a redirect.
  withr::local_options(
    shinyOAuth.allow_redirect = TRUE,
    shinyOAuth.max_body_bytes = 1024L,
    shinyOAuth.retry_max_tries = 1L
  )
  testthat::expect_error(discover("redirect"), class = "shinyOAuth_http_error")
  testthat::expect_error(
    discover("oversized"),
    class = "shinyOAuth_parse_error"
  )
  metrics <- smart_sandbox_json(paste0(server$url(), "metrics"))
  testthat::expect_identical(metrics$redirect_hits, 0L)
  testthat::expect_false(metrics$credential_headers)
})
