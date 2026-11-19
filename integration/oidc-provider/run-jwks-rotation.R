run_jwks_rotation <- function(args = commandArgs(TRUE)) {
  if (length(args)) {
    stop("Usage: Rscript integration/oidc-provider/run-jwks-rotation.R")
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
  withr::local_options(warn = 2)
  for (name in c("environment", "suite", "source", "app")) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  for (name in c("environment", "driver", "jwks-rotation")) {
    source(
      paste0("integration/oidc-provider/helper-", name, ".R"),
      local = TRUE
    )
  }
  openid_require(c(
    "testthat",
    "processx",
    "jsonlite",
    "httr2",
    "openssl",
    "jose",
    "shiny",
    "xml2",
    "httpuv",
    "withr",
    "cachem"
  ))
  output <- interop_output(profile = "jwks-rotation")
  checkout <- openid_source_identity(".")
  report <- list(
    schema_version = 1L,
    status = "failed",
    gate_passed = FALSE,
    scope = "native_oidc_provider_warm_jwks_rotation_sync",
    coverage_complete = FALSE,
    checkout_revision = checkout[["revision"]],
    checkout_dirty = checkout[["dirty"]],
    checkout_source = checkout,
    package_version = read.dcf("DESCRIPTION")[[1L, "Version"]],
    cleanup_verified = FALSE,
    source_verified = FALSE
  )
  on.exit(
    jsonlite::write_json(
      report,
      file.path(output, "evidence.json"),
      auto_unbox = TRUE,
      pretty = TRUE,
      null = "null"
    ),
    add = TRUE
  )
  library <- openid_install(".", output, checkout)
  report[["installation"]] <- openid_use_installation(library, checkout)
  context <- report
  regression <- testthat::test_file(
    "integration/oidc-provider/test-jwks-rotation.R",
    reporter = "summary",
    env = new.env(parent = environment())
  )
  regression <- rotation_write_regressions(
    regression,
    file.path(output, "regression-results.csv")
  )
  rotation_require(
    nrow(regression) > 0L &&
      all(regression[["failed"]] == 0L) &&
      !any(regression[["error"]]) &&
      !any(regression[["skipped"]]) &&
      all(regression[["warning"]] == 0L),
    "Warm-cache evidence regression checks failed"
  )
  report[["regression_assertions"]] <- sum(regression[["nb"]])
  report[["installation_after_regression"]] <- openid_use_installation(
    library,
    checkout,
    report[["installation"]]
  )
  openid_assert_source(".", checkout)
  environment <- interop_prepare(".", output)
  report[["provider_lock"]] <- environment[["lock"]]
  report[["image_id"]] <- environment[["image"]]
  report[["provider_source_hashes"]] <- environment[["source_hashes"]]
  config <- list(
    run_id = paste(format(openssl::rand_bytes(16)), collapse = ""),
    client_id = "local-warm-cache",
    client_auth_type = "none",
    redirect_uri = paste0("https://localhost:", httpuv::randomPort(), "/"),
    jwks_rotation = TRUE
  )
  stack <- interop_start(environment, config)
  # Headless testServer covers code/state/nonce/PKCE and signature handling.
  # It intentionally has no browser-cookie or worker-sharing claim.
  withr::local_envvar(c(CURL_CA_BUNDLE = stack[["ca"]], TESTTHAT = "true"))
  withr::local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.timeout = 10
  )
  metadata <- interop_discovery(stack)
  provider <- shinyOAuth::oauth_provider_oidc_discover(
    stack[["origin"]],
    token_auth_style = "public",
    id_token_allowed_algs = "RS256"
  )
  client <- shinyOAuth::oauth_client(
    provider,
    config[["client_id"]],
    redirect_uri = config[["redirect_uri"]],
    scopes = c("openid", "profile", "email"),
    state_transport = "reference"
  )
  cache <- client@provider@jwks_cache
  backend <- cache[["info"]]()
  rotation_require(
    inherits(cache, "cache_mem") && identical(backend[["max_age"]], 3600),
    "Selection requires the unchanged default one-hour cache backend"
  )
  key <- shinyOAuth:::jwks_cache_key(
    provider@issuer,
    pins = provider@jwks_pins,
    pin_mode = provider@jwks_pin_mode,
    issuer_match = provider@issuer_match,
    jwks_host_issuer_match = provider@jwks_host_issuer_match,
    jwks_host_allow_only = provider@jwks_host_allow_only,
    jwks_uri_override = provider@jwks_uri,
    tls_minimum = shinyOAuth:::client_tls_minimum(client)
  )
  rotation_require(
    is.null(rotation_snapshot(cache, key)),
    "JWKS cache did not start empty"
  )
  fetch <- shinyOAuth:::fetch_jwks
  perform <- shinyOAuth:::req_with_retry
  calls <- list()
  requests <- list()
  testthat::local_mocked_bindings(
    fetch_jwks = function(issuer, jwks_cache, force_refresh = FALSE, ...) {
      rotation_require(
        identical(issuer, stack[["origin"]]) && identical(jwks_cache, cache),
        "JWKS lookup changed issuer or cache identity"
      )
      calls[[length(calls) + 1L]] <<- list(
        force_refresh = force_refresh,
        entry = rotation_snapshot(cache, key)
      )
      fetch(issuer, jwks_cache, force_refresh = force_refresh, ...)
    },
    req_with_retry = function(req, ...) {
      is_jwks <- identical(req[["url"]], metadata[["jwks_uri"]])
      entry <- if (is_jwks) rotation_snapshot(cache, key) else NULL
      response <- perform(req, ...)
      if (is_jwks) {
        requests[[length(requests) + 1L]] <<- list(
          url = req[["url"]],
          entry = entry,
          status = httr2::resp_status(response),
          cache_control = httr2::resp_header(response, "cache-control"),
          expires = httr2::resp_header(response, "expires"),
          kids = unname(lapply(
            httr2::resp_body_json(response)[["keys"]],
            `[[`,
            "kid"
          ))
        )
      }
      response
    },
    .package = "shinyOAuth"
  )
  initial_provider <- interop_request(
    stack,
    "/fixture/evidence",
    evidence = TRUE
  )
  first <- rotation_login(client, stack)
  populated <- rotation_snapshot(cache, key)
  second <- rotation_login(client, stack)
  warm <- rotation_snapshot(cache, key)
  before <- interop_request(stack, "/fixture/evidence", evidence = TRUE)
  rotation_require(
    identical(initial_provider[["jwks_rotation"]], before[["jwks_rotation"]]),
    "Provider restarted before the warm-cache control"
  )
  pre_count <- length(Filter(
    function(event) identical(event[["type"]], "jwks"),
    before[["events"]]
  ))
  throttle_before <- cache[["get"]](paste0(key, "xfr"), missing = NULL)
  rotation_restart(stack)
  restarted <- interop_request(stack, "/fixture/evidence", evidence = TRUE)
  post_restart_count <- length(Filter(
    function(event) identical(event[["type"]], "jwks"),
    restarted[["events"]]
  ))
  retained <- rotation_snapshot(cache, key)
  third <- rotation_login(client, stack)
  refreshed <- rotation_snapshot(cache, key)
  throttle_after <- cache[["get"]](paste0(key, "xfr"), missing = NULL)
  # Snapshot the four legitimate lookups before direct cryptographic negatives.
  legitimate_calls <- calls
  rogues <- list(
    rotation_rogue(
      client,
      third[["id_token"]],
      first[["proof"]][["kid"]],
      "No JWKS key matches kid"
    ),
    rotation_rogue(
      client,
      third[["id_token"]],
      third[["proof"]][["kid"]],
      "signature"
    )
  )
  after <- interop_request(stack, "/fixture/evidence", evidence = TRUE)
  proof <- list(
    scope = report[["scope"]],
    run_id = stack[["run_id"]],
    issuer = stack[["origin"]],
    jwks_uri = metadata[["jwks_uri"]],
    backend_max_age = backend[["max_age"]],
    origin_freshness = "absent_default_backend_policy",
    same_cache_identity = identical(client@provider@jwks_cache, cache),
    same_issuer = identical(client@provider@issuer, stack[["origin"]]),
    no_cache_configuration_override = identical(cache[["info"]](), backend),
    browser_cookie_check_bypassed = TRUE,
    no_browser_or_worker_credit = TRUE,
    logins = list(first[["proof"]], second[["proof"]], third[["proof"]]),
    provider_before = before,
    provider_after_restart = restarted,
    provider_after = after,
    populated = populated,
    warm = warm,
    before_rotated_login = retained,
    refreshed = refreshed,
    fetch_calls = legitimate_calls,
    requests = requests,
    pre_rotation_requests = pre_count,
    post_restart_requests = post_restart_count,
    post_rogue_requests = length(Filter(
      function(event) identical(event[["type"]], "jwks"),
      after[["events"]]
    )),
    throttle_before = throttle_before,
    throttle_after = throttle_after,
    rogues = rogues
  )
  report[["proof"]] <- proof
  rotation_check(proof)
  serialized <- jsonlite::fromJSON(
    as.character(jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null")),
    simplifyVector = FALSE
  )
  rotation_check(serialized)
  interop_stop(stack)
  report[["cleanup_verified"]] <- isTRUE(stack[["lifecycle"]][["stopped"]])
  report[["checkout_source_after"]] <- openid_assert_source(".", checkout)
  report[["installation_after"]] <- openid_use_installation(
    library,
    checkout,
    report[["installation"]]
  )
  report[["source_verified"]] <- TRUE
  openid_check_source(report, context)
  rotation_require(
    report[["cleanup_verified"]],
    "Owned provider cleanup was not verified"
  )
  report[["gate_passed"]] <- TRUE
  report[["status"]] <- "passed"
  cat(
    "Native oidc-provider warm JWKS rotation passed: 3 code/S256 logins, ",
    "1 warm hit, 1 forced refresh, 2 rogue signatures rejected.\n",
    sep = ""
  )
  cat("Evidence:", file.path(output, "evidence.json"), "\n")
  invisible(report)
}

run_jwks_rotation()
