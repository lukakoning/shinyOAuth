# These plumbing checks use a package-owned metadata server, not OIDF assertions.
run_openid_fixture_checks <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (length(args)) {
    stop("Usage: Rscript integration/openid/run-fixture-checks.R")
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  source("integration/openid/helper-environment.R", local = TRUE)
  source("integration/openid/helper-app.R", local = TRUE)
  openid_require(c(
    "shiny",
    "callr",
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "chromote",
    "httpuv",
    "webfakes"
  ))
  output <- openid_output(".", "fixture")
  report <- list(status = "failed", independent_conformance = "not_attempted")
  on.exit(
    jsonlite::write_json(
      report,
      file.path(output, "evidence.json"),
      auto_unbox = TRUE,
      pretty = TRUE
    ),
    add = TRUE
  )
  library <- openid_install(".", output)
  stack <- openid_start(".", output)
  metadata <- webfakes::new_app()
  metadata_handler <- function(req, res) {
    issuer <- paste0("https://", req[["get_header"]]("Host"))
    res[["send_json"]](
      list(
        issuer = issuer,
        authorization_endpoint = paste0(issuer, "/authorize"),
        token_endpoint = paste0(issuer, "/token"),
        jwks_uri = paste0(issuer, "/jwks"),
        response_types_supported = list("code"),
        subject_types_supported = list("public"),
        id_token_signing_alg_values_supported = list("RS256"),
        token_endpoint_auth_methods_supported = list("client_secret_basic"),
        code_challenge_methods_supported = list("S256")
      ),
      auto_unbox = TRUE
    )
  }
  metadata[["get"]]("/.well-known/openid-configuration", metadata_handler)
  metadata[["get"]]("/bad/.well-known/openid-configuration", metadata_handler)
  metadata[["get"]]("/authorize", function(req, res) {
    res[["send"]]("Fixture authorization request received")
  })
  provider <- webfakes::new_app_process(metadata)
  withr::defer(provider[["stop"]]())
  provider_port <- as.integer(httr2::url_parse(provider[["url"]]())[["port"]])
  provider_tls <- openid_app_transport(".", stack, provider_port)
  transport <- openid_app_transport(".", stack, httpuv::randomPort())
  config <- list(
    issuer = provider_tls[["origin"]],
    client_id = "fixture-client",
    client_secret = "fixture-secret-do-not-export",
    response_mode = "query"
  )
  app <- openid_app_start(".", stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  snapshot <- openid_wait(
    function() openid_app_snapshot(tab, app[["config"]][["run_id"]]),
    "OpenID fixture snapshot",
    20
  )
  stopifnot(
    isTRUE(snapshot[["ready"]]),
    !isTRUE(snapshot[["authenticated"]]),
    !isTRUE(snapshot[["has_token"]]),
    identical(
      snapshot[["package_version"]],
      read.dcf("DESCRIPTION")[[1L, "Version"]]
    )
  )
  stopifnot(
    !grepl(
      config[["client_secret"]],
      openid_browser_value(tab, "document.documentElement.outerHTML"),
      fixed = TRUE
    )
  )
  openid_browser_value(tab, "document.querySelector('#login').click()")
  request <- openid_wait(
    function() {
      openid_browser_value(
        tab,
        "(() => { if (location.pathname !== '/authorize') return null; const p = new URL(location.href).searchParams; return {code:p.get('response_type') === 'code', pkce:p.get('code_challenge_method') === 'S256', nonce:!!p.get('nonce'), state:!!p.get('state'), openid:p.get('scope').split(' ').includes('openid')}; })()"
      )
    },
    "normal browser authorization request",
    20
  )
  stopifnot(all(unlist(request)))
  report[["package_version"]] <- snapshot[["package_version"]]
  report[["app_ready"]] <- TRUE
  report[["credentials_absent_from_dom"]] <- TRUE
  report[["authorization_request"]] <- request
  app[["process"]][["kill"]]()
  app[["process"]][["wait"]](10000)
  bad_transport <- openid_app_transport(".", stack, httpuv::randomPort())
  bad_config <- config
  bad_config[["issuer"]] <- paste0(provider_tls[["origin"]], "/bad")
  bad_config[["run_id"]] <- paste(
    format(openssl::rand_bytes(12)),
    collapse = ""
  )
  failure <- tryCatch(
    openid_app_start(".", stack, bad_transport, bad_config, library),
    error = identity
  )
  stopifnot(
    inherits(failure, "error"),
    grepl("fixture app exited", conditionMessage(failure), fixed = TRUE)
  )
  diagnostic <- readLines(
    file.path(output, paste0("app-", bad_config[["run_id"]], ".stderr")),
    warn = FALSE
  )
  stopifnot(any(grepl(
    "OIDC discovery issuer mismatch",
    diagnostic,
    fixed = TRUE
  )))
  logs <- list.files(
    output,
    pattern = "^app-.*[.](log|stderr)$",
    full.names = TRUE
  )
  stopifnot(
    !any(vapply(
      logs,
      function(path) {
        any(grepl(
          config[["client_secret"]],
          readLines(path, warn = FALSE),
          fixed = TRUE
        ))
      },
      logical(1)
    ))
  )
  report[["invalid_setup_rejected"]] <- TRUE
  report[["credentials_absent_from_logs"]] <- TRUE
  openid_stop(stack)
  report[["status"]] <- "passed"
  cat(
    "OpenID fixture checks passed using local synthetic metadata; no conformance claim.\n"
  )
}
run_openid_fixture_checks()
