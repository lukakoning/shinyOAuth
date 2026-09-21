transport_target_client <- function(base, binding = list(), mtls = FALSE) {
  provider <- oauth_provider(
    "bound-targets",
    paste0(base, "/authorize"),
    paste0(base, "/token"),
    use_nonce = FALSE,
    token_auth_style = "public",
    token_target_mode = "rfc8707",
    mtls_client_certificate_bound_access_tokens = mtls
  )
  do.call(
    oauth_client,
    c(
      list(
        provider = provider,
        client_id = "app",
        client_secret = "",
        redirect_uri = "https://app.example/callback",
        scopes = c("primary.read", "secondary.read"),
        token_targets = list(
          primary = list(
            resource = "urn:primary",
            scopes = "primary.read",
            resource_ids = "primary"
          ),
          secondary = list(
            resource = "urn:secondary",
            scopes = "secondary.read",
            resource_ids = "secondary"
          )
        ),
        default_token_target = "primary",
        resource_bases = c(
          primary = paste0(base, "/api/primary"),
          secondary = paste0(base, "/api/secondary")
        )
      ),
      binding
    )
  )
}

test_that("target acquisition and resource HTTP carry verifiable DPoP proofs", {
  skip_if_not_installed("webfakes")
  key <- openssl::rsa_keygen()
  jkt <- compute_jwk_thumbprint(dpop_public_jwk(key))
  app <- webfakes::new_app()
  app[["locals"]][["jkt"]] <- jkt
  app[["locals"]][["requests"]] <- list()
  app[["use"]](webfakes::mw_urlencoded())
  app[["post"]]("/token", function(req, res) {
    body <- lapply(req[["form"]], function(value) {
      paste(unlist(value), collapse = " ")
    })
    requests <- req[["app"]][["locals"]][["requests"]]
    requests[[length(requests) + 1L]] <- list(
      body = body,
      proof = req[["get_header"]]("dpop")
    )
    req[["app"]][["locals"]][["requests"]] <- requests
    if (length(requests) == 1L) {
      res[["set_status"]](400L)
      res[["set_header"]]("DPoP-Nonce", "target-token-nonce")
      return(res[["send_json"]](
        list(error = "use_dpop_nonce"),
        auto_unbox = TRUE
      ))
    }
    target <- sub("urn:", "", body[["resource"]], fixed = TRUE)
    res[["send_json"]](
      list(
        access_token = paste0(target, "-at"),
        refresh_token = paste0(target, "-rt"),
        token_type = "DPoP",
        expires_in = 3600,
        scope = body[["scope"]],
        cnf = list(jkt = req[["app"]][["locals"]][["jkt"]])
      ),
      auto_unbox = TRUE
    )
  })
  app[["get"]]("/api/:target/records", function(req, res) {
    res[["send_json"]](
      list(
        authorization = req[["get_header"]]("authorization"),
        proof = req[["get_header"]]("dpop"),
        token_requests = req[["app"]][["locals"]][["requests"]]
      ),
      auto_unbox = TRUE
    )
  })
  server <- webfakes::local_app_process(app)
  base <- sub("/$", "", server[["url"]]())
  client <- transport_target_client(
    base,
    list(dpop_private_key = key, dpop_require_observed_cnf = TRUE)
  )
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  token <- handle_callback(
    client,
    code = "code",
    state = parse_query_param(url, "state"),
    browser_token = browser
  )
  expect_identical(token@cnf[["jkt"]], jkt)
  verify <- function(proof, method, url, access = NULL) {
    parts <- strsplit(proof, ".", fixed = TRUE)[[1L]]
    expect_true(openssl::signature_verify(
      charToRaw(paste(parts[1:2], collapse = ".")),
      base64url_decode_raw(parts[[3L]]),
      hash = openssl::sha256,
      pubkey = key[["pubkey"]]
    ))
    header <- jsonlite::fromJSON(base64url_decode(parts[[1L]]))
    payload <- parse_jwt_payload(proof)
    expect_identical(compute_jwk_thumbprint(header[["jwk"]]), jkt)
    expect_identical(payload[["htm"]], method)
    expect_identical(payload[["htu"]], url)
    if (!is.null(access)) {
      expect_identical(
        payload[["ath"]],
        base64url_encode(openssl::sha256(charToRaw(access)))
      )
    }
    payload
  }
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(token, NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      response <- current[["request"]](
        "secondary",
        "records",
        target = "secondary",
        refresh = TRUE
      )
      observed <- httr2::resp_body_json(response)
      expect_identical(observed[["authorization"]], "DPoP secondary-at")
      verify(
        observed[["proof"]],
        "GET",
        paste0(base, "/api/secondary/records"),
        "secondary-at"
      )
      requests <- observed[["token_requests"]]
      expect_length(requests, 3L)
      claims <- lapply(requests, function(request) {
        verify(request[["proof"]], "POST", paste0(base, "/token"))
      })
      expect_length(unique(vapply(claims, `[[`, "", "jti")), 3L)
      expect_identical(claims[[2L]][["nonce"]], "target-token-nonce")
      expect_identical(claims[[3L]][["nonce"]], "target-token-nonce")
      expect_identical(requests[[3L]][["body"]][["resource"]], "urn:secondary")
      expect_identical(
        requests[[3L]][["body"]][["refresh_token"]],
        "primary-rt"
      )
      primary_response <- current[["request"]]("primary", "records")
      primary_observed <- httr2::resp_body_json(primary_response)
      expect_identical(primary_observed[["authorization"]], "DPoP primary-at")
      verify(
        primary_observed[["proof"]],
        "GET",
        paste0(base, "/api/primary/records"),
        "primary-at"
      )
      error <- tryCatch(
        current[["access_token"]](target = "secondary"),
        error = identity
      )
      expect_identical(
        error[["context"]][["reason"]],
        "unsupported_token_binding"
      )
    }
  )
})

test_that("target acquisition and resource TLS require the bound client certificate", {
  python <- Sys.which("python")
  if (!nzchar(python)) {
    python <- Sys.which("python3")
  }
  skip_if(!nzchar(python), "Python is required for the loopback TLS fixture")
  server <- processx::process[["new"]](
    python,
    mtls_pem_fixture("target-server.py"),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server[["kill"]]())
  port <- wait_for_mtls_server_port(server)
  base <- paste0("https://127.0.0.1:", port)
  client <- transport_target_client(
    base,
    mtls = TRUE,
    binding = list(
      mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
      mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
      mtls_client_ca_file = mtls_pem_fixture("server-cert.pem"),
      mtls_certificate_bound_access_tokens = TRUE,
      mtls_require_observed_cnf = TRUE
    )
  )
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  token <- handle_callback(
    client,
    code = "code",
    state = parse_query_param(url, "state"),
    browser_token = browser
  )
  thumbprint <- token@cnf[["x5t#S256"]]
  expect_type(thumbprint, "character")
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(token, NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      response <- current[["request"]](
        "secondary",
        "records",
        target = "secondary",
        refresh = TRUE
      )
      body <- httr2::resp_body_json(response)
      expect_identical(body[["authorization"]], "Bearer secondary-at")
      expect_identical(body[["certificate"]], thumbprint)
      expect_identical(
        body[["token_certificates"]],
        list(thumbprint, thumbprint)
      )
      expect_identical(
        body[["resources"]],
        list("urn:primary", "urn:secondary")
      )
      expect_identical(
        values[["targets"]][["tokens"]][["secondary"]]@cnf[["x5t#S256"]],
        thumbprint
      )
      error <- tryCatch(
        current[["access_token"]](target = "secondary"),
        error = identity
      )
      expect_identical(
        error[["context"]][["reason"]],
        "unsupported_token_binding"
      )
    }
  )
  # The same resource cannot be reached without presenting a certificate.
  request <- httr2::req_options(
    httr2::request(paste0(base, "/api/secondary/records")),
    cainfo = client@mtls_client_ca_file
  )
  expect_error(
    httr2::req_perform(httr2::req_timeout(request, 5)),
    class = "httr2_failure"
  )
})
