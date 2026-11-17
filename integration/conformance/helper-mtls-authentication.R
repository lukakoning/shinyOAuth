mtls_auth_request <- function(
  fixture,
  endpoint,
  form = NULL,
  certificate = "client",
  forwarded = NULL,
  headers = list(),
  query = list()
) {
  root <- fixture[["root"]]
  request <- httr2::request(paste0(fixture[["issuer"]], endpoint)) |>
    httr2::req_options(
      cainfo = file.path(root, "ca.pem"),
      followlocation = FALSE
    ) |>
    httr2::req_error(is_error = function(...) FALSE) |>
    httr2::req_timeout(5)
  if (!is.null(certificate)) {
    request <- request |>
      httr2::req_options(
        sslcert = file.path(root, paste0(certificate, ".pem")),
        sslkey = file.path(root, paste0(certificate, "-key.pem"))
      )
  }
  if (!is.null(forwarded)) {
    headers[["X-Ssl-Cert"]] <- paste(
      readLines(file.path(root, paste0(forwarded, ".pem"))),
      collapse = "\t"
    )
  }
  request <- do.call(httr2::req_headers, c(list(request), headers))
  request <- do.call(httr2::req_url_query, c(list(request), query))
  if (!is.null(form)) {
    request <- do.call(httr2::req_body_form, c(list(request), form))
  }
  httr2::req_perform(request)
}

mtls_auth_denials <- function(fixture, endpoint, form) {
  cases <- list(
    list(certificate = "unregistered", reason = "client_certificate_subject"),
    list(certificate = NULL, reason = "client_certificate_missing"),
    list(
      certificate = "unregistered",
      forwarded = "client",
      reason = "client_certificate_subject"
    ),
    list(
      certificate = NULL,
      forwarded = "client",
      reason = "client_certificate_missing"
    ),
    list(client_id = NULL, reason = "client_id"),
    list(client_id = "not-registered", reason = "client_id"),
    list(extra = list(client_secret = ""), reason = "single_client_auth"),
    list(extra = list(client_assertion = ""), reason = "single_client_auth"),
    list(
      extra = list(client_assertion_type = ""),
      reason = "single_client_auth"
    ),
    list(
      headers = list(Authorization = "Basic ZmFrZTpmYWtl"),
      reason = "single_client_auth"
    )
  )
  for (case in cases) {
    params <- form
    if ("client_id" %in% names(case)) {
      params[["client_id"]] <- case[["client_id"]]
    }
    params <- c(params, case[["extra"]])
    response <- mtls_auth_request(
      fixture,
      endpoint,
      params,
      certificate = if ("certificate" %in% names(case)) {
        case[["certificate"]]
      } else {
        "client"
      },
      forwarded = case[["forwarded"]],
      headers = case[["headers"]]
    )
    testthat::expect_identical(httr2::resp_status(response), 400L)
    testthat::expect_identical(
      httr2::resp_header(response, "cache-control"),
      "no-store"
    )
    testthat::expect_null(httr2::resp_header(response, "location"))
    testthat::expect_identical(
      httr2::resp_body_json(response),
      list(
        error = if (case[["reason"]] == "single_client_auth") {
          "invalid_request"
        } else {
          "invalid_client"
        },
        reason = case[["reason"]]
      )
    )
  }
  untrusted <- tryCatch(
    mtls_auth_request(fixture, endpoint, form, certificate = "rogue"),
    error = identity
  )
  testthat::expect_s3_class(untrusted, "httr2_failure")
  testthat::expect_match(
    conditionMessage(untrusted),
    "SSL|TLS|certificate",
    ignore.case = TRUE
  )
}

run_mtls_auth_denials <- function(alg) {
  fixture <- strict_as_fixture(alg, "tls_client_auth")
  client <- mtls_resource_client(
    fixture,
    alg,
    "client",
    FALSE,
    TRUE,
    auth_style = "tls_client_auth"
  )
  rogue <- openssl::read_cert(file.path(fixture[["root"]], "rogue.pem"))
  legitimate <- openssl::read_cert(file.path(fixture[["root"]], "client.pem"))
  testthat::expect_identical(
    as.list(rogue)[["subject"]],
    as.list(legitimate)[["subject"]]
  )
  testthat::expect_false(identical(
    as.list(rogue)[["issuer"]],
    as.list(legitimate)[["issuer"]]
  ))
  for (scope in c("mtls", "records")) {
    verifier <- strrep("v", 43)
    jar <- shinyOAuth:::build_authorization_request_object(
      client,
      list(
        client_id = "client",
        response_type = "code",
        redirect_uri = client@redirect_uri,
        scope = scope,
        state = "negative-control-state",
        code_challenge_method = "S256",
        code_challenge = shinyOAuth:::base64url_encode(openssl::sha256(charToRaw(
          verifier
        )))
      )
    )
    par_form <- list(client_id = "client", request = jar)
    mtls_auth_denials(fixture, "/par", par_form)
    # Failed authentication must leave the same signed request usable.
    pushed <- mtls_auth_request(fixture, "/par", par_form)
    testthat::expect_identical(httr2::resp_status(pushed), 201L)
    reference <- httr2::resp_body_json(pushed)[["request_uri"]]
    testthat::expect_true(is.character(reference) && nzchar(reference))
    authorization <- mtls_auth_request(
      fixture,
      "/authorize",
      certificate = NULL,
      query = list(client_id = "client", request_uri = reference)
    )
    testthat::expect_identical(httr2::resp_status(authorization), 302L)
    code <- httr2::url_parse(httr2::resp_header(authorization, "location"))[[
      "query"
    ]][["code"]]
    token_form <- list(
      client_id = "client",
      grant_type = "authorization_code",
      code = code,
      redirect_uri = client@redirect_uri,
      code_verifier = verifier
    )
    mtls_auth_denials(fixture, "/token", token_form)
    # A new eligible certificate can authenticate, but owns only its own token.
    response <- mtls_auth_request(
      fixture,
      "/token",
      token_form,
      certificate = "alternate"
    )
    testthat::expect_identical(httr2::resp_status(response), 200L)
    body <- httr2::resp_body_json(response)
    testthat::expect_false("refresh_token" %in% names(body))
    token <- shinyOAuth::OAuthToken(
      access_token = body[["access_token"]],
      cnf = body[["cnf"]]
    )
    resource <- mtls_resource_attack(fixture, token, "alternate")
    testthat::expect_identical(httr2::resp_status(resource), 200L)
    testthat::expect_identical(
      httr2::resp_body_json(resource),
      list(resource = "certificate-bound-content")
    )
    expect_mtls_resource_denied(mtls_resource_attack(
      fixture,
      token,
      "client",
      "alternate"
    ))
  }
  withr::local_envvar(
    R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
  )
  mirai::daemons(1L, rs = "--vanilla")
  withr::defer(mirai::daemons(0L))
  for (async in c(FALSE, TRUE)) {
    wrong <- mtls_resource_client(
      fixture,
      alg,
      "unregistered",
      FALSE,
      TRUE,
      auth_style = "tls_client_auth"
    )
    mtls_resource_login(
      wrong,
      async,
      tempfile("failed-exchange-", tmpdir = fixture[["root"]]),
      request_resource = FALSE,
      expected_failure = TRUE
    )
  }
  wrong_par <- mtls_resource_client(
    fixture,
    alg,
    "unregistered",
    TRUE,
    TRUE,
    auth_style = "tls_client_auth"
  )
  testthat::expect_error(
    shinyOAuth::prepare_call(wrong_par, browser_token = strrep("ab", 64)),
    class = "shinyOAuth_http_error"
  )
}
