testthat::test_that("independent AS enforces JAR and completes protected combinations", {
  python <- Sys.getenv("SHINYOAUTH_TEST_PYTHON", unset = Sys.which("python"))
  testthat::expect_true(nzchar(python))
  root <- tempfile("strict-as-")
  dir.create(root)
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  signing_key <- openssl::rsa_keygen()
  writeLines(
    openssl::write_pem(as.list(signing_key)$pubkey),
    file.path(root, "registered.pem")
  )
  server <- processx::process$new(
    python,
    c("strict_as.py", root),
    stdout = "|",
    stderr = "|"
  )
  on.exit(server$kill(), add = TRUE)
  deadline <- Sys.time() + 15
  ready <- character()
  while (!length(ready) && server$is_alive() && Sys.time() < deadline) {
    server$poll_io(100)
    ready <- server$read_output_lines()
  }
  if (!length(ready) || !startsWith(ready[[1]], "{")) {
    server$wait(1000)
    stop(paste(c(ready, server$read_all_error()), collapse = "\n"))
  }
  issuer <- jsonlite::fromJSON(ready[[1]])$issuer
  withr::local_envvar(CURL_CA_BUNDLE = file.path(root, "ca.pem"))
  withr::local_options(list(
    shinyOAuth.timeout = 5,
    shinyOAuth.otel_tracing_enabled = FALSE,
    shinyOAuth.otel_logging_enabled = FALSE
  ))
  provider <- shinyOAuth::oauth_provider(
    name = "strict-as",
    issuer = issuer,
    auth_url = paste0(issuer, "/authorize"),
    token_url = paste0(issuer, "/token"),
    jwks_uri = paste0(issuer, "/jwks"),
    token_auth_style = "public",
    use_nonce = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    signed_request_object_required = TRUE,
    request_parameter_supported = TRUE,
    request_object_signing_alg_values_supported = "RS256",
    allowed_token_types = c("Bearer", "DPoP")
  )
  client <- shinyOAuth::oauth_client(
    provider,
    client_id = "client",
    client_secret = "",
    redirect_uri = "https://app.example.com/callback",
    scopes = "openid",
    client_assertion_private_key = signing_key,
    request_object_mode = "request",
    request_object_signing_alg = "RS256"
  )
  browser <- strrep("ab", 64)
  get <- function(url) {
    httr2::request(url) |>
      httr2::req_options(
        cainfo = file.path(root, "ca.pem"),
        followlocation = FALSE
      ) |>
      httr2::req_error(is_error = function(resp) FALSE) |>
      httr2::req_perform()
  }
  query <- function(url) httr2::url_parse(url)$query
  # Required signing is an AS policy, independently enforced before code issue.
  unsigned <- get(paste0(
    issuer,
    "/authorize?",
    httr2::url_query_build(list(
      client_id = "client",
      response_type = "code",
      redirect_uri = client@redirect_uri
    ))
  ))
  testthat::expect_identical(httr2::resp_status(unsigned), 400L)
  testthat::expect_identical(
    httr2::resp_body_json(unsigned)$reason,
    "signed_request_required"
  )
  url <- shinyOAuth::prepare_call(client, browser_token = browser)
  original <- shinyOAuth:::parse_jwt_payload(query(url)$request)
  for (field in c("iss", "aud", "exp")) {
    claims <- original
    claims[[field]] <- switch(
      field,
      iss = "wrong",
      aud = "https://wrong.example.com",
      exp = as.numeric(Sys.time()) - 1
    )
    jwt <- jose::jwt_encode_sig(
      do.call(jose::jwt_claim, claims),
      key = signing_key
    )
    response <- get(paste0(
      issuer,
      "/authorize?",
      httr2::url_query_build(list(request = jwt))
    ))
    testthat::expect_identical(httr2::resp_status(response), 400L)
    testthat::expect_identical(
      httr2::resp_body_json(response)$reason,
      switch(
        field,
        iss = "jar_issuer",
        aud = "jar_audience",
        exp = "jar_expired"
      )
    )
  }
  first <- get(url)
  testthat::expect_identical(httr2::resp_status(first), 302L)
  replay <- get(url)
  testthat::expect_identical(httr2::resp_body_json(replay)$reason, "jar_replay")

  for (mode in c("dpop", "dpop-par", "mtls", "mtls-par", "jarm")) {
    configured <- client
    if (grepl("dpop", mode)) {
      configured@dpop_private_key <- openssl::ec_keygen("P-256")
      configured@dpop_require_access_token <- TRUE
    }
    if (grepl("mtls", mode)) {
      configured@scopes <- c("openid", "mtls")
      S7::props(configured) <- list(
        mtls_client_cert_file = file.path(root, "client.pem"),
        mtls_client_key_file = file.path(root, "client-key.pem"),
        mtls_client_ca_file = file.path(root, "ca.pem")
      )
      configured@provider@token_auth_style <- "tls_client_auth"
      configured@provider@mtls_client_certificate_bound_access_tokens <- TRUE
      configured@mtls_certificate_bound_access_tokens <- TRUE
    }
    if (grepl("par", mode)) {
      configured@provider@par_url <- paste0(issuer, "/par")
    }
    if (mode == "jarm") {
      configured@response_mode <- "query.jwt"
      configured@jarm_signed_response_alg <- "RS256"
    }
    url <- shinyOAuth::prepare_call(configured, browser_token = browser)
    response <- get(url)
    testthat::expect_identical(httr2::resp_status(response), 302L, info = mode)
    callback <- query(httr2::resp_header(response, "location"))
    if (mode != "jarm") {
      state <- shinyOAuth:::state_payload_decrypt_validate(
        configured,
        callback$state
      )
      saved <- shinyOAuth:::state_store_get(configured, state$state)
      unbound <- httr2::request(paste0(issuer, "/token")) |>
        httr2::req_options(cainfo = file.path(root, "ca.pem")) |>
        httr2::req_body_form(
          grant_type = "authorization_code",
          client_id = "client",
          code = callback$code,
          redirect_uri = configured@redirect_uri,
          code_verifier = saved$pkce_code_verifier
        ) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_perform()
      testthat::expect_identical(httr2::resp_status(unbound), 400L)
      testthat::expect_identical(
        httr2::resp_body_json(unbound)$reason,
        if (grepl("dpop", mode)) "dpop_required" else "mtls_certificate"
      )
    }
    if (mode == "jarm") {
      token <- NULL
      shiny::testServer(
        shinyOAuth::oauth_module_server,
        args = list(id = "auth", client = configured, auto_redirect = FALSE),
        {
          session$setInputs(shinyOAuth_sid = browser)
          values$.process_query(paste0("?", httr2::url_query_build(callback)))
          session$flushReact()
          testthat::expect_null(values$error)
          token <<- values$token
        }
      )
    } else {
      token <- shinyOAuth:::handle_callback(
        configured,
        code = callback$code,
        payload = callback$state,
        browser_token = browser,
        iss = callback$iss
      )
    }
    testthat::expect_true(
      S7::S7_inherits(token, shinyOAuth::OAuthToken),
      info = mode
    )
    testthat::expect_identical(
      token@token_type,
      if (grepl("dpop", mode)) "DPoP" else "Bearer"
    )
    testthat::expect_gt(token@expires_at, as.numeric(Sys.time()))
  }
})
