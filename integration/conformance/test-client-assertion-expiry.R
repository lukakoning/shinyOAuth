client_assertion_expiry_client <- function(fixture, alg, par = FALSE) {
  issuer <- fixture[["issuer"]]
  provider <- shinyOAuth::oauth_provider(
    name = "strict-client-assertion",
    issuer = issuer,
    auth_url = paste0(issuer, "/authorize"),
    token_url = paste0(issuer, "/token"),
    par_url = if (par) paste0(issuer, "/par") else NA_character_,
    token_auth_style = "private_key_jwt",
    infer_oidc_from_issuer = FALSE,
    use_nonce = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    signed_request_object_required = TRUE,
    request_parameter_supported = TRUE,
    request_object_signing_alg_values_supported = alg,
    token_endpoint_auth_signing_alg_values_supported = alg
  )
  shinyOAuth::oauth_client(
    provider,
    client_id = "client",
    redirect_uri = "https://app.example.com/callback",
    scopes = "jwt-legacy",
    client_assertion_private_key = fixture[["signing_key"]],
    client_assertion_alg = alg,
    request_object_mode = "request",
    request_object_signing_alg = alg,
    state_transport = "reference"
  )
}

client_assertion_expiry_request <- function(fixture, url, form = NULL) {
  request <- httr2::request(url) |>
    httr2::req_options(
      cainfo = file.path(fixture[["root"]], "ca.pem"),
      followlocation = FALSE
    ) |>
    httr2::req_timeout(5) |>
    httr2::req_error(is_error = function(...) FALSE)
  if (!is.null(form)) {
    request <- do.call(httr2::req_body_form, c(list(request), form))
  }
  httr2::req_perform(request)
}

expect_client_assertion_denial <- function(response, error, reason) {
  testthat::expect_identical(httr2::resp_status(response), 400L)
  testthat::expect_identical(
    httr2::resp_header(response, "cache-control"),
    "no-store"
  )
  testthat::expect_null(httr2::resp_header(response, "location"))
  # Exact body comparison also excludes codes, PAR references and tokens.
  testthat::expect_identical(
    httr2::resp_body_json(response),
    list(error = error, reason = reason)
  )
}

run_client_assertion_expiry <- function(alg, par) {
  fixture <- strict_as_fixture(alg)
  client <- client_assertion_expiry_client(fixture, alg, par)
  browser <- strrep("ab", 64)
  expire_assertions <- TRUE
  expired_signatures <- logical()
  observed <- list()
  build_assertion <- shinyOAuth:::build_client_assertion
  perform <- shinyOAuth:::req_with_retry
  testthat::local_mocked_bindings(
    build_client_assertion = function(client, aud) {
      jwt <- build_assertion(client, aud)
      if (!expire_assertions) {
        return(jwt)
      }
      claims <- shinyOAuth:::parse_jwt_payload(jwt)
      # Change only exp: the fresh issuer, audience, iat and jti remain valid.
      claims[["exp"]] <- floor(as.numeric(Sys.time())) - 1
      jwt <- shinyOAuth:::encode_asymmetric_jwt_with_header(
        claims,
        fixture[["signing_key"]],
        shinyOAuth:::parse_jwt_header(jwt)
      )
      parts <- strsplit(jwt, ".", fixed = TRUE)[[1L]]
      expired_signatures <<- c(
        expired_signatures,
        openssl::signature_verify(
          charToRaw(paste(parts[1:2], collapse = ".")),
          shinyOAuth:::base64url_decode_raw(parts[[3L]]),
          hash = if (alg == "RS384") openssl::sha384 else openssl::sha256,
          pubkey = as.list(fixture[["signing_key"]])[["pubkey"]]
        )
      )
      testthat::expect_lt(claims[["exp"]], as.numeric(Sys.time()))
      jwt
    },
    req_with_retry = function(req, idempotent = TRUE) {
      response <- perform(req, idempotent)
      observed[[length(observed) + 1L]] <<- list(
        path = httr2::url_parse(req[["url"]])[["path"]],
        response = response
      )
      response
    },
    .package = "shinyOAuth"
  )
  shiny::testServer(
    shinyOAuth::oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["setInputs"]](shinyOAuth_sid = browser)
      session[["flushReact"]]()
      build_url <- function() {
        result <- NULL
        promises::then(values[["build_auth_url"]](), function(url) {
          result <<- url
        })
        # Acknowledge the module's fresh cookie request in this headless session.
        # Browser transport/cookie enforcement is covered separately.
        session[["setInputs"]](
          shinyOAuth_sid = browser_ack[["token"]],
          shinyOAuth_cookie_ack = list(requestId = browser_ack[["id"]])
        )
        deadline <- Sys.time() + 10
        while (is.null(result) && Sys.time() < deadline) {
          later::run_now(0.02)
          session[["flushReact"]]()
        }
        if (is.null(result)) {
          stop("Client-assertion fixture preparation timed out")
        }
        result
      }
      url <- build_url()
      if (par) {
        testthat::expect_identical(url, NA_character_)
        testthat::expect_identical(values[["error"]], "auth_url_error")
        testthat::expect_length(client@state_store[["keys"]](), 0L)
        testthat::expect_identical(
          vapply(observed, `[[`, "", "path"),
          "/par"
        )
      } else {
        testthat::expect_length(client@state_store[["keys"]](), 1L)
        authorization <- client_assertion_expiry_request(fixture, url)
        testthat::expect_identical(httr2::resp_status(authorization), 302L)
        callback <- httr2::url_parse(httr2::resp_header(
          authorization,
          "location"
        ))[["query"]]
        query <- paste0("?", httr2::url_query_build(callback))
        values[[".process_query"]](query)
        session[["flushReact"]]()
        testthat::expect_identical(values[["error"]], "token_exchange_error")
        testthat::expect_null(client@state_store[["get"]](
          shinyOAuth:::state_cache_key(callback[["state"]]),
          missing = NULL
        ))
        testthat::expect_length(observed, 1L)
        values[["error"]] <- NULL
        values[[".process_query"]](query)
        session[["flushReact"]]()
        testthat::expect_identical(values[["error"]], "invalid_state")
        testthat::expect_length(observed, 1L)
      }
      testthat::expect_null(values[["token"]])
      testthat::expect_false(isTRUE(values[["authenticated"]]))
      testthat::expect_null(values[["connection"]]())
      testthat::expect_true(length(expired_signatures) > 0L)
      testthat::expect_true(all(expired_signatures))
      expect_client_assertion_denial(
        observed[[1L]][["response"]],
        "invalid_client",
        "assertion_expiry"
      )

      # A new public preparation and fresh assertions recover on the same AS.
      # The token negative already received a code; it must issue no token.
      # The PAR negative must expose neither a reference nor a browser redirect.
      expire_assertions <<- FALSE
      fresh_url <- build_url()
      testthat::expect_true(is.character(fresh_url) && !is.na(fresh_url))
      authorization <- client_assertion_expiry_request(fixture, fresh_url)
      testthat::expect_identical(httr2::resp_status(authorization), 302L)
      callback <- httr2::url_parse(httr2::resp_header(
        authorization,
        "location"
      ))[["query"]]
      values[[".process_query"]](paste0("?", httr2::url_query_build(callback)))
      session[["flushReact"]]()
      testthat::expect_null(values[["error"]])
      testthat::expect_true(isTRUE(values[["authenticated"]]))
      testthat::expect_true(S7::S7_inherits(
        values[["token"]],
        shinyOAuth::OAuthToken
      ))
      testthat::expect_identical(
        vapply(
          observed,
          function(item) httr2::resp_status(item[["response"]]),
          0L
        ),
        if (par) c(400L, 201L, 200L) else c(400L, 200L)
      )
    }
  )
}

for (algorithm in c("RS256", "RS384")) {
  for (use_par in c(FALSE, TRUE)) {
    local({
      alg <- algorithm
      par <- use_par
      testthat::test_that(
        paste(
          alg,
          "expired client assertion denies",
          if (par) "PAR" else "token"
        ),
        run_client_assertion_expiry(alg, par)
      )
    })
  }
}

testthat::test_that("client-auth errors stay separate from request and grant errors", {
  fixture <- strict_as_fixture("RS256")
  client <- client_assertion_expiry_client(fixture, "RS256")
  issuer <- fixture[["issuer"]]
  fresh_form <- function() {
    params <- httr2::url_parse(shinyOAuth::prepare_call(
      client,
      browser_token = strrep("ab", 64)
    ))[["query"]]
    params[["client_assertion_type"]] <-
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    params[["client_assertion"]] <- shinyOAuth:::build_client_assertion(
      client,
      issuer
    )
    params
  }
  post <- function(path, form) {
    client_assertion_expiry_request(fixture, paste0(issuer, path), form)
  }
  params <- fresh_form()
  claims <- shinyOAuth:::parse_jwt_payload(params[["request"]])
  claims[["exp"]] <- floor(as.numeric(Sys.time())) - 1
  params[["request"]] <- shinyOAuth:::encode_asymmetric_jwt_with_header(
    claims,
    fixture[["signing_key"]],
    list(alg = "RS256")
  )
  expect_client_assertion_denial(
    post("/par", params),
    "invalid_request",
    "jar_expired"
  )
  params <- fresh_form()
  params[["client_secret"]] <- "competing-secret"
  expect_client_assertion_denial(
    post("/par", params),
    "invalid_client",
    "single_client_auth"
  )
  params <- fresh_form()
  params[[
    "client_assertion"
  ]] <- shinyOAuth:::encode_asymmetric_jwt_with_header(
    shinyOAuth:::parse_jwt_payload(params[["client_assertion"]]),
    openssl::rsa_keygen(),
    list(alg = "RS256", typ = "JWT")
  )
  expect_client_assertion_denial(
    post("/par", params),
    "invalid_client",
    "assertion_signature"
  )
  expect_client_assertion_denial(
    post(
      "/token",
      list(
        grant_type = "authorization_code",
        client_id = "client",
        code = "not-an-issued-code"
      )
    ),
    "invalid_request",
    "invalid_code"
  )
})
