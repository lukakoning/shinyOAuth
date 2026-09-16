test_that("missing token type compatibility is explicit and validated", {
  args <- list(
    name = "legacy",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token"
  )
  for (constructor in list(oauth_provider, OAuthProvider)) {
    provider <- do.call(constructor, args)
    expect_false(provider@allow_missing_token_type)
    compatible <- do.call(
      constructor,
      c(args, list(allow_missing_token_type = TRUE))
    )
    expect_true(compatible@allow_missing_token_type)
    expect_false(identical(
      shinyOAuth:::provider_fingerprint(provider),
      shinyOAuth:::provider_fingerprint(compatible)
    ))
    for (invalid in list(NA, logical(), c(TRUE, FALSE), "TRUE", 1, NULL)) {
      expect_error(do.call(
        constructor,
        c(args, list(allow_missing_token_type = invalid))
      ))
    }
  }
})

test_that("login and refresh only infer Bearer from an absent token type", {
  client <- make_test_client(use_nonce = FALSE)
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@userinfo_required <- TRUE
  token_json <- NULL
  userinfo_calls <- 0L
  authorization <- NULL
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      is_userinfo <- identical(req[["url"]], client@provider@userinfo_url)
      if (is_userinfo) {
        userinfo_calls <<- userinfo_calls + 1L
        authorization <<- httr2::req_dry_run(
          req,
          quiet = TRUE,
          redact_headers = FALSE
        )[["headers"]][["authorization"]]
      }
      httr2::response(
        status_code = 200L,
        headers = list("Content-Type" = "application/json"),
        body = charToRaw(if (is_userinfo) '{"sub":"user"}' else token_json),
        url = req[["url"]]
      )
    },
    .package = "shinyOAuth"
  )
  for (operation in c("login", "refresh")) {
    run <- function() {
      if (operation == "refresh") {
        refresh_token(
          client,
          OAuthToken(access_token = "old", refresh_token = "refresh")
        )
      } else {
        browser <- valid_browser_token()
        state <- parse_query_param(
          prepare_call(client, browser_token = browser),
          "state"
        )
        handle_callback(
          client,
          code = "code",
          state = state,
          browser_token = browser
        )
      }
    }
    token_json <- '{"access_token":"new-access","expires_in":3600}'
    client@provider@allow_missing_token_type <- FALSE
    userinfo_calls <- 0L
    expect_error(run(), "missing token_type", class = "shinyOAuth_token_error")
    expect_identical(userinfo_calls, 0L)

    client@provider@allow_missing_token_type <- TRUE
    result <- run()
    expect_identical(result@token_type, "Bearer")
    expect_identical(result@userinfo, list(sub = "user"))
    expect_identical(userinfo_calls, 1L)
    expect_identical(authorization, "Bearer new-access")

    client@provider@allowed_token_types <- "MAC"
    expect_error(
      run(),
      "Unsupported token_type",
      class = "shinyOAuth_token_error"
    )
    client@provider@allowed_token_types <- "Bearer"

    for (value in c(
      'null',
      '""',
      '"MAC"',
      '"DPoP"',
      'false',
      '42',
      '["Bearer"]',
      '{}'
    )) {
      token_json <- paste0(
        '{"access_token":"new-access","expires_in":3600,"token_type":',
        value,
        '}'
      )
      userinfo_calls <- 0L
      expect_error(run(), class = "shinyOAuth_error")
      expect_identical(userinfo_calls, 0L)
    }

    token_json <- '{"access_token":"new-access","expires_in":3600,"token_type":"bearer"}'
    expect_identical(run()@token_type, "bearer")

    token_json <- '{"access_token":"new-access","expires_in":3600}'
    client@dpop_private_key <- openssl::rsa_keygen()
    client@dpop_require_access_token <- FALSE
    userinfo_calls <- 0L
    expect_error(run(), "missing token_type", class = "shinyOAuth_token_error")
    expect_identical(userinfo_calls, 0L)
    client@dpop_private_key <- NULL
  }
})

test_that("token verification applies the same missing-type policy", {
  client <- make_test_client(use_nonce = FALSE)
  response <- list(access_token = "access", expires_in = 3600)
  expect_error(
    shinyOAuth:::verify_token_set(client, response, nonce = NULL),
    "missing token_type"
  )
  client@provider@allow_missing_token_type <- TRUE
  for (refresh in c(FALSE, TRUE)) {
    result <- shinyOAuth:::verify_token_set(
      client,
      response,
      nonce = NULL,
      is_refresh = refresh
    )
    expect_identical(result[["token_type"]], "Bearer")
    expect_error(
      shinyOAuth:::verify_token_set(
        client,
        c(response, list(token_type = NULL)),
        nonce = NULL,
        is_refresh = refresh
      ),
      "missing token_type"
    )
  }
})
