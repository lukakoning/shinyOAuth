testthat::test_that("introspect_token uses JWT client assertion for client_secret_jwt with introspection aud", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@client_secret <- "s3cr3t"
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@token_auth_style <- "client_secret_jwt"
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  called <- FALSE
  got_aud <- NULL

  testthat::local_mocked_bindings(
    build_client_assertion = function(client, aud) {
      called <<- TRUE
      got_aud <<- aud
      return("jwt-assertion")
    },
    req_with_retry = function(req) {
      # Return a minimal successful response body
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  res <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(res$supported))
  testthat::expect_true(isTRUE(res$active))
  testthat::expect_true(called)
  testthat::expect_identical(got_aud, cli@provider@introspection_url)
})


testthat::test_that("introspect_token uses JWT client assertion for private_key_jwt with introspection aud", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Provide a dummy private key before switching auth style to satisfy validation
  cli@client_private_key <- openssl::rsa_keygen()
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@token_auth_style <- "private_key_jwt"
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  called <- FALSE
  got_aud <- NULL

  testthat::local_mocked_bindings(
    build_client_assertion = function(client, aud) {
      called <<- TRUE
      got_aud <<- aud
      return("jwt-assertion")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  res <- introspect_token(cli, t, which = "refresh", async = FALSE)
  testthat::expect_true(isTRUE(res$supported))
  testthat::expect_true(isTRUE(res$active))
  testthat::expect_true(called)
  testthat::expect_identical(got_aud, cli@provider@introspection_url)
})
