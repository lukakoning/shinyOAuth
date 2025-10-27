testthat::test_that("private_key_jwt picks EC-compatible default alg", {
  testthat::skip_if_not_installed("jose")
  # Some Windows/CI setups may lack EC support in OpenSSL; skip if ec_keygen fails
  key_ec <- try(openssl::ec_keygen(curve = "P-256"), silent = TRUE)
  if (inherits(key_ec, "try-error")) {
    testthat::skip("EC key generation not supported on this platform")
  }

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_private_key = key_ec,
    client_private_key_kid = NA_character_,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid")
  )

  # Capture the composed client_assertion to inspect the header alg
  captured <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    }
  )

  ts <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code",
    code_verifier = "ver"
  )
  testthat::expect_equal(ts$access_token, "at")
  assertion <- captured$client_assertion
  hdr <- shinyOAuth:::parse_jwt_header(assertion)
  testthat::expect_identical(toupper(hdr$typ), "JWT")
  testthat::expect_identical(toupper(hdr$alg), "ES256")
})
