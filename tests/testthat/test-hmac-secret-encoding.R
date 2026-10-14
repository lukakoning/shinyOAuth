test_that("HMAC strength checks measure the UTF-8 bytes actually signed", {
  withr::local_options(shinyOAuth.allow_hs = TRUE)
  for (size in c(256L, 384L, 512L)) {
    alg <- paste0("HS", size)
    utf8 <- enc2utf8(strrep("\u00e9", size / 16L))
    latin1 <- iconv(utf8, from = "UTF-8", to = "latin1")
    expect_lt(nchar(latin1, type = "bytes"), size / 8L)
    expect_identical(shinyOAuth:::hmac_secret_bytes(utf8),
      shinyOAuth:::hmac_secret_bytes(latin1))
    claims <- list(sub = "user", exp = floor(as.numeric(Sys.time())) + 300)
    encode <- function(secret) shinyOAuth:::encode_hmac_jwt_with_header(
      claims, secret, list(alg = alg), size
    )
    signed <- encode(utf8)
    expect_identical(encode(latin1), signed)
    expect_true(shinyOAuth:::verify_hmac_jws_signature_no_time(signed, latin1, alg))
    expect_error(encode(substr(latin1, 2L, nchar(latin1))), "requires client_secret")

    provider <- oauth_provider(
      name = "encoding", auth_url = "https://example.com/auth",
      token_url = "https://example.com/token", issuer = "https://example.com",
      use_nonce = FALSE, use_pkce = TRUE, token_auth_style = "client_secret_jwt",
      id_token_allowed_algs = alg
    )
    client <- oauth_client(provider, "abc", client_secret = latin1,
      redirect_uri = "http://localhost:8100", client_assertion_alg = alg,
      response_mode = "query.jwt", jarm_signed_response_alg = alg,
      request_object_mode = "request", request_object_signing_alg = alg)
    assertion <- shinyOAuth:::build_client_assertion(client, provider@token_url)
    expect_true(shinyOAuth:::verify_hmac_jws_signature_no_time(assertion, utf8, alg))
    request_object <- shinyOAuth:::build_authorization_request_object(client,
      list(client_id = "abc", response_type = "code", redirect_uri = client@redirect_uri))
    expect_true(shinyOAuth:::verify_hmac_jws_signature_no_time(request_object, utf8, alg))
    id_claims <- list(iss = provider@issuer, aud = "abc", sub = "user",
      iat = floor(as.numeric(Sys.time())), exp = floor(as.numeric(Sys.time())) + 120)
    id_token <- shinyOAuth:::encode_hmac_jwt_with_header(id_claims, utf8, list(alg = alg), size)
    expect_true(attr(shinyOAuth:::validate_id_token(client, id_token), "signature_verified", exact = TRUE))
    jarm_claims <- c(id_claims, list(code = "code", state = "state"))
    jarm <- shinyOAuth:::encode_hmac_jwt_with_header(jarm_claims, utf8, list(alg = alg), size)
    expect_identical(shinyOAuth:::validate_jarm_response(client, jarm)[["code"]], "code")
  }
})
