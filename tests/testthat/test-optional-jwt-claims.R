# Exercise JSON member presence separately from the decoded member value.
test_that("optional JWT claims distinguish omission, null, scalars and arrays", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  client <- make_test_client()
  client@provider@issuer <- "https://issuer.example.com"
  now <- floor(as.numeric(Sys.time()))
  base <- list(
    iss = client@provider@issuer, aud = client@client_id, sub = "user",
    iat = now - 1, exp = now + 60, code = "code", state = "state"
  )
  encode <- function(claims) {
    paste(
      base64url_encode(charToRaw('{"alg":"RS256"}')),
      base64url_encode(charToRaw(jsonlite::toJSON(
        claims, auto_unbox = TRUE, null = "null"
      ))),
      base64url_encode(charToRaw("signature")), sep = "."
    )
  }
  surfaces <- list(
    id_token = list(
      validate = function(jwt) validate_id_token(client, jwt, expected_access_token = "access"),
      values = list(nbf = now - 1, azp = client@client_id, at_hash = compute_at_hash("access", "RS256")),
      error = "shinyOAuth_id_token_error"
    ),
    jarm = list(
      validate = function(jwt) validate_jarm_claims(client, parse_jwt_payload(jwt)),
      values = list(iat = now - 1, nbf = now - 1),
      error = "shinyOAuth_state_error"
    ),
    userinfo = list(
      validate = function(jwt) validate_signed_userinfo_claims(
        parse_jwt_payload(jwt), client@provider@issuer, client@client_id
      ),
      values = list(exp = now + 60, iat = now - 1, nbf = now - 1),
      error = "shinyOAuth_userinfo_error"
    )
  )
  for (surface in surfaces) {
    for (claim in names(surface$values)) {
      claims <- base
      claims[[claim]] <- NULL
      expect_no_error(surface$validate(encode(claims)))
      claims[[claim]] <- surface$values[[claim]]
      expect_no_error(surface$validate(encode(claims)))
      for (invalid in list(NULL, list(surface$values[[claim]]), list(), TRUE)) {
        claims[claim] <- list(invalid)
        expect_error(surface$validate(encode(claims)), class = surface$error)
      }
    }
  }
})
