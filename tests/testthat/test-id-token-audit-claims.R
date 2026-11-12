test_that("issuer and nonce rejection events name the claim without disclosing values", {
  events <- list()
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  client <- make_test_client(use_nonce = TRUE, scopes = "openid")
  client@provider@issuer <- "https://issuer.example"
  client@provider@id_token_validation <- TRUE
  client@provider@id_token_allowed_algs <- "RS256"
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    .package = "shinyOAuth"
  )
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "private-subject",
    nonce = "expected-private-nonce",
    iat = now,
    exp = now + 300
  )
  sign <- function(payload) {
    jose::jwt_encode_sig(do.call(jose::jwt_claim, payload), key)
  }
  expect_true(attr(
    validate_id_token(client, sign(claims), expected_nonce = claims[["nonce"]]),
    "signature_verified",
    exact = TRUE
  ))
  cases <- list(
    list(claim = "iss", payload = utils::modifyList(claims, list(iss = NULL))),
    list(
      claim = "iss",
      payload = utils::modifyList(
        claims,
        list(iss = "https://wrong-private-issuer.example")
      )
    ),
    list(
      claim = "nonce",
      payload = utils::modifyList(claims, list(nonce = NULL))
    ),
    list(
      claim = "nonce",
      payload = utils::modifyList(
        claims,
        list(nonce = "received-private-nonce")
      )
    ),
    list(
      claim = "nonce",
      payload = utils::modifyList(claims, list(nonce = 123))
    )
  )
  for (case in cases) {
    events <- list()
    jwt <- sign(case[["payload"]])
    failure <- tryCatch(
      validate_id_token(client, jwt, expected_nonce = claims[["nonce"]]),
      error = identity
    )
    expect_s3_class(failure, "shinyOAuth_id_token_error")
    expect_identical(failure[["context"]][["claim"]], case[["claim"]])
    errors <- Filter(
      function(event) {
        identical(event[["error_class"]], "shinyOAuth_id_token_error")
      },
      events
    )
    expect_length(errors, 1L)
    expect_identical(errors[[1L]][["claim"]], case[["claim"]])
    expect_null(errors[[1L]][["message"]])
    encoded <- as.character(jsonlite::toJSON(
      events,
      auto_unbox = TRUE,
      null = "null"
    ))
    for (private in c(
      jwt,
      "expected-private-nonce",
      "received-private-nonce",
      "wrong-private-issuer"
    )) {
      expect_false(grepl(private, encoded, fixed = TRUE))
    }
  }
})
