test_that("ID-token rejection events name the claim without disclosing values", {
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
    encode <- function(value) {
      base64url_encode(charToRaw(as.character(jsonlite::toJSON(
        value,
        auto_unbox = TRUE
      ))))
    }
    input <- paste(encode(list(alg = "RS256")), encode(payload), sep = ".")
    paste(
      input,
      base64url_encode(openssl::signature_create(
        charToRaw(input),
        openssl::sha256,
        key
      )),
      sep = "."
    )
  }
  expect_true(attr(
    validate_id_token(client, sign(claims), expected_nonce = claims[["nonce"]]),
    "signature_verified",
    exact = TRUE
  ))
  cases <- list(
    list(claim = "sub", payload = utils::modifyList(claims, list(sub = NULL))),
    list(claim = "aud", payload = utils::modifyList(claims, list(aud = NULL))),
    list(
      claim = "aud",
      payload = utils::modifyList(claims, list(aud = "private-wrong-audience"))
    ),
    list(
      claim = "aud",
      payload = utils::modifyList(
        claims,
        list(aud = c(client@client_id, "private-extra-audience"))
      )
    ),
    list(claim = "iat", payload = utils::modifyList(claims, list(iat = NULL))),
    list(
      claim = "iat",
      payload = utils::modifyList(claims, list(iat = "private-wrong-time"))
    ),
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
      "wrong-private-issuer",
      "private-wrong-audience",
      "private-extra-audience",
      "private-wrong-time"
    )) {
      expect_false(grepl(private, encoded, fixed = TRUE))
    }
  }
})

test_that("signature and algorithm rejection events have safe reason codes", {
  events <- list()
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  client <- make_test_client(scopes = "openid")
  client@provider@issuer <- "https://issuer.example"
  client@provider@id_token_allowed_algs <- "RS256"
  key <- openssl::rsa_keygen(2048)
  other <- openssl::rsa_keygen(2048)
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
    iat = now,
    exp = now + 300
  )
  signed <- jose::jwt_encode_sig(do.call(jose::jwt_claim, claims), other)
  encode <- function(value) {
    base64url_encode(charToRaw(as.character(jsonlite::toJSON(
      value,
      auto_unbox = TRUE
    ))))
  }
  unsigned <- paste0(encode(list(alg = "none")), ".", encode(claims), ".")
  for (reason in c("invalid_signature", "disallowed_algorithm")) {
    events <- list()
    jwt <- if (reason == "invalid_signature") signed else unsigned
    failure <- tryCatch(validate_id_token(client, jwt), error = identity)
    expect_s3_class(failure, "shinyOAuth_id_token_error")
    expect_identical(failure[["context"]][["reason"]], reason)
    errors <- Filter(
      function(event) {
        identical(event[["error_class"]], "shinyOAuth_id_token_error")
      },
      events
    )
    expect_length(errors, 1L)
    expect_identical(errors[[1L]][["reason"]], reason)
    expect_null(errors[[1L]][["message"]])
    encoded <- as.character(jsonlite::toJSON(
      events,
      auto_unbox = TRUE,
      null = "null"
    ))
    expect_false(grepl(jwt, encoded, fixed = TRUE))
    expect_false(grepl("private-subject", encoded, fixed = TRUE))
  }
})
