make_typed_assertion_client <- function(style = "client_secret_jwt", ...) {
  provider <- oauth_provider(
    name = "typed",
    issuer = "https://issuer.example",
    issuer_thus_oidc = FALSE,
    auth_url = "https://issuer.example/auth",
    token_url = "https://issuer.example/token",
    par_url = "https://issuer.example/par",
    introspection_url = "https://issuer.example/introspect",
    revocation_url = "https://issuer.example/revoke",
    token_auth_style = style,
    use_pkce = TRUE
  )
  oauth_client(
    provider,
    client_id = "client",
    client_secret = strrep("s", 32),
    client_assertion_private_key = if (style == "private_key_jwt") {
      openssl::ec_keygen()
    } else {
      NULL
    },
    redirect_uri = "https://app.example/callback",
    state_key = strrep("k", 64),
    ...
  )
}

test_that("typed issuer-audience assertions reach each endpoint and retry", {
  for (style in c("client_secret_jwt", "private_key_jwt")) {
    client <- make_typed_assertion_client(
      style,
      client_assertion_typ = "client-authentication+jwt",
      client_assertion_audience = "https://issuer.example"
    )
    seen <- character()
    testthat::local_mocked_bindings(
      req_with_retry = function(req, ...) {
        seen <<- c(seen, req$url)
        assertions <- character()
        for (attempt in 1:2) {
          current <- req$shinyOAuth_prepare_attempt(req, attempt)
          fields <- if (current$body$type == "form") {
            lapply(current$body$data, function(value) {
              utils::URLdecode(as.character(value))
            })
          } else {
            decode_form_pairs(rawToChar(current$body$data))
          }
          jwt <- fields$client_assertion
          assertions <- c(assertions, jwt)
          expect_identical(
            parse_jwt_header(jwt)$typ,
            "client-authentication+jwt"
          )
          expect_identical(parse_jwt_payload(jwt)$aud, client@provider@issuer)
          expect_identical(
            fields$client_assertion_type,
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
          )
          if (style == "client_secret_jwt") {
            parts <- strsplit(as.character(jwt), ".", fixed = TRUE)[[1L]]
            expected <- openssl::sha256(
              charToRaw(paste(parts[1:2], collapse = ".")),
              key = charToRaw(client@client_secret)
            )
            expect_identical(parts[[3L]], base64url_encode(expected))
          } else {
            expect_true(verify_jws_signature_no_time(
              jwt,
              client@client_assertion_private_key$pubkey,
              "ES256"
            ))
          }
        }
        expect_false(identical(
          parse_jwt_payload(assertions[[1]])$jti,
          parse_jwt_payload(assertions[[2]])$jti
        ))
        body <- if (grepl("/par$", req$url)) {
          '{"request_uri":"urn:example:par","expires_in":60}'
        } else if (grepl("/introspect$", req$url)) {
          '{"active":true}'
        } else {
          '{"access_token":"access","token_type":"Bearer","expires_in":3600}'
        }
        httr2::response(
          status = if (grepl("/par$", req$url)) 201 else 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(body)
        )
      },
      .package = "shinyOAuth"
    )
    token <- OAuthToken(
      access_token = "access",
      refresh_token = "refresh",
      token_type = "Bearer"
    )
    swap_code_for_token_set(client, "code", "verifier")
    refresh_token(client, token, async = FALSE)
    push_authorization_request(client, list(client_id = client@client_id))
    introspect_token(client, token, async = FALSE)
    revoke_token(client, token, async = FALSE)
    expect_equal(length(seen), 5L)
    expect_equal(sum(seen == client@provider@token_url), 2L)
  }
})

test_that("legacy assertion defaults and per-endpoint overrides remain independent", {
  client <- make_typed_assertion_client()
  expect_identical(client@client_assertion_typ, "JWT")
  expect_identical(
    parse_jwt_header(build_client_assertion(
      client,
      client@provider@token_url
    ))$typ,
    "JWT"
  )
  expect_identical(
    resolve_client_assertion_audience(
      client,
      httr2::request(client@provider@token_url)
    ),
    client@provider@token_url
  )
  expect_identical(
    resolve_client_assertion_audience(
      client,
      httr2::request(client@provider@par_url)
    ),
    client@provider@issuer
  )
  before <- state_client_policy_fingerprint(client)
  client@endpoint_auth <- list(
    par = list(
      client_assertion_typ = "client-authentication+jwt",
      client_assertion_audience = client@provider@issuer
    )
  )
  resolved <- endpoint_auth_client(client, "par")
  jwt <- apply_direct_client_auth(
    httr2::request(client@provider@par_url),
    list(),
    resolved,
    "par"
  )$params$client_assertion
  expect_identical(parse_jwt_header(jwt)$typ, "client-authentication+jwt")
  expect_identical(parse_jwt_payload(jwt)$aud, client@provider@issuer)
  expect_identical(client@client_assertion_typ, "JWT")
  expect_false(identical(before, state_client_policy_fingerprint(client)))
  client@client_assertion_typ <- "client-authentication+jwt"
  expect_identical(
    unserialize(serialize(client, NULL))@client_assertion_typ,
    "client-authentication+jwt"
  )
})

test_that("assertion typ validation applies to helper, raw and endpoint configurations", {
  client <- make_typed_assertion_client()
  args <- S7::props(client)
  for (value in list(
    "",
    NA_character_,
    character(),
    c("JWT", "JWT"),
    "bad\ntype",
    "bad type"
  )) {
    args$client_assertion_typ <- value
    expect_error(do.call(OAuthClient, args), "client_assertion_typ")
    expect_error(
      make_typed_assertion_client(client_assertion_typ = value),
      "client_assertion_typ"
    )
    expect_error(
      {
        client@endpoint_auth <- list(par = list(client_assertion_typ = value))
      },
      "client_assertion_typ"
    )
  }
})
