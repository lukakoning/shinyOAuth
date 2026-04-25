enc_b64url_ms <- function(x) {
  b <- openssl::base64_encode(charToRaw(x))
  b <- gsub("=+$", "", b)
  chartr("+/", "-_", b)
}

build_jwt_ms <- function(header, claims, sig = "") {
  paste(
    enc_b64url_ms(jsonlite::toJSON(header, auto_unbox = TRUE)),
    enc_b64url_ms(jsonlite::toJSON(claims, auto_unbox = TRUE)),
    sig,
    sep = "."
  )
}

ms_alias_client <- function(tenant = "common") {
  prov <- shinyOAuth::oauth_provider_microsoft(tenant = tenant)
  shinyOAuth::oauth_client(
    prov,
    client_id = "client-ms",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
}

test_that("validate_id_token accepts Microsoft common issuer template", {
  client <- ms_alias_client()
  tid <- "12345678-1234-1234-1234-123456789abc"
  now <- floor(as.numeric(Sys.time()))
  jwt <- build_jwt_ms(
    list(alg = "none"),
    list(
      iss = sprintf("https://login.microsoftonline.com/%s/v2.0", tid),
      tid = tid,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 3600,
      iat = now - 10
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    dec <- shinyOAuth:::validate_id_token(client, jwt)
    expect_identical(dec$tid, tid)
  })
})

test_that("validate_id_token accepts Microsoft organizations issuer template", {
  client <- ms_alias_client("organizations")
  tid <- "12345678-1234-1234-1234-123456789abc"
  now <- floor(as.numeric(Sys.time()))
  jwt <- build_jwt_ms(
    list(alg = "none"),
    list(
      iss = sprintf("https://login.microsoftonline.com/%s/v2.0", tid),
      tid = tid,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 3600,
      iat = now - 10
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    dec <- shinyOAuth:::validate_id_token(client, jwt)
    expect_identical(dec$tid, tid)
  })
})

test_that("validate_id_token rejects Microsoft common tokens with invalid tid", {
  client <- ms_alias_client()
  now <- floor(as.numeric(Sys.time()))
  jwt <- build_jwt_ms(
    list(alg = "none"),
    list(
      iss = "https://login.microsoftonline.com/not-a-guid/v2.0",
      tid = "not-a-guid",
      aud = client@client_id,
      sub = "user-1",
      exp = now + 3600,
      iat = now - 10
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      class = "shinyOAuth_id_token_error",
      regexp = "tid claim"
    )
  })
})

test_that("validate_id_token accepts templated Microsoft key issuers", {
  testthat::skip_if_not_installed("jose")

  client <- ms_alias_client()
  tid <- "12345678-1234-1234-1234-123456789abc"
  now <- as.numeric(Sys.time())

  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(
    kty = priv_jwk$kty,
    n = priv_jwk$n,
    e = priv_jwk$e,
    kid = "ms-common-key",
    use = "sig",
    alg = "RS256",
    issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
  )
  id_token <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = sprintf("https://login.microsoftonline.com/%s/v2.0", tid),
      tid = tid,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 120,
      iat = now - 1
    ),
    key = rsa,
    header = list(alg = "RS256", kid = pub_jwk$kid, typ = "JWT")
  )
  jwks <- list(keys = list(pub_jwk))

  expect_silent(testthat::with_mocked_bindings(
    fetch_jwks = function(
      issuer,
      jwks_cache,
      force_refresh = FALSE,
      pins = NULL,
      pin_mode = c("any", "all"),
      provider = NULL
    ) {
      jwks
    },
    .package = "shinyOAuth",
    {
      dec <- shinyOAuth:::validate_id_token(client, id_token)
      expect_identical(dec$tid, tid)
    }
  ))
})

test_that("validate_id_token rejects Microsoft keys outside issuer scope", {
  testthat::skip_if_not_installed("jose")

  client <- ms_alias_client()
  tid <- "12345678-1234-1234-1234-123456789abc"
  other_tid <- "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  now <- as.numeric(Sys.time())

  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(
    kty = priv_jwk$kty,
    n = priv_jwk$n,
    e = priv_jwk$e,
    kid = "ms-wrong-scope-key",
    use = "sig",
    alg = "RS256",
    issuer = sprintf("https://login.microsoftonline.com/%s/v2.0", other_tid)
  )
  id_token <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = sprintf("https://login.microsoftonline.com/%s/v2.0", tid),
      tid = tid,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 120,
      iat = now - 1
    ),
    key = rsa,
    header = list(alg = "RS256", kid = pub_jwk$kid, typ = "JWT")
  )
  jwks <- list(keys = list(pub_jwk))

  expect_error(
    testthat::with_mocked_bindings(
      fetch_jwks = function(
        issuer,
        jwks_cache,
        force_refresh = FALSE,
        pins = NULL,
        pin_mode = c("any", "all"),
        provider = NULL
      ) {
        jwks
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::validate_id_token(client, id_token)
      }
    ),
    class = "shinyOAuth_id_token_error",
    regexp = "issuer scope"
  )
})
