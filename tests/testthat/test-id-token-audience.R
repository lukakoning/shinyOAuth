test_that("validate_id_token accepts multi-audience with azp", {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE
  )
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "client-123",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )

  # Build a fake JWT payload with multiple audiences and azp
  payload <- list(
    iss = prov@issuer,
    aud = c("client-123", "other-app"),
    azp = "client-123",
    sub = "user-1",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 10
  )
  # Create a non-signed JWT: we'll skip signature verification via option
  header <- jsonlite::toJSON(list(alg = "none"), auto_unbox = TRUE)
  claims <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  enc <- function(x) {
    b <- openssl::base64_encode(charToRaw(x))
    b <- gsub("=+$", "", b)
    chartr("+/", "-_", b)
  }
  jwt <- paste(enc(header), enc(claims), "", sep = ".")

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    dec <- shinyOAuth:::validate_id_token(client, jwt)
    expect_true(is.list(dec))
    expect_identical(dec$azp, "client-123")
  })
})

test_that("validate_id_token rejects multi-audience without azp", {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE
  )
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "client-abc",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )

  payload <- list(
    iss = prov@issuer,
    aud = c("client-abc", "another"),
    sub = "user-1",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 10
  )
  header <- jsonlite::toJSON(list(alg = "none"), auto_unbox = TRUE)
  claims <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  enc <- function(x) {
    b <- openssl::base64_encode(charToRaw(x))
    b <- gsub("=+$", "", b)
    chartr("+/", "-_", b)
  }
  jwt <- paste(enc(header), enc(claims), "", sep = ".")

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      class = "shinyOAuth_id_token_error"
    )
  })
})

test_that("validate_id_token rejects when client_id not in aud", {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE
  )
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "client-z",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )

  payload <- list(
    iss = prov@issuer,
    aud = c("other1", "other2"),
    sub = "user-1",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 10
  )
  header <- jsonlite::toJSON(list(alg = "none"), auto_unbox = TRUE)
  claims <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  enc <- function(x) {
    b <- openssl::base64_encode(charToRaw(x))
    b <- gsub("=+$", "", b)
    chartr("+/", "-_", b)
  }
  jwt <- paste(enc(header), enc(claims), "", sep = ".")

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      regexp = "Audience does not include client_id",
      class = "shinyOAuth_id_token_error"
    )
  })
})
