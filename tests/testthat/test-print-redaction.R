collect_rendered_output <- function(x) {
  c(
    format = paste(format(x), collapse = "\n"),
    print = paste(capture.output(print(x)), collapse = "\n")
  )
}

expect_no_secret_material <- function(output, secrets) {
  for (secret in secrets) {
    testthat::expect_false(
      grepl(secret, output, fixed = TRUE),
      info = paste("unexpected secret material in output:", secret)
    )
  }
}

test_that("OAuthToken printing redacts token material", {
  access_token <- "access-secret-1234567890"
  refresh_token <- "refresh-secret-ABCDEFGHIJ"
  id_token <- "idtoken-secret-zyxwvutsrqponm-9876543210"

  tok <- OAuthToken(
    access_token = access_token,
    token_type = "Bearer",
    refresh_token = refresh_token,
    id_token = id_token,
    userinfo = list(sub = "user-1", email = "user@example.com")
  )

  rendered <- collect_rendered_output(tok)

  for (output in unname(rendered)) {
    expect_match(output, "<redacted", fixed = TRUE)
    expect_match(output, "acce...7890", fixed = TRUE)
    expect_match(output, "refr...GHIJ", fixed = TRUE)
    expect_match(output, "idto...3210", fixed = TRUE)
    expect_no_secret_material(
      output,
      c(access_token, refresh_token, id_token, "user@example.com")
    )
  }
})

test_that("OAuthClient printing redacts secrets and private keys", {
  client_secret <- "client-secret-1234567890XYZ"
  state_key <- paste0(
    "state-key-secret-",
    "abcdefghijklmnopqrstuvwxyz0123456789"
  )
  client_private_key <- openssl::write_pem(openssl::rsa_keygen())
  dpop_private_key <- openssl::write_pem(openssl::rsa_keygen())

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = client_secret,
    client_private_key = client_private_key,
    client_private_key_kid = "kid-123",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = state_key,
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = "dpop-kid-123"
  )

  rendered <- collect_rendered_output(cli)

  for (output in unname(rendered)) {
    expect_match(output, "<redacted", fixed = TRUE)
    expect_match(output, "clie...0XYZ", fixed = TRUE)
    expect_match(output, "stat...6789", fixed = TRUE)
    expect_match(output, "<redacted PRIVATE KEY>", fixed = TRUE)
    expect_no_secret_material(
      output,
      c(
        client_secret,
        state_key,
        client_private_key,
        dpop_private_key
      )
    )
  }
})

test_that("OAuthClient formatter redacts encrypted PEM strings", {
  encrypted_private_key <- openssl::write_pem(
    openssl::rsa_keygen(),
    password = "test-password"
  )

  rendered <- shinyOAuth:::.shinyoauth_format_field(
    encrypted_private_key,
    secret = TRUE
  )

  expect_identical(rendered, "<redacted ENCRYPTED PRIVATE KEY>")
  expect_false(grepl(encrypted_private_key, rendered, fixed = TRUE))
})
