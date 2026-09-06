test_that("RSA signing keys are rejected below 2048 bits at construction", {
  weak <- openssl::rsa_keygen(1024)
  strong <- openssl::rsa_keygen(2048)
  for (mode in c("private_key_jwt", "jar", "dpop")) {
    provider <- oauth_provider(
      name = "strength",
      issuer = "https://example.com",
      issuer_thus_oidc = FALSE,
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      id_token_validation = FALSE,
      use_nonce = FALSE,
      token_auth_style = if (mode == "private_key_jwt") mode else "public"
    )
    args <- list(
      provider = provider,
      client_id = "client",
      redirect_uri = "http://localhost/callback"
    )
    if (mode == "jar") {
      args$request_object_mode <- "request"
    }
    field <- if (mode == "dpop") {
      "dpop_private_key"
    } else {
      "client_assertion_private_key"
    }
    alg_field <- switch(
      mode,
      private_key_jwt = "client_assertion_alg",
      jar = "request_object_signing_alg",
      dpop = "dpop_signing_alg"
    )
    for (constructor in list(oauth_client, OAuthClient)) {
      for (explicit in c(FALSE, TRUE)) {
        configured <- args
        if (explicit) {
          configured[[alg_field]] <- "RS256"
        }
        for (key in list(weak, openssl::write_pem(weak))) {
          configured[[field]] <- key
          expect_error(
            do.call(constructor, configured),
            "RSA modulus must be at least 2048 bits"
          )
        }
        configured[[field]] <- strong
        client <- do.call(constructor, configured)
        expect_s3_class(client, "shinyOAuth::OAuthClient")
        expect_error(
          {
            S7::prop(client, field) <- weak
          },
          "at least 2048 bits"
        )
      }
    }
  }
  expect_false(private_key_can_sign_jws_alg(weak, "RS256"))
  expect_true(private_key_can_sign_jws_alg(strong, "RS256"))
})
