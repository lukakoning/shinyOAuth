test_that("Ed25519 signs interoperable client assertions, Request Objects and DPoP", {
  key <- openssl::ed25519_keygen()
  for (role in c("assertion", "request", "dpop")) {
    for (input in list(key, openssl::write_pem(key))) {
      for (alg in list(NULL, "eddsa")) {
        provider <- make_test_provider()
        provider@issuer <- "https://issuer.example.com"
        provider@token_auth_style <- if (role == "assertion") {
          "private_key_jwt"
        } else {
          "body"
        }
        metadata <- switch(
          role,
          assertion = "token_endpoint_auth_signing_alg_values_supported",
          request = "request_object_signing_alg_values_supported",
          dpop = "dpop_signing_alg_values_supported"
        )
        S7::prop(provider, metadata) <- "EdDSA"
        args <- list(
          provider = provider,
          client_id = "client",
          redirect_uri = "http://localhost:8100",
          scopes = "openid"
        )
        if (role == "dpop") {
          args$dpop_private_key <- input
          args$dpop_signing_alg <- alg
        } else {
          args$client_assertion_private_key <- input
          if (role == "assertion") {
            args$client_assertion_alg <- alg
          } else {
            args$request_object_mode <- "request"
            args$request_object_signing_alg <- alg
          }
        }
        client <- do.call(oauth_client, args)
        jwt <- switch(
          role,
          assertion = build_client_assertion(client, provider@token_url),
          request = build_authorization_request_object(
            client,
            list(
              response_type = "code",
              client_id = "client",
              state = "synthetic"
            )
          ),
          dpop = build_dpop_proof(
            client,
            "GET",
            "https://api.example.com/data?ignored=1",
            access_token = "synthetic"
          )
        )
        parts <- strsplit(jwt, ".", fixed = TRUE)[[1L]]
        header <- jsonlite::fromJSON(base64url_decode(parts[[1L]]))
        expect_identical(header$alg, "EdDSA")
        signing_input <- charToRaw(paste(parts[1:2], collapse = "."))
        signature <- base64url_decode_raw(parts[[3L]])
        expect_length(signature, 64L)
        expect_true(openssl::ed25519_verify(
          signing_input,
          signature,
          key$pubkey
        ))
        signature[[1L]] <- as.raw(bitwXor(as.integer(signature[[1L]]), 1L))
        expect_error(
          openssl::ed25519_verify(
            signing_input,
            signature,
            key$pubkey
          ),
          "signature"
        )
        if (role == "dpop") {
          expect_setequal(names(header$jwk), c("kty", "crv", "x"))
          expect_identical(header$jwk$crv, "Ed25519")
          expect_identical(
            base64url_decode_raw(header$jwk$x),
            as.list(key$pubkey)$data
          )
          expect_identical(
            client_dpop_jkt(client),
            compute_jwk_thumbprint(header$jwk)
          )
        }
        provider2 <- provider
        S7::prop(provider2, metadata) <- "RS256"
        args$provider <- provider2
        expect_error(do.call(oauth_client, args), "not supported by provider")
      }
    }
  }
})

test_that("unsupported modern JOSE modes remain explicit configuration errors", {
  provider <- make_test_provider()
  provider@issuer <- "https://issuer.example.com"
  key <- openssl::rsa_keygen()
  args <- list(
    provider = provider,
    client_id = "client",
    redirect_uri = "http://localhost:8100",
    scopes = "openid"
  )
  for (alg in c("PS256", "PS384", "PS512")) {
    expect_error(
      do.call(
        oauth_client,
        c(
          args,
          list(response_mode = "query.jwt", jarm_signed_response_alg = alg)
        )
      ),
      "not supported for inbound JARM"
    )
    expect_error(
      do.call(
        oauth_client,
        c(args, list(dpop_private_key = key, dpop_signing_alg = alg))
      ),
      "incompatible with DPoP"
    )
  }
  expect_error(
    do.call(
      oauth_client,
      c(
        args,
        list(
          request_object_mode = "request",
          client_assertion_private_key = key,
          request_object_encryption_alg = "RSA-OAEP-256",
          request_object_encryption_enc = "A128CBC-HS256"
        )
      )
    ),
    "not supported"
  )
  for (enc in c("A128GCM", "A192GCM", "A256GCM")) {
    expect_error(
      do.call(
        oauth_client,
        c(
          args,
          list(
            response_mode = "query.jwt",
            jarm_decryption_private_key = key,
            jarm_encrypted_response_alg = "RSA-OAEP",
            jarm_encrypted_response_enc = enc
          )
        )
      ),
      "not supported"
    )
  }
})
