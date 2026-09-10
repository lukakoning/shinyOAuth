testthat::test_that("RS384 interoperates with Python cryptography in both directions", {
  withr::local_options(shinyOAuth.skip_id_sig = FALSE)
  python <- Sys.getenv("SHINYOAUTH_TEST_PYTHON", unset = Sys.which("python"))
  testthat::expect_true(nzchar(python))
  root <- tempfile("rs384-interop-")
  dir.create(root)
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  # Check both the RFC 7518 minimum and a larger modulus. The signature width
  # follows the RSA modulus, not the 384-bit digest size.
  for (bits in c(2048L, 3072L)) {
    key <- openssl::rsa_keygen(bits)
    writeLines(openssl::write_pem(key), file.path(root, "outbound-key.pem"))
    provider <- shinyOAuth::oauth_provider(
      name = "rs384-interop",
      issuer = "https://as.example",
      auth_url = "https://as.example/authorize",
      token_url = "https://as.example/token",
      token_auth_style = "private_key_jwt",
      allowed_algs = "RS384",
      token_endpoint_auth_signing_alg_values_supported = "RS384",
      request_object_signing_alg_values_supported = "RS384",
      dpop_signing_alg_values_supported = "RS384",
      id_token_at_hash_required = TRUE
    )
    client <- shinyOAuth::oauth_client(
      provider,
      client_id = "rs384-client",
      redirect_uri = "https://app.example/callback",
      scopes = "openid",
      client_assertion_private_key = key,
      client_assertion_private_key_kid = "rs384-test-key",
      client_assertion_alg = "RS384",
      request_object_mode = "request",
      request_object_signing_alg = "RS384",
      dpop_private_key = key,
      dpop_private_key_kid = "rs384-test-key",
      dpop_signing_alg = "RS384"
    )
    outbound <- list(
      assertion = shinyOAuth:::build_client_assertion(
        client,
        provider@token_url
      ),
      request_object = shinyOAuth:::build_authorization_request_object(
        client,
        list(
          client_id = client@client_id,
          response_type = "code",
          redirect_uri = client@redirect_uri,
          scope = "openid",
          state = "synthetic-state"
        )
      ),
      dpop = shinyOAuth:::build_dpop_proof(
        client,
        method = "GET",
        url = "https://api.example/records?page=2",
        access_token = "synthetic-access",
        nonce = "synthetic-nonce"
      )
    )
    jsonlite::write_json(
      outbound,
      file.path(root, "outbound.json"),
      auto_unbox = TRUE
    )
    # A missing dependency, a crashed oracle or a failed crypto check must fail
    # this test, rather than become a skip or an expected rejection.
    oracle <- processx::run(
      python,
      c("rs384_interop.py", root, as.character(bits)),
      timeout = 30000,
      error_on_status = FALSE
    )
    testthat::expect_identical(oracle$status, 0L, info = oracle$stderr)
    if (oracle$status != 0L) {
      stop("Independent RS384 oracle failed")
    }
    vectors <- jsonlite::read_json(file.path(root, "verified.json"))
    testthat::expect_identical(unlist(vectors$verified), names(outbound))
    public <- openssl::read_pubkey(file.path(root, "inbound-public.pem"))
    testthat::expect_true(shinyOAuth:::verify_jws_signature_no_time(
      vectors$valid,
      public,
      "RS384"
    ))
    # Only the JWKS transport is substituted. Python supplies its public JWK;
    # the package performs its real key selection, signature and claim checks.
    testthat::with_mocked_bindings(
      fetch_jwks = function(...) vectors$jwks,
      .package = "shinyOAuth",
      {
        validate <- function(jwt) {
          shinyOAuth:::validate_id_token(
            client,
            jwt,
            expected_nonce = "synthetic-nonce",
            expected_sub = "synthetic-user",
            expected_access_token = "synthetic-access"
          )
        }
        testthat::expect_silent(validate(vectors$valid))
        for (case in names(vectors$invalid)) {
          jwt <- vectors$invalid[[case]]
          testthat::expect_false(
            shinyOAuth:::verify_jws_signature_no_time(jwt, public, "RS384"),
            info = paste(bits, case)
          )
          testthat::expect_error(
            validate(jwt),
            regexp = "signature",
            class = "shinyOAuth_id_token_error",
            info = paste(bits, case)
          )
        }
        testthat::expect_error(
          validate(vectors$wrong_at_hash),
          regexp = "at_hash",
          class = "shinyOAuth_id_token_error"
        )
      }
    )
  }
})
