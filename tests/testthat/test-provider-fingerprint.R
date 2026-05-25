test_that("provider_fingerprint avoids delimiter collisions", {
  # Construct a minimal S7 object with the fields provider_fingerprint uses.
  # This keeps the test focused on fingerprint serialization, independent of
  # URL/host validation rules in oauth_provider().
  DummyProvider <- S7::new_class(
    "DummyProvider",
    properties = list(
      issuer = S7::class_character,
      auth_url = S7::class_character,
      token_url = S7::class_character,
      userinfo_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      introspection_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      issuer_match = S7::new_property(
        S7::class_character,
        default = "url"
      ),
      use_nonce = S7::new_property(S7::class_logical, default = FALSE),
      use_pkce = S7::new_property(S7::class_logical, default = TRUE),
      pkce_method = S7::new_property(
        S7::class_character,
        default = "S256"
      ),
      userinfo_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      userinfo_id_selector = S7::new_property(
        S7::class_any,
        default = quote(function(userinfo) userinfo[["sub"]])
      ),
      userinfo_id_token_match = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      userinfo_signed_jwt_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      id_token_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      id_token_validation = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      id_token_at_hash_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      tolerate_duplicate_top_level_jarm_iss = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      token_auth_style = S7::new_property(
        S7::class_character,
        default = "body"
      ),
      tls_client_certificate_bound_access_tokens = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      jwks_pins = S7::new_property(
        S7::class_character,
        default = character()
      ),
      jwks_pin_mode = S7::new_property(
        S7::class_character,
        default = "any"
      ),
      jwks_host_issuer_match = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      jwks_host_allow_only = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      allowed_algs = S7::new_property(
        S7::class_character,
        default = c("RS256", "ES256")
      ),
      allowed_token_types = S7::new_property(
        S7::class_character,
        default = character()
      ),
      leeway = S7::new_property(S7::class_numeric, default = 30),
      mtls_endpoint_aliases = S7::new_property(
        S7::class_list,
        default = list()
      )
    )
  )

  prov1 <- DummyProvider(
    issuer = "a|au=b",
    auth_url = "c",
    token_url = "d"
  )

  prov2 <- DummyProvider(
    issuer = "a",
    auth_url = "b|au=c",
    token_url = "d"
  )

  # The old implementation (key=value fields with | delimiters) can collide when
  # values contain the delimiter tokens.
  old_fp <- function(p) {
    paste0(
      "iss=",
      p@issuer,
      "|au=",
      p@auth_url,
      "|tu=",
      p@token_url
    )
  }

  expect_identical(old_fp(prov1), old_fp(prov2))

  # The new implementation must not collide.
  fp1 <- shinyOAuth:::provider_fingerprint(prov1)
  fp2 <- shinyOAuth:::provider_fingerprint(prov2)

  expect_true(startsWith(fp1, "sha256:"))
  expect_true(startsWith(fp2, "sha256:"))
  expect_false(identical(fp1, fp2))
})

test_that("provider_fingerprint changes when callback security policy changes", {
  DummyProvider <- S7::new_class(
    "DummyProviderPolicy",
    properties = list(
      issuer = S7::class_character,
      auth_url = S7::class_character,
      token_url = S7::class_character,
      userinfo_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      introspection_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      issuer_match = S7::new_property(
        S7::class_character,
        default = "url"
      ),
      use_nonce = S7::new_property(S7::class_logical, default = TRUE),
      use_pkce = S7::new_property(S7::class_logical, default = TRUE),
      pkce_method = S7::new_property(
        S7::class_character,
        default = "S256"
      ),
      userinfo_required = S7::new_property(
        S7::class_logical,
        default = TRUE
      ),
      userinfo_id_selector = S7::new_property(
        S7::class_any,
        default = quote(function(userinfo) userinfo[["sub"]])
      ),
      userinfo_id_token_match = S7::new_property(
        S7::class_logical,
        default = TRUE
      ),
      userinfo_signed_jwt_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      id_token_required = S7::new_property(
        S7::class_logical,
        default = TRUE
      ),
      id_token_validation = S7::new_property(
        S7::class_logical,
        default = TRUE
      ),
      id_token_at_hash_required = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      tolerate_duplicate_top_level_jarm_iss = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      token_auth_style = S7::new_property(
        S7::class_character,
        default = "body"
      ),
      tls_client_certificate_bound_access_tokens = S7::new_property(
        S7::class_logical,
        default = FALSE
      ),
      jwks_pins = S7::new_property(
        S7::class_character,
        default = character()
      ),
      jwks_pin_mode = S7::new_property(
        S7::class_character,
        default = "any"
      ),
      jwks_host_issuer_match = S7::new_property(
        S7::class_logical,
        default = TRUE
      ),
      jwks_host_allow_only = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      allowed_algs = S7::new_property(
        S7::class_character,
        default = c("RS256", "ES256")
      ),
      allowed_token_types = S7::new_property(
        S7::class_character,
        default = c("Bearer")
      ),
      leeway = S7::new_property(S7::class_numeric, default = 30),
      mtls_endpoint_aliases = S7::new_property(
        S7::class_list,
        default = list()
      )
    )
  )

  strict <- DummyProvider(
    issuer = "https://issuer.example.com",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo"
  )
  loose <- DummyProvider(
    issuer = strict@issuer,
    auth_url = strict@auth_url,
    token_url = strict@token_url,
    userinfo_url = strict@userinfo_url,
    allowed_algs = "ES256"
  )
  tolerant_duplicate_iss <- DummyProvider(
    issuer = strict@issuer,
    auth_url = strict@auth_url,
    token_url = strict@token_url,
    userinfo_url = strict@userinfo_url,
    tolerate_duplicate_top_level_jarm_iss = TRUE
  )

  expect_false(identical(
    shinyOAuth:::provider_fingerprint(strict),
    shinyOAuth:::provider_fingerprint(loose)
  ))
  expect_false(identical(
    shinyOAuth:::provider_fingerprint(strict),
    shinyOAuth:::provider_fingerprint(tolerant_duplicate_iss)
  ))
})
