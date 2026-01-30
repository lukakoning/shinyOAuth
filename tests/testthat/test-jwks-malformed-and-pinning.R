test_that("fetch_jwks does not cache on invalid JSON", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  app <- webfakes::new_app()
  base <- NULL
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$send_json(
      object = list(jwks_uri = paste0(base, "/jwks")),
      auto_unbox = TRUE
    )
  })
  app$get("/jwks", function(req, res) {
    res$status <- 200
    res$set_type("text/plain")
    res$send("not json")
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  cache <- cachem::cache_mem(max_age = 3600)
  cache_key <- shinyOAuth:::jwks_cache_key(base, pins = NULL, pin_mode = "any")
  expect_null(cache$get(cache_key, missing = NULL))

  expect_error(
    shinyOAuth:::fetch_jwks(
      issuer = base,
      jwks_cache = cache,
      pins = NULL,
      pin_mode = "any"
    )
  )

  # Ensure cache wasn't populated on parse failure
  expect_null(cache$get(cache_key, missing = NULL))
})

test_that("validate_jwks_host_matches_issuer enforces policy only when configured", {
  # Default relaxed: no error
  expect_no_error(shinyOAuth:::validate_jwks_host_matches_issuer(
    issuer = "https://issuer.example.com",
    jwks_uri = "https://evil.example.com/jwks"
  ))
  # Strict check: must match issuer host or subdomain
  prov_strict <- oauth_provider(
    name = "t",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    jwks_host_issuer_match = TRUE
  )
  expect_no_error(shinyOAuth:::validate_jwks_host_matches_issuer(
    issuer = "https://issuer.example.com",
    jwks_uri = "https://issuer.example.com/.well-known/jwks.json",
    provider = prov_strict
  ))
  expect_no_error(shinyOAuth:::validate_jwks_host_matches_issuer(
    issuer = "https://issuer.example.com",
    jwks_uri = "https://sub.issuer.example.com/jwks",
    provider = prov_strict
  ))
  expect_error(
    shinyOAuth:::validate_jwks_host_matches_issuer(
      issuer = "https://issuer.example.com",
      jwks_uri = "https://evil.example.com/jwks",
      provider = prov_strict
    ),
    class = "shinyOAuth_config_error"
  )
  # Pinned host takes precedence
  prov_pinned <- oauth_provider(
    name = "t",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    jwks_host_allow_only = "keys.example.com"
  )
  expect_error(
    shinyOAuth:::validate_jwks_host_matches_issuer(
      issuer = "https://issuer.example.com",
      jwks_uri = "https://evil.example.com/jwks",
      provider = prov_pinned
    ),
    class = "shinyOAuth_config_error"
  )
  expect_no_error(shinyOAuth:::validate_jwks_host_matches_issuer(
    issuer = "https://issuer.example.com",
    jwks_uri = "https://keys.example.com/jwks",
    provider = prov_pinned
  ))
})


test_that("fetch_jwks evicts poisoned cache on pin mismatch even if refetch fails", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  # Good JWKS the server will return
  good_rsa <- list(kty = "RSA", n = "n-good", e = "AQAB", kid = "good")
  good_jwks <- list(keys = list(good_rsa))
  good_pin <- shinyOAuth:::compute_jwk_thumbprint(good_rsa)

  app <- webfakes::new_app()
  # Make discovery fail fast with 500 to simulate network/refetch failure
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$status <- 500
    res$set_type("application/json")
    res$send(jsonlite::toJSON(list(error = "boom"), auto_unbox = TRUE))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  cache <- cachem::cache_mem(max_age = 3600)
  # Compute cache key for the current pins/pin_mode
  ckey <- shinyOAuth:::jwks_cache_key(base, pins = good_pin, pin_mode = "any")

  # Seed cache with a poisoned JWKS that won't match the pin
  bad_rsa <- list(kty = "RSA", n = "n-bad", e = "AQAB", kid = "bad")
  bad_jwks <- list(keys = list(bad_rsa))
  cache$set(ckey, list(jwks = bad_jwks, fetched_at = as.numeric(Sys.time())))

  # Now call fetch_jwks: it should notice the pin mismatch and evict the cache entry
  expect_error(
    shinyOAuth:::fetch_jwks(
      issuer = base,
      jwks_cache = cache,
      pins = good_pin,
      pin_mode = "any"
    )
  )

  # Ensure entry was evicted despite refetch failure
  expect_null(cache$get(ckey, missing = NULL))
})
