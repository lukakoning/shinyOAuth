make_host_policy_rsa_jwk <- local({
  base_jwk <- NULL

  function(kid = "k1") {
    if (is.null(base_jwk)) {
      key <- openssl::rsa_keygen(bits = 2048)
      jwk <- jsonlite::fromJSON(jose::write_jwk(key), simplifyVector = TRUE)
      base_jwk <<- list(kty = jwk$kty, n = jwk$n, e = jwk$e)
    }

    c(base_jwk, list(kid = kid))
  }
})

test_that("jwks_cache_key varies with host-policy fields", {
  issuer <- "https://issuer.example.com"

  # Baseline: no host-policy
  k_base <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any"
  )

  # With jwks_host_issuer_match = TRUE
  k_match <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = TRUE
  )

  # With jwks_host_allow_only set

  k_allow <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_allow_only = "keys.example.com"
  )

  # With both
  k_both <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = TRUE,
    jwks_host_allow_only = "keys.example.com"
  )

  # All four must be distinct
  all_keys <- c(k_base, k_match, k_allow, k_both)
  expect_equal(length(unique(all_keys)), 4L)

  # Default args should match explicit FALSE / NA
  k_explicit_defaults <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = FALSE,
    jwks_host_allow_only = NA_character_
  )
  expect_identical(k_base, k_explicit_defaults)
})

test_that("jwks_cache_key varies with discovery issuer policy", {
  issuer <- "https://issuer.example.com"

  k_url <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    issuer_match = "url"
  )
  k_host <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    issuer_match = "host"
  )
  k_none <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    issuer_match = "none"
  )

  expect_equal(length(unique(c(k_url, k_host, k_none))), 3L)
})

test_that("jwks_cache_key is case-insensitive for jwks_host_allow_only", {
  issuer <- "https://issuer.example.com"
  k_lower <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_allow_only = "keys.example.com"
  )
  k_upper <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_allow_only = "KEYS.EXAMPLE.COM"
  )
  expect_identical(k_lower, k_upper)
})

test_that("different host policies produce separate cache entries preventing cross-policy reuse", {
  # This test verifies that two provider configs for the same issuer with

  # different host policies get different cache keys, so a cached JWKS from a
  # relaxed-policy provider cannot be served to a strict-policy provider.
  issuer <- "https://issuer.example.com"
  cache <- cachem::cache_mem(max_age = 3600)

  rsa_jwk <- make_host_policy_rsa_jwk(kid = "k1")
  jwks <- list(keys = list(rsa_jwk))

  # Simulate a relaxed provider storing a JWKS entry
  k_relaxed <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = FALSE
  )
  cache$set(
    k_relaxed,
    list(
      jwks = jwks,
      fetched_at = as.numeric(Sys.time()),
      jwks_uri_host = "evil.example.com"
    )
  )

  # A strict provider (jwks_host_issuer_match = TRUE) should not find this entry
  k_strict <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = TRUE
  )
  expect_false(identical(k_relaxed, k_strict))
  expect_null(cache$get(k_strict, missing = NULL))

  # Likewise, a provider with jwks_host_allow_only should have its own key
  k_pinned_host <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_allow_only = "keys.example.com"
  )
  expect_false(identical(k_relaxed, k_pinned_host))
  expect_null(cache$get(k_pinned_host, missing = NULL))
})

test_that("fetch_jwks stores jwks_uri_host in cache entry", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  rsa_jwk <- make_host_policy_rsa_jwk(kid = "k1")
  good_jwks <- list(keys = list(rsa_jwk))

  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    host <- req$headers$Host %||% req$headers$host
    jwks_url <- paste0("http://", host, "/jwks")
    res$send_json(
      object = list(
        issuer = paste0("http://", host),
        jwks_uri = jwks_url
      ),
      auto_unbox = TRUE
    )
  })
  app$get("/jwks", function(req, res) {
    res$send_json(object = good_jwks, auto_unbox = TRUE)
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  cache <- cachem::cache_mem(max_age = 3600)
  shinyOAuth:::fetch_jwks(
    issuer = base,
    jwks_cache = cache,
    pins = NULL,
    pin_mode = "any"
  )

  cache_key <- shinyOAuth:::jwks_cache_key(base, pins = NULL, pin_mode = "any")
  entry <- cache$get(cache_key, missing = NULL)
  expect_false(is.null(entry))
  expect_false(is.null(entry$jwks_uri_host))
  expect_true(is.character(entry$jwks_uri_host))
  expect_true(nzchar(entry$jwks_uri_host))
})

test_that("fetch_jwks rejects discovery issuer mismatch by default", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  rsa_jwk <- make_host_policy_rsa_jwk(kid = "k1")
  good_jwks <- list(keys = list(rsa_jwk))

  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    host <- req$headers$Host %||% req$headers$host
    jwks_url <- paste0("http://", host, "/jwks")
    res$send_json(
      object = list(
        issuer = "https://accounts.example.com/tenant-b",
        jwks_uri = jwks_url
      ),
      auto_unbox = TRUE
    )
  })
  app$get("/jwks", function(req, res) {
    res$send_json(object = good_jwks, auto_unbox = TRUE)
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  cache <- cachem::cache_mem(max_age = 3600)
  expect_error(
    shinyOAuth:::fetch_jwks(
      issuer = base,
      jwks_cache = cache,
      pins = NULL,
      pin_mode = "any"
    ),
    class = "shinyOAuth_config_error",
    regexp = "issuer mismatch"
  )
})

test_that("fetch_jwks honors provider issuer_match policy", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  rsa_jwk <- make_host_policy_rsa_jwk(kid = "k1")
  good_jwks <- list(keys = list(rsa_jwk))

  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    host <- req$headers$Host %||% req$headers$host
    base <- paste0("http://", host)
    res$send_json(
      object = list(
        issuer = paste0(base, "/tenant-b"),
        jwks_uri = paste0(base, "/jwks")
      ),
      auto_unbox = TRUE
    )
  })
  app$get("/jwks", function(req, res) {
    res$send_json(object = good_jwks, auto_unbox = TRUE)
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  provider <- oauth_provider(
    name = "host-only-discovery",
    auth_url = paste0(base, "/authorize"),
    token_url = paste0(base, "/token"),
    issuer = base,
    issuer_match = "host",
    jwks_host_issuer_match = FALSE
  )

  cache <- cachem::cache_mem(max_age = 3600)
  jwks <- shinyOAuth:::fetch_jwks(
    issuer = base,
    jwks_cache = cache,
    pins = NULL,
    pin_mode = "any",
    provider = provider
  )

  expect_identical(jwks, good_jwks)
})

test_that("fetch_jwks evicts cache entry when stored host fails host-policy re-validation", {
  # Simulate a scenario where a cache entry was stored with a host that
  # doesn't match the current provider's strict host policy.
  # This is the defense-in-depth re-validation on cache read.
  issuer <- "https://issuer.example.com"
  cache <- cachem::cache_mem(max_age = 3600)

  rsa_jwk <- make_host_policy_rsa_jwk(kid = "k1")
  jwks <- list(keys = list(rsa_jwk))

  # Create a strict provider
  prov_strict <- oauth_provider(
    name = "t",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    jwks_host_issuer_match = TRUE
  )

  # Compute the cache key for this strict provider config
  cache_key <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any",
    jwks_host_issuer_match = TRUE
  )

  # Manually seed cache with a JWKS that was allegedly fetched from a
  # non-matching host (simulating a corrupted/injected entry)
  cache$set(
    cache_key,
    list(
      jwks = jwks,
      fetched_at = as.numeric(Sys.time()),
      jwks_uri_host = "evil.example.com"
    )
  )

  # Verify the entry exists
  expect_false(is.null(cache$get(cache_key, missing = NULL)))

  # Calling fetch_jwks with this strict provider should detect the host
  # mismatch on the cached entry and evict it. Since the fresh fetch will
  # also fail (no real server), we expect an error — but the cache entry
  # should be evicted.
  expect_error(
    shinyOAuth:::fetch_jwks(
      issuer = issuer,
      jwks_cache = cache,
      pins = NULL,
      pin_mode = "any",
      provider = prov_strict
    )
  )

  # Cache entry was evicted
  expect_null(cache$get(cache_key, missing = NULL))
})
