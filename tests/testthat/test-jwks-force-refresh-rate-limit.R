test_that("Unknown kid triggers at most one forced JWKS refresh per interval", {
  testthat::skip_if_not_installed("jose")

  now <- as.numeric(Sys.time())
  base <- "http://localhost"

  # Generate an RSA key pair and a public JWK that will be returned by the mocked JWKS fetch.
  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
  pub_jwk$kid <- "rsa-1"

  # Configure provider/client with an in-memory jwks_cache so the rate-limit state persists
  # across repeated validations.
  prov <- oauth_provider(
    name = "local",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("RS256"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "c1",
    client_secret = "ignore",
    redirect_uri = paste0(base, "/cb")
  )

  # Create a token whose header kid does not exist in the (mocked) JWKS.
  id_token <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = base,
      aud = "c1",
      sub = "u",
      exp = now + 120,
      iat = now - 1
    ),
    key = rsa,
    header = list(alg = "RS256", kid = "unknown-kid-1", typ = "JWT")
  )

  force_refresh_true <- 0L
  total_fetches <- 0L

  testthat::with_mocked_bindings(
    fetch_jwks = function(
      issuer,
      jwks_cache,
      force_refresh = FALSE,
      pins = NULL,
      pin_mode = c("any", "all"),
      provider = NULL
    ) {
      total_fetches <<- total_fetches + 1L
      if (isTRUE(force_refresh)) {
        force_refresh_true <<- force_refresh_true + 1L
      }
      list(keys = list(pub_jwk))
    },
    .package = "shinyOAuth",
    {
      # First call: allowed to force-refresh once, then errors with no matching kid.
      expect_error(
        shinyOAuth:::validate_id_token(cli, id_token),
        class = "shinyOAuth_id_token_error",
        regexp = "No JWKS key matches kid"
      )

      # Second call immediately: forced refresh should be rate-limited.
      expect_error(
        shinyOAuth:::validate_id_token(cli, id_token),
        class = "shinyOAuth_id_token_error",
        regexp = "rate-limited"
      )
    }
  )

  expect_identical(force_refresh_true, 1L)
  expect_gte(total_fetches, 3L)
})

test_that("shared JWKS refresh throttling uses an atomic claim", {
  claimed <- FALSE
  get_calls <- 0L
  set_calls <- 0L
  seen_ttl <- NULL
  cache <- list(
    get = function(key, missing = NULL) {
      get_calls <<- get_calls + 1L
      missing
    },
    set = function(key, value) {
      set_calls <<- set_calls + 1L
      invisible(NULL)
    },
    set_if_absent = function(key, value, ttl = NULL) {
      seen_ttl <<- ttl
      if (claimed) {
        return(FALSE)
      }
      claimed <<- TRUE
      TRUE
    }
  )

  allowed <- function() shinyOAuth:::jwks_force_refresh_allowed(
    issuer = "https://issuer.example.com",
    jwks_cache = cache,
    min_interval = 30,
    now = 100
  )

  expect_true(allowed())
  expect_false(allowed())
  expect_identical(seen_ttl, 30)
  expect_identical(get_calls, 0L)
  expect_identical(set_calls, 0L)
})

test_that("shared JWKS refresh throttling fails closed without atomic claim", {
  cache <- list(
    get = function(...) stop("non-atomic get must not be used"),
    set = function(...) stop("non-atomic set must not be used")
  )

  expect_false(shinyOAuth:::jwks_force_refresh_allowed(
    issuer = "https://issuer.example.com",
    jwks_cache = cache,
    min_interval = 30,
    now = 100
  ))
})
