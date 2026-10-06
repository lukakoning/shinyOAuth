test_that("JWKS cache identity follows the combined global and local TLS floor", {
  local_options(shinyOAuth.tls_min_version = NULL)
  key <- function(minimum = NULL) {
    jwks_cache_key("https://ehr.example", tls_minimum = minimum)
  }
  backend_default <- key()
  tls12 <- key("1.2")
  tls13 <- key("1.3")
  expect_length(unique(c(backend_default, tls12, tls13)), 3L)
  options(shinyOAuth.tls_min_version = "1.2")
  expect_identical(key(), tls12)
  expect_identical(key("1.2"), tls12)
  expect_identical(key("1.3"), tls13)
  options(shinyOAuth.tls_min_version = "1.3")
  expect_identical(key(), tls13)
  expect_identical(key("1.2"), tls13)
  expect_identical(key("1.3"), tls13)
  options(shinyOAuth.tls_min_version = "invalid")
  expect_error(key(), class = "shinyOAuth_config_error")
  expect_error(key("1.3"), class = "shinyOAuth_config_error")
})

for (smart in c(FALSE, TRUE)) {
  test_that(
    paste("TLS tightening isolates JWKS reuse and refresh throttles; SMART =", smart),
    {
      local_options(shinyOAuth.tls_min_version = "1.2")
      client <- smart_client(
        smart_client_fixture(oidc = TRUE),
        "app",
        "https://app.example/callback",
        character(),
        identity = "fhirUser"
      )
      if (!smart) {
        client <- oauth_client(
          client@provider,
          client_id = "app",
          client_secret = character(),
          redirect_uri = "https://app.example/callback",
          scopes = "openid"
        )
      }
      issuer <- client@provider@issuer
      cache <- client@provider@jwks_cache
      key <- openssl::rsa_keygen(2048)
      jwk <- jsonlite::fromJSON(
        write_test_jwk(key[["pubkey"]]),
        simplifyVector = FALSE
      )
      jwk[["kid"]] <- "old-policy-key"
      current <- list(keys = list(jwk))
      requests <- list()
      local_mocked_bindings(
        req_with_retry = function(req, ...) {
          requests[[length(requests) + 1L]] <<- req
          httr2::response(
            url = req[["url"]],
            status = 200L,
            headers = list(
              "content-type" = "application/json",
              "cache-control" = "max-age=3600",
              date = format(Sys.time(), "%a, %d %b %Y %H:%M:%S GMT", tz = "UTC")
            ),
            body = charToRaw(jsonlite::toJSON(current, auto_unbox = TRUE))
          )
        }
      )
      fetch <- function() {
        fetch_client_jwks(client, issuer, cache, provider = client@provider)
      }
      refresh <- function() {
        force_refresh_client_jwks(
          client,
          issuer,
          cache,
          provider = client@provider,
          min_interval = 30
        )
      }
      captured <- capture_async_options()
      expect_identical(fetch()[["keys"]][[1]][["kid"]], "old-policy-key")
      expect_identical(fetch()[["keys"]][[1]][["kid"]], "old-policy-key")
      expect_length(requests, 1L)
      expect_false(is.null(refresh()))
      expect_null(refresh())
      expect_length(requests, 2L)

      options(shinyOAuth.tls_min_version = "1.3")
      current[["keys"]][[1]][["kid"]] <- "new-policy-key"
      expect_identical(fetch()[["keys"]][[1]][["kid"]], "new-policy-key")
      expect_identical(fetch()[["keys"]][[1]][["kid"]], "new-policy-key")
      expect_length(requests, 3L)
      expect_false(is.null(refresh()))
      expect_null(refresh())
      expect_length(requests, 4L)
      expect_identical(
        vapply(requests, function(req) req[["options"]][["sslversion"]], integer(1)),
        c(6L, 6L, 7L, 7L)
      )

      # A pending transaction with the captured older policy retains its own
      # cache and throttle entries without contaminating the stronger policy.
      with_async_options(captured, {
        expect_identical(fetch()[["keys"]][[1]][["kid"]], "old-policy-key")
        expect_null(refresh())
      })
      expect_identical(getOption("shinyOAuth.tls_min_version"), "1.3")
      expect_identical(fetch()[["keys"]][[1]][["kid"]], "new-policy-key")
      expect_length(requests, 4L)
    }
  )
}
