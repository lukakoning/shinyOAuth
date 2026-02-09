# Tests for OIDC claims request parameter support (OIDC Core §5.5)

# Helper: parse query parameter from URL
parse_query_param <- function(url, name, decode = FALSE) {
  parsed <- httr2::url_parse(url)
  val <- parsed$query[[name]]
  if (is.null(val)) {
    return(NULL)
  }
  if (isTRUE(decode)) {
    val <- utils::URLdecode(val)
  }
  val
}

# ---- Validation tests ------------------------------------------------------

test_that("OAuthClient accepts NULL claims (default)", {
  prov <- make_test_provider()
  expect_no_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = NULL
    )
  )
})

test_that("OAuthClient accepts list claims", {
  prov <- make_test_provider()
  expect_no_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = list(
        userinfo = list(
          email = NULL,
          given_name = list(essential = TRUE)
        )
      )
    )
  )
})

test_that("OAuthClient accepts pre-encoded JSON string claims", {
  prov <- make_test_provider()
  json_claims <- '{"userinfo":{"email":null,"given_name":{"essential":true}}}'
  expect_no_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = json_claims
    )
  )
})

test_that("OAuthClient rejects invalid claims (not list, character, or NULL)", {
  prov <- make_test_provider()
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = 123
    ),
    regexp = "claims must be NULL, a list, or a character string"
  )
})

test_that("OAuthClient rejects empty character string claims", {
  prov <- make_test_provider()
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = ""
    ),
    regexp = "claims must be a single non-empty character string"
  )
})

test_that("OAuthClient rejects character vector with multiple elements", {
  prov <- make_test_provider()
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = c("{}", "{}")
    ),
    regexp = "claims must be a single non-empty character string"
  )
})

test_that("OAuthClient rejects invalid JSON string claims", {
  prov <- make_test_provider()
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "test-id",
      client_secret = "test-secret",
      redirect_uri = "http://localhost:8100",
      claims = "{not valid json"
    ),
    regexp = "claims provided as character must be valid JSON"
  )
})

# ---- OAuthProvider extra_auth_params blocking ------------------------------

test_that("OAuthProvider rejects claims in extra_auth_params", {
  expect_error(
    oauth_provider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(claims = "{}")
    ),
    regexp = "extra_auth_params must not contain reserved keys.*claims"
  )
})

# ---- build_auth_url integration tests --------------------------------------

test_that("build_auth_url omits claims parameter when claims is NULL", {
  cli <- make_test_client(claims = NULL)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims")
  expect_null(claims_val)
})

test_that("build_auth_url includes JSON-encoded claims when claims is a list", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        email = NULL,
        given_name = list(essential = TRUE)
      ),
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  expect_true(!is.null(claims_val))
  expect_true(nzchar(claims_val))

  # Parse the JSON and verify structure
  claims_parsed <- jsonlite::fromJSON(claims_val)
  expect_true("userinfo" %in% names(claims_parsed))
  expect_true("id_token" %in% names(claims_parsed))
  expect_true("email" %in% names(claims_parsed$userinfo))
  expect_true("given_name" %in% names(claims_parsed$userinfo))
  expect_equal(claims_parsed$userinfo$given_name$essential, TRUE)
  expect_equal(claims_parsed$id_token$auth_time$essential, TRUE)
})

test_that("build_auth_url preserves explicit nulls in claims list", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        email = NULL,
        picture = NULL
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  # Per OIDC spec, null values request the claim without additional parameters
  claims_parsed <- jsonlite::fromJSON(claims_val)
  expect_true("email" %in% names(claims_parsed$userinfo))
  expect_true("picture" %in% names(claims_parsed$userinfo))
  # jsonlite should preserve null
  expect_null(claims_parsed$userinfo$email)
  expect_null(claims_parsed$userinfo$picture)
})

test_that("build_auth_url uses pre-encoded JSON string claims as-is", {
  json_claims <- '{"userinfo":{"email":null}}'
  cli <- make_test_client(claims = json_claims)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  expect_equal(claims_val, json_claims)
})

test_that("build_auth_url handles complex claims with essential and values", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        email = list(essential = TRUE),
        email_verified = list(essential = TRUE)
      ),
      id_token = list(
        acr = list(
          values = c(
            "urn:mace:incommon:iap:silver",
            "urn:mace:incommon:iap:bronze"
          )
        )
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  claims_parsed <- jsonlite::fromJSON(claims_val)
  expect_equal(claims_parsed$userinfo$email$essential, TRUE)
  expect_equal(claims_parsed$userinfo$email_verified$essential, TRUE)
  expect_true("acr" %in% names(claims_parsed$id_token))
  expect_true("values" %in% names(claims_parsed$id_token$acr))
  expect_equal(
    claims_parsed$id_token$acr$values,
    c("urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze")
  )
})

test_that("build_auth_url handles custom claims with URI identifiers", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        "http://example.info/claims/groups" = NULL
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  claims_parsed <- jsonlite::fromJSON(claims_val)
  expect_true(
    "http://example.info/claims/groups" %in% names(claims_parsed$userinfo)
  )
})

# ---- End-to-end scenario test ----------------------------------------------

test_that("claims parameter survives URL encoding/decoding round-trip", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        email = NULL,
        given_name = list(essential = TRUE)
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)

  # Parse the URL and extract claims
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  # Re-encode and decode to verify round-trip stability
  re_encoded <- utils::URLencode(claims_val, reserved = TRUE)
  re_decoded <- utils::URLdecode(re_encoded)

  expect_equal(re_decoded, claims_val)

  # Verify JSON is still valid after round-trip
  expect_no_error(jsonlite::fromJSON(re_decoded))
})

# ---- auto_unbox edge case: I() preserves single-element arrays ---------------

test_that("I() forces array encoding for single-element values field", {
  # Per OIDC Core §5.5.1, values is always an array. auto_unbox = TRUE
  # collapses single-element vectors to scalars; I() prevents this.
  cli <- make_test_client(
    claims = list(
      id_token = list(
        acr = list(values = I("urn:mace:incommon:iap:silver"))
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  # The raw JSON should contain an array, not a scalar
  expect_true(grepl('\\["urn:mace:incommon:iap:silver"\\]', claims_val))

  claims_parsed <- jsonlite::fromJSON(claims_val)
  expect_equal(
    claims_parsed$id_token$acr$values,
    "urn:mace:incommon:iap:silver"
  )
})

test_that("single-element values without I() becomes scalar (expected)", {
  # Without I(), auto_unbox produces a scalar — user should be aware
  cli <- make_test_client(
    claims = list(
      id_token = list(
        acr = list(values = "urn:mace:incommon:iap:silver")
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)

  # The raw JSON will contain a scalar string, not an array
  expect_true(grepl('"values":"urn:mace:incommon:iap:silver"', claims_val))
})

# ---- Spec example from OIDC Core §5.5 ----------------------------------------

test_that("full spec example from OIDC Core §5.5 encodes correctly", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        given_name = list(essential = TRUE),
        nickname = NULL,
        email = list(essential = TRUE),
        email_verified = list(essential = TRUE),
        picture = NULL,
        "http://example.info/claims/groups" = NULL
      ),
      id_token = list(
        auth_time = list(essential = TRUE),
        acr = list(values = I("urn:mace:incommon:iap:silver"))
      )
    )
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  claims_val <- parse_query_param(url, "claims", decode = TRUE)
  claims_parsed <- jsonlite::fromJSON(claims_val)

  # Verify all userinfo claims present
  expect_setequal(
    names(claims_parsed$userinfo),
    c(
      "given_name",
      "nickname",
      "email",
      "email_verified",
      "picture",
      "http://example.info/claims/groups"
    )
  )
  # essential = TRUE preserved
  expect_true(claims_parsed$userinfo$given_name$essential)
  expect_true(claims_parsed$userinfo$email$essential)
  # null claims preserved
  expect_null(claims_parsed$userinfo$nickname)
  expect_null(claims_parsed$userinfo$picture)
  # id_token claims
  expect_true(claims_parsed$id_token$auth_time$essential)
  # values as array (via I())
  expect_equal(
    claims_parsed$id_token$acr$values,
    "urn:mace:incommon:iap:silver"
  )
})
