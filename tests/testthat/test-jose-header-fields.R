# Tests for shared JOSE header field validation across ID token and
# UserInfo JWT verification.

make_header_jwt <- function(header_json, claims) {
  payload_json <- jsonlite::toJSON(
    claims,
    auto_unbox = TRUE,
    null = "null",
    na = "null"
  )
  paste0(
    shinyOAuth:::base64url_encode(charToRaw(header_json)),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(as.character(payload_json))),
    "."
  )
}

make_id_token_header_client <- function() {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  cli@provider@id_token_validation <- TRUE
  cli@provider@allowed_algs <- "RS256"
  cli
}

make_userinfo_header_client <- function(require_signed = FALSE) {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    userinfo_signed_jwt_required = require_signed
  )
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@allowed_algs <- c("RS256", "ES256")
  cli
}

base_id_token_claims <- function() {
  now <- floor(as.numeric(Sys.time()))
  list(
    iss = "https://issuer.example.com",
    aud = "abc",
    sub = "user-1",
    iat = now - 1,
    exp = now + 120
  )
}

base_userinfo_claims <- function() {
  list(
    iss = "https://issuer.example.com",
    aud = "abc",
    sub = "user-1",
    name = "User One"
  )
}

get_userinfo_with_jwt <- function(cli, jwt_body) {
  testthat::with_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(jwt_body)
      )
    },
    .package = "shinyOAuth",
    get_userinfo(cli, token = "access-token")
  )
}

expect_id_token_header_error <- function(header_json, regexp) {
  cli <- make_id_token_header_client()
  jwt <- make_header_jwt(header_json, base_id_token_claims())

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  expect_error(
    shinyOAuth:::validate_id_token(cli, jwt),
    regexp = regexp,
    class = "shinyOAuth_id_token_error"
  )
}

expect_userinfo_header_error <- function(
  header_json,
  regexp,
  require_signed = FALSE
) {
  cli <- make_userinfo_header_client(require_signed = require_signed)
  jwt <- make_header_jwt(header_json, base_userinfo_claims())

  expect_error(
    get_userinfo_with_jwt(cli, jwt),
    regexp = regexp,
    class = "shinyOAuth_userinfo_error"
  )
}

test_that("validate_id_token rejects malformed JOSE header field shapes", {
  cases <- list(
    list(
      header_json = '{"alg":["RS256"]}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":["RS256","RS256"]}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":{"value":"RS256"}}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":""}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"typ":"JWT"}',
      regexp = "header missing alg"
    ),
    list(
      header_json = '{"alg":"RS256","kid":["kid-1","kid-1"]}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","kid":{"value":"kid-1"}}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","kid":""}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":["JWT","JWT"]}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":{"value":"JWT"}}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":""}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","crit":{"exp":true}}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp",""]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp",null]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp","exp"]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    )
  )

  for (case in cases) {
    expect_id_token_header_error(case$header_json, case$regexp)
  }
})

test_that("get_userinfo rejects malformed JOSE header field shapes", {
  cases <- list(
    list(
      header_json = '{"alg":["RS256"]}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":["RS256","RS256"]}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":{"value":"RS256"}}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":""}',
      regexp = "alg header must be a single non-empty string"
    ),
    list(
      header_json = '{"typ":"JWT"}',
      regexp = "header missing alg"
    ),
    list(
      header_json = '{"alg":"RS256","kid":["kid-1","kid-1"]}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","kid":{"value":"kid-1"}}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","kid":""}',
      regexp = "kid header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":["JWT","JWT"]}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":{"value":"JWT"}}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","typ":""}',
      regexp = "typ header must be a single non-empty string"
    ),
    list(
      header_json = '{"alg":"RS256","crit":{"exp":true}}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp",""]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp",null]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    ),
    list(
      header_json = '{"alg":"RS256","crit":["exp","exp"]}',
      regexp = "crit header must be a non-empty character vector of unique extension names"
    )
  )

  for (case in cases) {
    expect_userinfo_header_error(case$header_json, case$regexp)
  }
})

test_that("get_userinfo audits malformed JOSE header fields", {
  cli <- make_userinfo_header_client()
  jwt <- make_header_jwt('{"alg":["RS256"]}', base_userinfo_claims())
  events <- list()

  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  ))

  expect_error(
    get_userinfo_with_jwt(cli, jwt),
    regexp = "alg header must be a single non-empty string",
    class = "shinyOAuth_userinfo_error"
  )

  types <- vapply(
    events,
    function(event) event$type %||% NA_character_,
    character(1)
  )
  ui_events <- events[types == "audit_userinfo"]
  statuses <- vapply(
    ui_events,
    function(event) event$status %||% NA_character_,
    character(1)
  )
  expect_true("userinfo_jwt_header_invalid" %in% statuses)
})
