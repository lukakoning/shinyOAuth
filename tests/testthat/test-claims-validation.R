# Test claims_validation modes: "strict", "warn", "none"
# Validates that essential claims requested via the OIDC claims parameter
# (OIDC Core §5.5) are checked against returned ID token / userinfo.

# --- Unit tests for extract_essential_claims() --------------------------------

test_that("extract_essential_claims: extracts essential id_token claims from list", {
  claims <- list(
    id_token = list(
      auth_time = list(essential = TRUE),
      acr = list(values = c("urn:mace:incommon:iap:silver")),
      email = NULL
    ),
    userinfo = list(
      given_name = list(essential = TRUE),
      email = NULL
    )
  )

  result <- shinyOAuth:::extract_essential_claims(claims, "id_token")
  expect_equal(result, "auth_time")

  result <- shinyOAuth:::extract_essential_claims(claims, "userinfo")
  expect_equal(result, "given_name")
})

test_that("extract_essential_claims: returns empty for no essential claims", {
  claims <- list(
    id_token = list(
      email = NULL,
      acr = list(values = c("something"))
    )
  )

  result <- shinyOAuth:::extract_essential_claims(claims, "id_token")
  expect_equal(result, character(0))
})

test_that("extract_essential_claims: returns empty for NULL claims", {
  result <- shinyOAuth:::extract_essential_claims(NULL, "id_token")
  expect_equal(result, character(0))
})

test_that("extract_essential_claims: returns empty for missing target", {
  claims <- list(userinfo = list(email = list(essential = TRUE)))

  result <- shinyOAuth:::extract_essential_claims(claims, "id_token")
  expect_equal(result, character(0))
})

test_that("extract_essential_claims: handles JSON string input", {
  json <- '{"id_token":{"auth_time":{"essential":true},"sub":null}}'

  result <- shinyOAuth:::extract_essential_claims(json, "id_token")
  expect_equal(result, "auth_time")
})

test_that("extract_essential_claims: handles multiple essential claims", {
  claims <- list(
    id_token = list(
      auth_time = list(essential = TRUE),
      email = list(essential = TRUE),
      acr = list(values = c("something")),
      sub = NULL,
      nonce = list(essential = TRUE)
    )
  )

  result <- shinyOAuth:::extract_essential_claims(claims, "id_token")
  expect_equal(sort(result), sort(c("auth_time", "email", "nonce")))
})

test_that("extract_essential_claims: essential = FALSE is not essential", {
  claims <- list(
    id_token = list(
      auth_time = list(essential = FALSE)
    )
  )

  result <- shinyOAuth:::extract_essential_claims(claims, "id_token")
  expect_equal(result, character(0))
})

# --- Unit tests for validate_essential_claims() -------------------------------

test_that("validate_essential_claims: 'none' mode skips validation entirely", {
  cli <- make_test_client(
    claims = list(
      id_token = list(auth_time = list(essential = TRUE))
    ),
    claims_validation = "none"
  )

  # Should not error or warn even when essential claims are missing
  result <- NULL
  warned <- FALSE
  result <- withCallingHandlers(
    tryCatch(
      shinyOAuth:::validate_essential_claims(
        cli,
        list(sub = "user1"),
        "id_token"
      ),
      error = function(e) {
        NULL
      }
    ),
    warning = function(w) {
      warned <<- TRUE
      invokeRestart("muffleWarning")
    }
  )
  expect_false(warned)
})

test_that("validate_essential_claims: 'strict' mode errors on missing essential id_token claims", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE),
        email = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  # Both claims missing

  expect_error(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1"),
      "id_token"
    ),
    class = "shinyOAuth_id_token_error"
  )
})

test_that("validate_essential_claims: 'strict' mode errors on missing essential userinfo claims", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        given_name = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  expect_error(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1", email = "a@b.c"),
      "userinfo"
    ),
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("validate_essential_claims: 'strict' mode passes when all essential claims present", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE),
        email = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  # Should not error
  expect_no_error(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1", auth_time = 1234567890, email = "a@b.c"),
      "id_token"
    )
  )
})

test_that("validate_essential_claims: 'warn' mode warns on missing essential claims", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    ),
    claims_validation = "warn"
  )

  # Reset frequency so the warning fires
  rlang::reset_warning_verbosity("claims-validation-missing-id_token")

  expect_warning(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1"),
      "id_token"
    ),
    regexp = "Essential claims missing"
  )
})

test_that("validate_essential_claims: 'warn' mode does not error", {
  cli <- make_test_client(
    claims = list(
      userinfo = list(
        given_name = list(essential = TRUE)
      )
    ),
    claims_validation = "warn"
  )

  rlang::reset_warning_verbosity("claims-validation-missing-userinfo")

  expect_no_error(
    suppressWarnings(
      shinyOAuth:::validate_essential_claims(
        cli,
        list(sub = "user1"),
        "userinfo"
      )
    )
  )
})

test_that("validate_essential_claims: skips when no essential claims in spec", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        email = NULL,
        acr = list(values = c("something"))
      )
    ),
    claims_validation = "strict"
  )

  # No essential claims requested -> should not error even in strict mode
  expect_no_error(
    shinyOAuth:::validate_essential_claims(cli, list(sub = "user1"), "id_token")
  )
})

test_that("validate_essential_claims: skips when client has no claims", {
  cli <- make_test_client(
    claims = NULL,
    claims_validation = "strict"
  )

  # No claims at all -> nothing to validate
  expect_no_error(
    shinyOAuth:::validate_essential_claims(cli, list(sub = "user1"), "id_token")
  )
})

test_that("validate_essential_claims: error message lists missing claims", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE),
        acr = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  err <- tryCatch(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1"),
      "id_token"
    ),
    error = function(e) e
  )

  expect_s3_class(err, "shinyOAuth_id_token_error")
  expect_match(conditionMessage(err), "auth_time")
  expect_match(conditionMessage(err), "acr")
})

test_that("validate_essential_claims: partially present essential claims", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE),
        email = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  # auth_time present, email missing
  expect_error(
    shinyOAuth:::validate_essential_claims(
      cli,
      list(sub = "user1", auth_time = 12345),
      "id_token"
    ),
    regexp = "email"
  )
})

# --- Integration tests via handle_callback() ----------------------------------

test_that("claims_validation = 'strict' errors during handle_callback for missing ID token essential claims", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Mock token exchange returning an ID token without auth_time
  # We need id_token_validation = FALSE so it doesn't fail on signature
  # Create a minimal JWT payload without auth_time
  # Note: gsub removes newlines that jsonlite::base64url_enc may insert
  header <- gsub(
    "\n",
    "",
    jsonlite::base64url_enc(
      jsonlite::toJSON(list(alg = "none", typ = "JWT"), auto_unbox = TRUE)
    )
  )
  payload <- gsub(
    "\n",
    "",
    jsonlite::base64url_enc(
      jsonlite::toJSON(
        list(
          sub = "user1",
          iss = "https://example.com",
          aud = "abc",
          exp = as.numeric(Sys.time()) + 3600,
          iat = as.numeric(Sys.time())
        ),
        auto_unbox = TRUE
      )
    )
  )
  fake_jwt <- paste(header, payload, "", sep = ".")

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "t",
          token_type = "Bearer",
          id_token = fake_jwt,
          expires_in = 3600
        )
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    class = "shinyOAuth_id_token_error"
  )
})

test_that("claims_validation = 'none' does not error for missing ID token essential claims in handle_callback", {
  cli <- make_test_client(
    claims = list(
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    ),
    claims_validation = "none"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  header <- gsub(
    "\n",
    "",
    jsonlite::base64url_enc(
      jsonlite::toJSON(list(alg = "none", typ = "JWT"), auto_unbox = TRUE)
    )
  )
  payload <- gsub(
    "\n",
    "",
    jsonlite::base64url_enc(
      jsonlite::toJSON(
        list(
          sub = "user1",
          iss = "https://example.com",
          aud = "abc",
          exp = as.numeric(Sys.time()) + 3600,
          iat = as.numeric(Sys.time())
        ),
        auto_unbox = TRUE
      )
    )
  )
  fake_jwt <- paste(header, payload, "", sep = ".")

  result <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "my_access_token",
        token_type = "Bearer",
        id_token = fake_jwt,
        expires_in = 3600
      )
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    )
  )

  expect_true(S7::S7_inherits(result, OAuthToken))
  expect_equal(result@access_token, "my_access_token")
})

# --- OAuthClient validation ---------------------------------------------------

test_that("claims_validation defaults to 'none'", {
  cli <- make_test_client()
  expect_equal(cli@claims_validation, "none")
})

test_that("invalid claims_validation value is rejected by oauth_client()", {
  expect_error(
    make_test_client(claims_validation = "invalid")
  )
})

test_that("claims_validation accepts 'strict', 'warn', 'none'", {
  for (mode in c("strict", "warn", "none")) {
    cli <- make_test_client(claims_validation = mode)
    expect_equal(cli@claims_validation, mode)
  }
})
