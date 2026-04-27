## Integration tests: Keycloak PKCE authorization-code flow
##
## Goal: Demonstrate that PKCE is enforced for the public client and that tampering
## with the stored code_verifier (missing or incorrect) breaks the flow.
##
## We exercise three scenarios against the imported realm:
## 1. Happy path: public client `shiny-public` completes code flow with PKCE (S256)
## 2. Unhappy path: code_verifier removed from state store prior to callback
## 3. Unhappy path: code_verifier replaced with a different valid verifier (mismatch)
##
## Proof PKCE works: scenarios (2) and (3) fail while (1) succeeds.
## (2) fails locally before token exchange (state validation); (3) fails during token exchange
## with server-side rejection (invalid_grant) surfaced as an HTTP/token error.
##
## These tests follow the pattern used in `test_integration_keycloak_code_jwt_auth.R` to
## drive the login form headlessly (no browser) and capture the authorization code.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_provider <- function() {
  prov <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  prov@par_url <- NA_character_
  prov
}

testthat::test_that("Keycloak PKCE happy path (public client)", {
  skip_common()
  local_test_options()
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))
      res <- perform_login_form(url, redirect_uri = client@redirect_uri)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      # Assertions
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))
      testthat::expect_true(prov@use_pkce) # Provider PKCE enabled
    }
  )
})

testthat::test_that("Keycloak PKCE unhappy path: missing code_verifier", {
  skip_common()
  local_test_options()
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      state <- get_state_store_entry(client, url)
      orig <- state$entry
      testthat::expect_true(is.list(orig))
      client@state_store$set(
        key = state$info$key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = NULL,
          nonce = orig$nonce
        )
      )
      res <- perform_login_form(url, redirect_uri = client@redirect_uri)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      # Error description should mention PKCE/code verifier
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "code verifier|PKCE",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Keycloak PKCE unhappy path: wrong code_verifier", {
  skip_common()
  local_test_options()
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      state <- get_state_store_entry(client, url)
      orig <- state$entry
      testthat::expect_true(is.list(orig))
      new_ver <- orig$pkce_code_verifier
      for (i in 1:5) {
        cand <- paste0(
          sample(c(letters, LETTERS, 0:9, '-', '_', '.', '~'), 64, TRUE),
          collapse = ''
        )
        if (!identical(cand, new_ver)) {
          new_ver <- cand
          break
        }
      }
      client@state_store$set(
        key = state$info$key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = new_ver,
          nonce = orig$nonce
        )
      )
      res <- perform_login_form(url, redirect_uri = client@redirect_uri)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      # Should reference token exchange or HTTP failure; be tolerant of wording
      testthat::expect_true(grepl(
        "Token exchange failed|invalid_grant|http_",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})
