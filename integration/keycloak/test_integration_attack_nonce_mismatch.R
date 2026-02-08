## Attack vector: Nonce Mismatch / Replay
##
## Verifies that tampering with the nonce stored in the state store causes
## ID token validation to fail (nonce claim mismatch).
## Defense mechanisms tested:
##   1. Nonce is embedded in the ID token by the IdP and must match the
##      value stored in the state store during validation.
##   2. Missing nonce → rejected
##   3. Nonce from a previous flow → rejected (different value in new ID token)

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Nonce tamper: replaced nonce in state store causes ID token rejection", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  # Ensure provider uses nonces (Keycloak OIDC provider should by default)
  testthat::expect_true(prov@use_nonce)

  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()

      # Get the state store entry and replace the nonce with a fake one
      ss <- get_state_store_entry(client, url)
      orig_nonce <- ss$entry$nonce
      testthat::expect_true(
        is.character(orig_nonce) && nzchar(orig_nonce)
      )

      # Generate a clearly different nonce
      fake_nonce <- paste0(
        sample(c(letters, LETTERS, 0:9, "-", "_", ".", "~"), 32, TRUE),
        collapse = ""
      )
      testthat::expect_false(identical(fake_nonce, orig_nonce))

      # Replace just the nonce, keep everything else intact
      set_state_store_entry(
        client,
        ss$info$key,
        list(
          browser_token = ss$entry$browser_token,
          pkce_code_verifier = ss$entry$pkce_code_verifier,
          nonce = fake_nonce
        )
      )

      # Complete the login — Keycloak will embed the ORIGINAL nonce in the ID token
      res <- perform_login_form(url)

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      # Must fail: ID token nonce (original) != stored nonce (fake)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "nonce|id.token|ID token",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Nonce tamper: removed nonce from state store", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  testthat::expect_true(prov@use_nonce)
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()

      # Remove the nonce from the state store entry
      ss <- get_state_store_entry(client, url)
      testthat::expect_true(
        is.character(ss$entry$nonce) && nzchar(ss$entry$nonce)
      )

      set_state_store_entry(
        client,
        ss$info$key,
        list(
          browser_token = ss$entry$browser_token,
          pkce_code_verifier = ss$entry$pkce_code_verifier,
          nonce = NULL
        )
      )

      res <- perform_login_form(url)

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      # Must fail: ID token has a nonce claim but no expected nonce to compare against
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "nonce|id.token|ID token",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Nonce replay: nonce from flow 1 injected into flow 2", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  testthat::expect_true(prov@use_nonce)
  client <- make_public_client(prov)

  captured_nonce <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Flow 1: capture the nonce
      url1 <- values$build_auth_url()
      ss1 <- get_state_store_entry(client, url1)
      captured_nonce <<- ss1$entry$nonce
      testthat::expect_true(
        is.character(captured_nonce) && nzchar(captured_nonce)
      )

      # Complete flow 1 normally
      res1 <- perform_login_form(url1)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res1$code),
        "&state=",
        utils::URLencode(res1$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))
    }
  )

  # Flow 2: new session, inject the old nonce
  client2 <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client2),
    expr = {
      url2 <- values$build_auth_url()

      # Replace flow 2's nonce with the captured nonce from flow 1
      ss2 <- get_state_store_entry(client2, url2)
      # Ensure flow 2's nonce is different (they're random)
      testthat::expect_false(identical(ss2$entry$nonce, captured_nonce))

      set_state_store_entry(
        client2,
        ss2$info$key,
        list(
          browser_token = ss2$entry$browser_token,
          pkce_code_verifier = ss2$entry$pkce_code_verifier,
          nonce = captured_nonce
        )
      )

      res2 <- perform_login_form(url2)

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res2$code),
        "&state=",
        utils::URLencode(res2$state_payload)
      ))
      session$flushReact()

      # Must fail: ID token nonce (flow 2's) != stored nonce (flow 1's)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "nonce|id.token|ID token",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})
