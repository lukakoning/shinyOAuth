## Attack vector: State Parameter Tampering
##
## Verifies that modified state parameters are rejected by AES-256-GCM
## authenticated encryption. Any bit-flip, truncation, or substitution
## should cause decryption failure.
## Defense mechanisms tested:
##   1. AES-256-GCM authentication tag integrity
##   2. Input validation (empty / oversized state)

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

## Helper: build an auth URL and get a valid code+state, then test a tampered state
run_tampered_state_test <- function(
  tamper_fn,
  error_pattern = "state|State|decrypt|validation"
) {
  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      original_state <- parse_query_param(url, "state")

      # Apply tamper function to the state
      tampered <- tamper_fn(original_state)

      # Drive login form with the ORIGINAL url (code is valid)
      res <- perform_login_form(url)

      # Callback with valid code but TAMPERED state
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(tampered)
      ))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        error_pattern,
        combo,
        ignore.case = TRUE
      ))
    }
  )
}

testthat::test_that("State tamper: bit-flip in middle of ciphertext", {
  skip_common()
  local_test_options()

  run_tampered_state_test(function(state) {
    # Flip a character near the middle of the state string
    chars <- strsplit(state, "")[[1]]
    mid <- length(chars) %/% 2
    # Replace the char with a different one
    old_char <- chars[mid]
    new_char <- if (old_char == "A") "B" else "A"
    chars[mid] <- new_char
    paste0(chars, collapse = "")
  })
})

testthat::test_that("State tamper: truncation to 50%", {
  skip_common()
  local_test_options()

  run_tampered_state_test(function(state) {
    substr(state, 1, nchar(state) %/% 2)
  })
})

testthat::test_that("State tamper: random replacement (same length)", {
  skip_common()
  local_test_options()

  run_tampered_state_test(function(state) {
    # Generate a random base64url string of the same length
    n <- nchar(state)
    chars <- c(letters, LETTERS, 0:9, "-", "_")
    paste0(sample(chars, n, replace = TRUE), collapse = "")
  })
})

testthat::test_that("State tamper: empty state parameter", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # Callback with empty state
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state="
      ))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
    }
  )
})

testthat::test_that("State tamper: appended garbage bytes", {
  skip_common()
  local_test_options()

  run_tampered_state_test(function(state) {
    # Append random bytes — changes ciphertext length, breaks GCM
    paste0(state, "AAAAAAAAAA")
  })
})

testthat::test_that("State tamper: prepended garbage bytes", {
  skip_common()
  local_test_options()

  run_tampered_state_test(function(state) {
    paste0("XXXXXXXXXX", state)
  })
})

testthat::test_that("State tamper: state encrypted with different key", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Client with key A — builds the auth URL
  client_a <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_key = "key-alpha-bravo-charlie-delta-echo"
  )

  # Client with key B — tries to use the state
  client_b <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_key = "key-foxtrot-golf-hotel-india-juliet"
  )

  captured_state <- NULL
  captured_code <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_a),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)
      captured_state <<- res$state_payload
      captured_code <<- res$code
    }
  )

  # Now try to use client_a's state in client_b's session
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_b),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(captured_code),
        "&state=",
        utils::URLencode(captured_state)
      ))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|decrypt|validation|GCM",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})
