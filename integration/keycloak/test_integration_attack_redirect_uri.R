## Attack vector: Redirect URI Manipulation
##
## Verifies that modified redirect_uri parameters are rejected, preventing
## authorization codes from being sent to attacker-controlled endpoints.
## Defense mechanisms tested:
##   1. Keycloak server-side redirect URI allowlist (rejects unknown URIs)
##   2. State payload redirect_uri binding (client-side validation)

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Redirect URI: Keycloak rejects unauthorized redirect_uri", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Construct an auth URL manually with an evil redirect_uri
  # Keycloak should reject this at the authorization endpoint
  evil_redirect <- "http://evil.com/steal-code"
  auth_url <- paste0(
    prov@auth_url,
    "?response_type=code",
    "&client_id=shiny-public",
    "&redirect_uri=",
    utils::URLencode(evil_redirect, reserved = TRUE),
    "&scope=openid",
    "&state=fake-state"
  )

  resp <- httr2::request(auth_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()

  # Keycloak should return an error page (not redirect to evil.com)
  # Status should be 400 or the page should contain an error message
  body <- httr2::resp_body_string(resp)
  status <- httr2::resp_status(resp)

  # Either HTTP error status or the body mentions invalid redirect
  is_error <- status >= 400 ||
    grepl(
      "Invalid redirect|invalid_redirect|redirect_uri",
      body,
      ignore.case = TRUE
    )
  testthat::expect_true(
    is_error,
    info = paste0(
      "Expected Keycloak to reject evil redirect_uri. Status: ",
      status,
      "\nBody snippet: ",
      substr(body, 1, 500)
    )
  )
})

testthat::test_that("Redirect URI: tampered redirect_uri in auth URL rejected by Keycloak", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Build the legitimate auth URL
      url <- values$build_auth_url()

      # Parse and replace redirect_uri with an attacker-controlled one
      # Note: Keycloak must have this URI in its allowlist to issue a code.
      # Since it doesn't, the auth request itself should fail.
      tampered_url <- sub(
        "redirect_uri=[^&]+",
        paste0(
          "redirect_uri=",
          utils::URLencode(
            "http://attacker.com/callback",
            reserved = TRUE
          )
        ),
        url
      )

      resp <- httr2::request(tampered_url) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "text/html") |>
        httr2::req_options(followlocation = FALSE) |>
        httr2::req_perform()

      body <- httr2::resp_body_string(resp)
      status <- httr2::resp_status(resp)

      is_error <- status >= 400 ||
        grepl(
          "Invalid redirect|invalid_redirect|redirect_uri",
          body,
          ignore.case = TRUE
        )
      testthat::expect_true(
        is_error,
        info = paste0(
          "Keycloak should reject modified redirect_uri. Status: ",
          status,
          "\nBody: ",
          substr(body, 1, 500)
        )
      )
    }
  )
})

testthat::test_that("Redirect URI: state payload binding catches redirect_uri swap", {
  skip_common()
  local_test_options()

  # This tests the client-side defense: even if an attacker could somehow get
  # Keycloak to issue a code with a different redirect_uri, the state payload
  # contains the original redirect_uri and the validation would catch the mismatch.

  prov <- make_provider()

  # Create two clients with different redirect_uris
  client_a <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid")
  )

  client_b <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = c("openid")
  )

  # Build auth URL with client_a (redirect_uri = localhost:3000/callback)
  state_from_a <- NULL
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_a),
    expr = {
      url_a <- values$build_auth_url()
      state_from_a <<- parse_query_param(url_a, "state")
    }
  )

  # Try to validate client_a's state in client_b's context
  # The state payload says redirect_uri=localhost:3000/callback
  # but client_b has redirect_uri=localhost:8100/callback → binding mismatch
  testthat::expect_error(
    shinyOAuth:::state_payload_decrypt_validate(client_b, state_from_a),
    regexp = "redirect|binding|mismatch|validation|State",
    ignore.case = TRUE
  )
})
