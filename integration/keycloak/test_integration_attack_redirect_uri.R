## Headless protocol integration: redirect URI manipulation
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

expect_auth_url_rejected <- function(auth_url, redirect_uri) {
  resp <- httr2::request(auth_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()

  status <- httr2::resp_status(resp)
  location <- httr2::resp_header(resp, "location")

  testthat::expect_identical(
    status,
    400L,
    info = paste0(
      "Expected HTTP 400 for unregistered redirect_uri ",
      redirect_uri,
      "; got ",
      status
    )
  )
  testthat::expect_null(
    location,
    info = paste0(
      "Keycloak must not redirect to an unregistered URI; Location was ",
      location %||% "<absent>"
    )
  )

  invisible(resp)
}

expect_redirect_uri_rejected <- function(prov, redirect_uri) {
  auth_url <- paste0(
    prov@auth_url,
    "?response_type=code",
    "&client_id=shiny-public",
    "&redirect_uri=",
    utils::URLencode(redirect_uri, reserved = TRUE),
    "&scope=openid",
    "&state=fake-state"
  )

  expect_auth_url_rejected(auth_url, redirect_uri)
}

testthat::test_that("Redirect URI: Keycloak rejects unregistered redirects exactly", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  rejected_redirects <- c(
    "http://evil.com/steal-code",
    "http://localhost:3000/callback/attacker",
    "http://localhost:3000/callback?next=http://evil.com/steal-code"
  )

  for (redirect_uri in rejected_redirects) {
    expect_redirect_uri_rejected(prov, redirect_uri)
  }
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

      expect_auth_url_rejected(
        tampered_url,
        "http://attacker.com/callback"
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

  # Reuse the same state key so this check isolates redirect_uri policy binding
  # instead of failing earlier on a different encryption key.
  client_b@state_key <- client_a@state_key

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

  # The state payload decrypts under the shared key, then fails closed because
  # it carries client_a's redirect_uri rather than client_b's.
  err <- tryCatch(
    {
      shinyOAuth:::state_payload_decrypt_validate(client_b, state_from_a)
      NULL
    },
    error = identity
  )

  testthat::expect_s3_class(err, "shinyOAuth_state_error")
  testthat::expect_match(
    conditionMessage(err),
    "redirect|client policy|payload|binding",
    ignore.case = TRUE
  )
})
