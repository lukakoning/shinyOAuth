## Integration tests: PKCE downgrade/tampering at the authorization endpoint
##
## Existing PKCE tests mutate the stored verifier before callback. These tests
## tamper with the outbound authorization URL itself and assert Keycloak does
## not issue an authorization code for downgraded or malformed PKCE requests.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

drop_query_param <- function(url, name) {
  pieces <- strsplit(url, "?", fixed = TRUE)[[1]]
  if (length(pieces) < 2L) {
    return(url)
  }

  prefix <- pieces[[1]]
  query <- paste(pieces[-1], collapse = "?")
  parts <- strsplit(query, "&", fixed = TRUE)[[1]]
  parts <- parts[!startsWith(parts, paste0(name, "="))]

  if (!length(parts)) {
    return(prefix)
  }

  paste0(prefix, "?", paste(parts, collapse = "&"))
}

set_query_param <- function(url, name, value) {
  pieces <- strsplit(url, "?", fixed = TRUE)[[1]]
  prefix <- pieces[[1]]
  query <- if (length(pieces) > 1L) paste(pieces[-1], collapse = "?") else ""
  parts <- if (nzchar(query)) {
    strsplit(query, "&", fixed = TRUE)[[1]]
  } else {
    character(0)
  }
  encoded <- paste0(
    utils::URLencode(name, reserved = TRUE),
    "=",
    utils::URLencode(value, reserved = TRUE)
  )
  matched <- startsWith(parts, paste0(name, "="))
  if (any(matched)) {
    parts[matched] <- encoded
  } else {
    parts <- c(parts, encoded)
  }
  paste0(prefix, "?", paste(parts, collapse = "&"))
}

expect_no_authorization_code <- function(auth_url, redirect_uri) {
  result <- try(
    perform_login_form(auth_url, redirect_uri = redirect_uri),
    silent = TRUE
  )

  if (inherits(result, "try-error")) {
    return(invisible(TRUE))
  }

  code <- result[["code"]] %||% NA_character_
  testthat::expect_false(
    is.character(code) && length(code) == 1L && !is.na(code) && nzchar(code),
    info = paste0(
      "Tampered authorization URL unexpectedly issued a code: ",
      result[["callback_url"]] %||% "<no callback>"
    )
  )

  combo <- paste(
    result[["callback_url"]] %||% "",
    result[["state_payload"]] %||% ""
  )
  testthat::expect_match(
    combo,
    "error|invalid|pkce|code_challenge",
    ignore.case = TRUE
  )

  invisible(TRUE)
}

testthat::test_that("Keycloak rejects authorization request without code_challenge", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_match(auth_url, "[?&]code_challenge=")

      tampered_url <- drop_query_param(auth_url, "code_challenge")
      expect_no_authorization_code(tampered_url, client@redirect_uri)
    }
  )
})

testthat::test_that("Keycloak rejects authorization request downgraded to plain PKCE", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      testthat::expect_match(auth_url, "code_challenge_method=S256")

      tampered_url <- set_query_param(
        auth_url,
        "code_challenge_method",
        "plain"
      )
      expect_no_authorization_code(tampered_url, client@redirect_uri)
    }
  )
})

testthat::test_that("Keycloak rejects authorization request with malformed challenge", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      tampered_url <- set_query_param(auth_url, "code_challenge", "short")

      expect_no_authorization_code(tampered_url, client@redirect_uri)
    }
  )
})
