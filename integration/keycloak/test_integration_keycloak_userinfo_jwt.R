## Integration tests: signed UserInfo JWTs from live Keycloak

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_userinfo_jwt_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-userinfo-jwt",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid", "profile", "email")
  )
}

userinfo_jwt_login_via_module <- function(client) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      values$.process_query(callback_query(login))
      session$flushReact()
      result <<- list(
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

userinfo_jwt_aud_includes <- function(aud, expected) {
  if (is.character(aud)) {
    return(expected %in% aud)
  }
  if (is.list(aud)) {
    return(expected %in% unlist(aud, use.names = FALSE))
  }
  FALSE
}

testthat::test_that("Keycloak signed UserInfo JWT is verified and subject-bound", {
  skip_common()
  local_test_options()

  prov <- make_provider(userinfo_signed_jwt_required = TRUE)
  client <- make_userinfo_jwt_client(prov)

  result <- userinfo_jwt_login_via_module(client)

  testthat::expect_true(isTRUE(result$authenticated))
  testthat::expect_null(result$error)
  testthat::expect_true(isTRUE(result$token@id_token_validated))
  testthat::expect_identical(
    result$token@userinfo$preferred_username,
    "alice"
  )
  testthat::expect_identical(result$token@userinfo$email, "alice@example.com")

  id_payload <- shinyOAuth:::parse_jwt_payload(result$token@id_token)
  testthat::expect_identical(result$token@userinfo$sub, id_payload$sub)

  raw_resp <- httr2::request(prov@userinfo_url) |>
    httr2::req_headers(
      Authorization = paste("Bearer", result$token@access_token),
      Accept = "application/jwt"
    ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()

  testthat::expect_identical(httr2::resp_status(raw_resp), 200L)
  ct <- httr2::resp_content_type(raw_resp)
  testthat::expect_match(ct, "^application/jwt", ignore.case = TRUE)

  jwt <- trimws(httr2::resp_body_string(raw_resp))
  testthat::expect_length(strsplit(jwt, ".", fixed = TRUE)[[1]], 3L)

  header <- shinyOAuth:::parse_jwt_header(jwt)
  payload <- shinyOAuth:::parse_jwt_payload(jwt)

  testthat::expect_identical(toupper(header$alg), "RS256")
  testthat::expect_identical(payload$iss, prov@issuer)
  testthat::expect_true(userinfo_jwt_aud_includes(
    payload$aud,
    client@client_id
  ))
  testthat::expect_identical(payload$sub, result$token@userinfo$sub)

  fetched <- shinyOAuth::get_userinfo(client, result$token)
  testthat::expect_identical(fetched$sub, result$token@userinfo$sub)
  testthat::expect_identical(fetched$email, "alice@example.com")
})
