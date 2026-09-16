# Isolate AS client binding: keep the correct PKCE verifier and redirect URI,
# changing only client_id in the token request for the same authorization code.
testthat::test_that("Keycloak binds codes to clients independently of PKCE", {
  skip_common()
  local_test_options()
  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  provider@par_url <- NA_character_
  client <- make_public_client(provider)
  admin <- keycloak_admin_token()
  peer_id <- keycloak_temp_client_id("shiny-cross-client")
  peer <- keycloak_create_client(
    admin,
    list(
      clientId = peer_id,
      protocol = "openid-connect",
      publicClient = TRUE,
      standardFlowEnabled = TRUE,
      redirectUris = list(client@redirect_uri),
      attributes = list("pkce.code.challenge.method" = "S256")
    ),
    delete_existing = FALSE
  )
  withr::defer(keycloak_delete_client(admin, id = peer[["id"]]))
  peer_client <- make_public_client(provider, client_id = peer_id)
  browser <- strrep("ab", 64)
  authorization <- function(registration) {
    url <- shinyOAuth::prepare_call(registration, browser_token = browser)
    state <- get_state_store_entry(registration, url)
    verifier <- state[["entry"]][["pkce_code_verifier"]]
    testthat::expect_identical(
      shinyOAuth:::base64url_encode(openssl::sha256(charToRaw(verifier))),
      parse_query_param(url, "code_challenge", decode = TRUE)
    )
    login <- perform_login_form_as(
      url,
      redirect_uri = registration@redirect_uri
    )
    list(
      grant_type = "authorization_code",
      code = login[["code"]],
      redirect_uri = registration@redirect_uri,
      code_verifier = verifier,
      client_id = registration@client_id
    )
  }
  redeem <- function(fields) {
    req <- do.call(
      httr2::req_body_form,
      c(list(httr2::request(provider@token_url)), fields)
    )
    req |>
      httr2::req_error(is_error = function(resp) FALSE) |>
      httr2::req_perform()
  }
  # Both registrations can redeem their own code with this exact request shape.
  for (registration in list(client, peer_client)) {
    response <- redeem(authorization(registration))
    testthat::expect_identical(httr2::resp_status(response), 200L)
    testthat::expect_true(nzchar(httr2::resp_body_json(response)[[
      "access_token"
    ]]))
  }
  original <- authorization(client)
  attack <- original
  attack[["client_id"]] <- peer_id
  testthat::expect_identical(
    attack[names(attack) != "client_id"],
    original[names(original) != "client_id"]
  )
  response <- redeem(attack)
  testthat::expect_identical(httr2::resp_status(response), 400L)
  body <- httr2::resp_body_json(response)
  testthat::expect_identical(body[["error"]], "invalid_grant")
  testthat::expect_null(body[["access_token"]])
})
