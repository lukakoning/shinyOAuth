## Integration tests: live Keycloak JWKS key rotation

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

keycloak_base_url <- function() {
  sub("/realms/shinyoauth$", "", get_issuer())
}

keycloak_nonempty_string <- function(x) {
  is.character(x) &&
    length(x) == 1L &&
    !is.na(x) &&
    nzchar(x)
}

keycloak_admin_token <- function() {
  resp <- httr2::request(
    paste0(keycloak_base_url(), "/realms/master/protocol/openid-connect/token")
  ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_body_form(
      grant_type = "password",
      client_id = "admin-cli",
      username = "admin",
      password = "admin"
    ) |>
    httr2::req_perform()

  if (httr2::resp_is_error(resp)) {
    testthat::skip("Keycloak admin token request failed")
  }

  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  token <- body$access_token %||% NA_character_
  if (!keycloak_nonempty_string(token)) {
    testthat::skip("Keycloak admin token response did not include access_token")
  }
  token
}

keycloak_admin_request <- function(method, path, token, body = NULL) {
  req <- httr2::request(paste0(keycloak_base_url(), path)) |>
    httr2::req_auth_bearer_token(token) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_method(method)

  if (!is.null(body)) {
    req <- httr2::req_body_json(req, body, auto_unbox = TRUE)
  }

  httr2::req_perform(req)
}

keycloak_realm_keys <- function(token) {
  resp <- keycloak_admin_request(
    "GET",
    "/admin/realms/shinyoauth/keys",
    token = token
  )
  if (httr2::resp_is_error(resp)) {
    testthat::skip("Keycloak admin keys endpoint failed")
  }
  httr2::resp_body_json(resp, simplifyVector = FALSE)
}

keycloak_realm_id <- function(token) {
  resp <- keycloak_admin_request(
    "GET",
    "/admin/realms/shinyoauth",
    token = token
  )
  if (httr2::resp_is_error(resp)) {
    testthat::skip("Keycloak admin realm endpoint failed")
  }
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  realm_id <- body$id %||% body$realm %||% NA_character_
  if (!keycloak_nonempty_string(realm_id)) {
    testthat::skip("Could not determine Keycloak realm id")
  }
  realm_id
}

keycloak_active_rs256_kid <- function(keys) {
  active <- keys$active %||% list()
  active_kid <- active$RS256 %||% active$rs256 %||% NA_character_
  if (keycloak_nonempty_string(active_kid)) {
    return(active_kid)
  }

  for (key in keys$keys %||% list()) {
    alg <- toupper(key$algorithm %||% "")
    status <- toupper(key$status %||% "")
    use <- toupper(key$use %||% key$type %||% "")
    kid <- key$kid %||% NA_character_
    if (
      identical(alg, "RS256") &&
        identical(status, "ACTIVE") &&
        (use %in% c("SIG", "RSA", "")) &&
        keycloak_nonempty_string(kid)
    ) {
      return(kid)
    }
  }

  NA_character_
}

keycloak_create_generated_rsa_key_provider <- function(token) {
  name <- paste0(
    "shinyoauth-rotation-",
    format(Sys.time(), "%Y%m%d%H%M%S"),
    "-",
    paste(sample(c(letters, 0:9), 6, replace = TRUE), collapse = "")
  )

  body <- list(
    name = name,
    providerId = "rsa-generated",
    providerType = "org.keycloak.keys.KeyProvider",
    parentId = keycloak_realm_id(token),
    config = list(
      priority = list("999"),
      enabled = list("true"),
      active = list("true"),
      algorithm = list("RS256"),
      keySize = list("2048")
    )
  )

  resp <- keycloak_admin_request(
    "POST",
    "/admin/realms/shinyoauth/components",
    token = token,
    body = body
  )

  if (httr2::resp_status(resp) >= 400L) {
    testthat::skip(
      paste(
        "Keycloak did not accept an rsa-generated key provider component:",
        httr2::resp_body_string(resp)
      )
    )
  }

  location <- httr2::resp_header(resp, "location") %||% ""
  component_id <- sub(".*/components/", "", location)
  if (
    !keycloak_nonempty_string(component_id) ||
      identical(component_id, location)
  ) {
    testthat::skip("Could not infer generated key provider component id")
  }

  list(id = component_id, name = name)
}

keycloak_delete_component <- function(token, component_id) {
  try(
    keycloak_admin_request(
      "DELETE",
      paste0("/admin/realms/shinyoauth/components/", component_id),
      token = token
    ),
    silent = TRUE
  )
  invisible(NULL)
}

wait_for_active_rs256_kid <- function(token, previous_kid, timeout = 10) {
  deadline <- Sys.time() + timeout
  repeat {
    kid <- keycloak_active_rs256_kid(keycloak_realm_keys(token))
    if (
      keycloak_nonempty_string(kid) &&
        !identical(kid, previous_kid)
    ) {
      return(kid)
    }
    if (Sys.time() >= deadline) {
      break
    }
    Sys.sleep(0.25)
  }
  NA_character_
}

jwks_rotation_login_via_module <- function(client) {
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

make_rogue_id_token_with_kid <- function(id_token, kid) {
  claims <- shinyOAuth:::parse_jwt_payload(id_token)
  now <- floor(as.numeric(Sys.time()))
  claims$iat <- now - 1
  claims$exp <- now + 300

  jose::jwt_encode_sig(
    do.call(jose::jwt_claim, as.list(claims)),
    key = openssl::rsa_keygen(bits = 2048),
    header = list(alg = "RS256", kid = kid, typ = "JWT")
  )
}

testthat::test_that("JWKS cache refreshes on live Keycloak signing-key rotation", {
  skip_common()
  testthat::skip_if_not_installed("jose")
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  first <- jwks_rotation_login_via_module(client)
  testthat::expect_true(isTRUE(first$authenticated))
  first_header <- shinyOAuth:::parse_jwt_header(first$token@id_token)
  first_kid <- first_header$kid %||% NA_character_
  testthat::expect_true(keycloak_nonempty_string(first_kid))

  admin_token <- keycloak_admin_token()
  component <- keycloak_create_generated_rsa_key_provider(admin_token)
  on.exit(keycloak_delete_component(admin_token, component$id), add = TRUE)

  new_kid <- wait_for_active_rs256_kid(admin_token, previous_kid = first_kid)
  testthat::expect_true(keycloak_nonempty_string(new_kid))
  testthat::expect_false(identical(new_kid, first_kid))

  second <- jwks_rotation_login_via_module(client)
  testthat::expect_true(isTRUE(second$authenticated))
  second_header <- shinyOAuth:::parse_jwt_header(second$token@id_token)
  testthat::expect_identical(second_header$kid, new_kid)
  testthat::expect_true(isTRUE(second$token@id_token_validated))

  rogue_old_kid <- make_rogue_id_token_with_kid(
    second$token@id_token,
    first_kid
  )
  rogue_new_kid <- make_rogue_id_token_with_kid(second$token@id_token, new_kid)

  testthat::expect_error(
    shinyOAuth:::validate_id_token(client, rogue_old_kid),
    regexp = "signature|No JWKS key matches kid",
    class = "shinyOAuth_id_token_error"
  )
  testthat::expect_error(
    shinyOAuth:::validate_id_token(client, rogue_new_kid),
    regexp = "signature",
    class = "shinyOAuth_id_token_error"
  )
})
