## Integration tests: live Keycloak JWKS key rotation

if (!exists("make_provider", mode = "function")) {
  source(file.path(
    dirname(sys.frame(1)[["ofile"]] %||% "."),
    "helper-keycloak.R"
  ))
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
    stop("Keycloak admin token request failed", call. = FALSE)
  }

  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  token <- body[["access_token"]] %||% NA_character_
  if (!keycloak_nonempty_string(token)) {
    stop(
      "Keycloak admin token response did not include access_token",
      call. = FALSE
    )
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
    stop("Keycloak admin keys endpoint failed", call. = FALSE)
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
    stop("Keycloak admin realm endpoint failed", call. = FALSE)
  }
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  realm_id <- body[["id"]] %||% body[["realm"]] %||% NA_character_
  if (!keycloak_nonempty_string(realm_id)) {
    stop("Could not determine Keycloak realm id", call. = FALSE)
  }
  realm_id
}

keycloak_active_rs256_kid <- function(keys) {
  active <- keys[["active"]] %||% list()
  active_kid <- active[["RS256"]] %||% active[["rs256"]] %||% NA_character_
  if (keycloak_nonempty_string(active_kid)) {
    return(active_kid)
  }

  for (key in keys[["keys"]] %||% list()) {
    alg <- toupper(key[["algorithm"]] %||% "")
    status <- toupper(key[["status"]] %||% "")
    use <- toupper(key[["use"]] %||% key[["type"]] %||% "")
    kid <- key[["kid"]] %||% NA_character_
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
    stop(
      paste(
        "Keycloak did not accept an rsa-generated key provider component:",
        httr2::resp_body_string(resp)
      ),
      call. = FALSE
    )
  }

  location <- httr2::resp_header(resp, "location") %||% ""
  component_id <- sub(".*/components/", "", location)
  if (
    !keycloak_nonempty_string(component_id) ||
      identical(component_id, location)
  ) {
    stop("Could not infer generated key provider component id", call. = FALSE)
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
      auth_url <- values[["build_auth_url"]]()
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      values[[".process_query"]](callback_query(login))
      session[["flushReact"]]()
      result <<- list(
        authenticated = isTRUE(values[["authenticated"]]),
        error = values[["error"]],
        error_description = values[["error_description"]],
        token = values[["token"]]
      )
    }
  )

  result
}

make_rogue_id_token_with_kid <- function(id_token, kid) {
  claims <- shinyOAuth:::parse_jwt_payload(id_token)
  now <- floor(as.numeric(Sys.time()))
  claims[["iat"]] <- now - 1
  claims[["exp"]] <- now + 300

  jose::jwt_encode_sig(
    do.call(jose::jwt_claim, as.list(claims)),
    key = openssl::rsa_keygen(bits = 2048),
    header = list(alg = "RS256", kid = kid, typ = "JWT")
  )
}

testthat::test_that("Keycloak no-cache JWKS are refetched across signing-key rotation", {
  for (package in c("jose", "xml2", "rvest")) {
    if (!requireNamespace(package, quietly = TRUE)) {
      stop(paste("Required rotation-test dependency is missing:", package))
    }
  }
  if (!keycloak_reachable()) {
    stop("Required rotation-test Keycloak is not reachable at localhost:8080")
  }
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)
  cache <- client@provider@jwks_cache
  cache_key <- shinyOAuth:::jwks_cache_key(
    prov@issuer,
    pins = prov@jwks_pins,
    pin_mode = prov@jwks_pin_mode,
    issuer_match = prov@issuer_match,
    jwks_host_issuer_match = prov@jwks_host_issuer_match,
    jwks_host_allow_only = prov@jwks_host_allow_only,
    jwks_uri_override = prov@jwks_uri,
    tls_minimum = shinyOAuth:::client_tls_minimum(client)
  )
  cached_kids <- function(entry) {
    vapply(
      entry[["jwks"]][["keys"]],
      function(key) key[["kid"]] %||% "",
      character(1)
    )
  }
  testthat::expect_null(cache[["get"]](cache_key, missing = NULL))

  # Count real downloads without replacing the cache or changing HTTP responses.
  perform <- shinyOAuth:::req_with_retry
  jwks_requests <- list()
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      is_jwks <- identical(req[["url"]], prov@jwks_uri)
      if (is_jwks) {
        requested_at <- as.numeric(Sys.time())
        entry <- cache[["get"]](cache_key, missing = NULL)
      }
      resp <- perform(req, ...)
      if (is_jwks) {
        jwks_requests[[length(jwks_requests) + 1L]] <<- list(
          requested_at = requested_at,
          entry = entry,
          cache_control = httr2::resp_header(resp, "cache-control")
        )
      }
      resp
    },
    .package = "shinyOAuth"
  )

  first <- jwks_rotation_login_via_module(client)
  testthat::expect_true(isTRUE(first[["authenticated"]]))
  testthat::expect_true(isTRUE(first[["token"]]@id_token_validated))
  first_header <- shinyOAuth:::parse_jwt_header(first[["token"]]@id_token)
  first_kid <- first_header[["kid"]] %||% NA_character_
  testthat::expect_true(keycloak_nonempty_string(first_kid))

  first_entry <- cache[["get"]](cache_key, missing = NULL)
  testthat::expect_type(first_entry, "list")
  testthat::expect_true(first_kid %in% cached_kids(first_entry))
  testthat::expect_lte(
    first_entry[["fresh_until"]],
    first_entry[["fetched_at"]]
  )
  testthat::expect_length(jwks_requests, 1L)
  testthat::expect_match(
    jwks_requests[[1L]][["cache_control"]],
    "(^|,)\\s*no-cache\\s*(,|$)"
  )
  testthat::expect_null(jwks_requests[[1L]][["entry"]])
  testthat::expect_null(cache[["get"]](
    paste0(cache_key, "xfr"),
    missing = NULL
  ))

  # This pinned server requires revalidation. These logins do not prove a warm
  # cache hit or refresh-on-unknown-kid from a still-fresh cached key set.
  repeated_login <- jwks_rotation_login_via_module(client)
  testthat::expect_true(isTRUE(repeated_login[["authenticated"]]))
  testthat::expect_true(isTRUE(repeated_login[["token"]]@id_token_validated))
  testthat::expect_identical(
    shinyOAuth:::parse_jwt_header(repeated_login[["token"]]@id_token)[["kid"]],
    first_kid
  )
  testthat::expect_identical(client@provider@jwks_cache, cache)
  testthat::expect_length(jwks_requests, 2L)
  testthat::expect_identical(jwks_requests[[2L]][["entry"]], first_entry)
  testthat::expect_match(
    jwks_requests[[2L]][["cache_control"]],
    "(^|,)\\s*no-cache\\s*(,|$)"
  )
  repeated_entry <- cache[["get"]](cache_key, missing = NULL)
  testthat::expect_gt(
    repeated_entry[["fetched_at"]],
    first_entry[["fetched_at"]]
  )
  testthat::expect_lte(
    repeated_entry[["fresh_until"]],
    repeated_entry[["fetched_at"]]
  )

  admin_token <- keycloak_admin_token()
  component <- keycloak_create_generated_rsa_key_provider(admin_token)
  on.exit(keycloak_delete_component(admin_token, component[["id"]]), add = TRUE)

  new_kid <- wait_for_active_rs256_kid(admin_token, previous_kid = first_kid)
  testthat::expect_true(keycloak_nonempty_string(new_kid))
  testthat::expect_false(identical(new_kid, first_kid))
  testthat::expect_false(new_kid %in% cached_kids(repeated_entry))
  testthat::expect_identical(client@provider@jwks_cache, cache)
  testthat::expect_identical(cache[["get"]](cache_key), repeated_entry)

  second <- jwks_rotation_login_via_module(client)
  testthat::expect_true(isTRUE(second[["authenticated"]]))
  second_header <- shinyOAuth:::parse_jwt_header(second[["token"]]@id_token)
  testthat::expect_identical(second_header[["kid"]], new_kid)
  testthat::expect_true(isTRUE(second[["token"]]@id_token_validated))
  testthat::expect_identical(client@provider@jwks_cache, cache)
  testthat::expect_length(jwks_requests, 3L)
  testthat::expect_match(
    jwks_requests[[3L]][["cache_control"]],
    "(^|,)\\s*no-cache\\s*(,|$)"
  )
  testthat::expect_identical(jwks_requests[[3L]][["entry"]], repeated_entry)
  testthat::expect_lte(
    repeated_entry[["fresh_until"]],
    jwks_requests[[3L]][["requested_at"]]
  )

  refreshed_entry <- cache[["get"]](cache_key, missing = NULL)
  testthat::expect_true(new_kid %in% cached_kids(refreshed_entry))
  testthat::expect_gt(
    refreshed_entry[["fetched_at"]],
    repeated_entry[["fetched_at"]]
  )
  testthat::expect_lte(
    refreshed_entry[["fresh_until"]],
    refreshed_entry[["fetched_at"]]
  )
  testthat::expect_null(cache[["get"]](
    paste0(cache_key, "xfr"),
    missing = NULL
  ))

  rogue_old_kid <- make_rogue_id_token_with_kid(
    second[["token"]]@id_token,
    first_kid
  )
  rogue_new_kid <- make_rogue_id_token_with_kid(
    second[["token"]]@id_token,
    new_kid
  )

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
  testthat::expect_identical(client@provider@jwks_cache, cache)
})
