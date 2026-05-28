## Shared helpers for Keycloak integration tests
##
## Sourced by individual test files to avoid duplicating infrastructure code.
## Provides: connectivity checks, query parsing, cookie handling,
## login-form driving, and factory functions for providers/clients.

keycloak_configure_curl_ssl_backend <- function() {
  if (!identical(.Platform$OS.type, "windows")) {
    return(invisible(FALSE))
  }
  if (nzchar(Sys.getenv("CURL_SSL_BACKEND", unset = ""))) {
    return(invisible(FALSE))
  }

  # R's Windows libcurl build can default to Schannel, which ignores local
  # PEM CA bundles in this harness. Prefer OpenSSL before curl is initialized.
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  invisible(TRUE)
}

keycloak_configure_curl_ssl_backend()

get_issuer <- function() {
  "http://localhost:8080/realms/shinyoauth"
}

get_https_issuer <- function() {
  "https://localhost:8443/realms/shinyoauth"
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
  token <- body[["access_token"]] %||% NA_character_
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

keycloak_find_client <- function(token, client_id) {
  stopifnot(keycloak_nonempty_string(client_id))

  resp <- keycloak_admin_request(
    "GET",
    paste0(
      "/admin/realms/shinyoauth/clients?clientId=",
      utils::URLencode(client_id, reserved = TRUE)
    ),
    token = token
  )

  if (httr2::resp_is_error(resp)) {
    testthat::skip("Keycloak admin clients endpoint failed")
  }

  body <- httr2::resp_body_json(resp, simplifyVector = FALSE)
  if (!is.list(body) || length(body) == 0L) {
    return(NULL)
  }

  for (candidate in body) {
    candidate_id <- candidate[["clientId"]] %||% NA_character_
    if (identical(candidate_id, client_id)) {
      return(candidate)
    }
  }

  NULL
}

keycloak_delete_client <- function(token, client_id = NULL, id = NULL) {
  resolved_id <- id %||% NA_character_

  if (
    !keycloak_nonempty_string(resolved_id) &&
      keycloak_nonempty_string(client_id)
  ) {
    client_info <- keycloak_find_client(token, client_id)
    resolved_id <- if (is.list(client_info)) {
      client_info[["id"]] %||% NA_character_
    } else {
      NA_character_
    }
  }

  if (!keycloak_nonempty_string(resolved_id)) {
    return(invisible(FALSE))
  }

  try(
    keycloak_admin_request(
      "DELETE",
      paste0("/admin/realms/shinyoauth/clients/", resolved_id),
      token = token
    ),
    silent = TRUE
  )

  invisible(TRUE)
}

keycloak_create_client <- function(token, body, delete_existing = TRUE) {
  stopifnot(is.list(body))

  client_id <- body[["clientId"]] %||% NA_character_
  if (!keycloak_nonempty_string(client_id)) {
    stop("body[['clientId']] must be a non-empty string", call. = FALSE)
  }

  if (isTRUE(delete_existing)) {
    keycloak_delete_client(token, client_id = client_id)
  }

  resp <- keycloak_admin_request(
    "POST",
    "/admin/realms/shinyoauth/clients",
    token = token,
    body = body
  )

  if (httr2::resp_status(resp) >= 400L) {
    testthat::skip(
      paste(
        "Keycloak did not accept the client fixture:",
        httr2::resp_body_string(resp)
      )
    )
  }

  location <- httr2::resp_header(resp, "location") %||% ""
  created_id <- sub(".*/clients/", "", location)

  if (
    !keycloak_nonempty_string(created_id) || identical(created_id, location)
  ) {
    client_info <- keycloak_find_client(token, client_id)
    created_id <- if (is.list(client_info)) {
      client_info[["id"]] %||% NA_character_
    } else {
      NA_character_
    }
  }

  list(
    id = created_id,
    client_id = client_id,
    response = resp
  )
}

keycloak_realm_issuer <- function(realm) {
  stopifnot(keycloak_nonempty_string(realm))
  paste0(keycloak_base_url(), "/realms/", realm)
}

keycloak_realm_auth_endpoint <- function(realm) {
  paste0(keycloak_realm_issuer(realm), "/protocol/openid-connect/auth")
}

keycloak_delete_realm <- function(token, realm) {
  stopifnot(keycloak_nonempty_string(realm))

  try(
    keycloak_admin_request(
      "DELETE",
      paste0("/admin/realms/", realm),
      token = token
    ),
    silent = TRUE
  )

  invisible(TRUE)
}

keycloak_create_realm <- function(token, body, delete_existing = TRUE) {
  stopifnot(is.list(body))

  realm <- body[["realm"]] %||% NA_character_
  if (!keycloak_nonempty_string(realm)) {
    stop("body[['realm']] must be a non-empty string", call. = FALSE)
  }

  if (isTRUE(delete_existing)) {
    keycloak_delete_realm(token, realm = realm)
  }

  resp <- keycloak_admin_request(
    "POST",
    "/admin/realms",
    token = token,
    body = body
  )

  if (httr2::resp_status(resp) >= 400L) {
    testthat::skip(
      paste(
        "Keycloak did not accept the realm fixture:",
        httr2::resp_body_string(resp)
      )
    )
  }

  list(
    realm = realm,
    issuer = keycloak_realm_issuer(realm),
    auth_endpoint = keycloak_realm_auth_endpoint(realm),
    response = resp
  )
}

keycloak_temp_realm_name <- function(prefix = "shinyoauth-mixup") {
  suffix <- paste(sample(c(letters, 0:9), 8L, replace = TRUE), collapse = "")
  paste(prefix, suffix, sep = "-")
}

keycloak_create_mixup_realm <- function(
  token,
  realm = keycloak_temp_realm_name()
) {
  body <- list(
    realm = realm,
    enabled = TRUE,
    sslRequired = "none",
    loginWithEmailAllowed = TRUE,
    registrationAllowed = FALSE,
    resetPasswordAllowed = TRUE,
    clients = list(
      list(
        clientId = "shiny-public",
        protocol = "openid-connect",
        publicClient = TRUE,
        redirectUris = list(
          "http://localhost:3000/*",
          "http://127.0.0.1:3000/*",
          "http://localhost:8100/*",
          "http://127.0.0.1:8100/*"
        ),
        webOrigins = list("+"),
        standardFlowEnabled = TRUE,
        implicitFlowEnabled = FALSE,
        directAccessGrantsEnabled = FALSE,
        serviceAccountsEnabled = FALSE,
        attributes = list(
          "pkce.code.challenge.method" = "S256"
        )
      )
    ),
    users = list(
      list(
        username = "alice",
        enabled = TRUE,
        emailVerified = TRUE,
        firstName = "Alice",
        lastName = "Mixup",
        email = paste0("alice@", realm, ".example.com"),
        credentials = list(
          list(
            type = "password",
            userLabel = "password",
            value = "alice",
            temporary = FALSE
          )
        )
      )
    )
  )

  keycloak_create_realm(token, body = body, delete_existing = TRUE)
}

normalize_existing_path <- function(path) {
  if (
    !is.character(path) || length(path) != 1L || is.na(path) || !nzchar(path)
  ) {
    return(NA_character_)
  }
  if (!file.exists(path)) {
    return(NA_character_)
  }
  normalizePath(path, winslash = "/", mustWork = TRUE)
}

is_existing_path_string <- function(path) {
  is.character(path) &&
    length(path) == 1L &&
    !is.na(path) &&
    nzchar(path) &&
    file.exists(path)
}

get_keycloak_tls_path <- function(envvar, filename) {
  env_path <- normalize_existing_path(Sys.getenv(envvar, unset = ""))
  if (is_existing_path_string(env_path)) {
    return(env_path)
  }

  candidates <- c(
    file.path("integration", "keycloak", "tls", filename),
    file.path("tls", filename)
  )

  for (candidate in candidates) {
    resolved <- normalize_existing_path(candidate)
    if (is_existing_path_string(resolved)) {
      return(resolved)
    }
  }

  NA_character_
}

get_keycloak_tls_ca_file <- function() {
  get_keycloak_tls_path("SHINYOAUTH_KEYCLOAK_CA_FILE", "ca-cert.pem")
}

get_keycloak_tls_client_cert_file <- function(
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  switch(
    cert_variant,
    valid = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_CLIENT_CERT_FILE",
      "client-cert.pem"
    ),
    wrong = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_ATTACKER_CERT_FILE",
      "attacker-cert.pem"
    ),
    rogue = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_ROGUE_CLIENT_CERT_FILE",
      "rogue-client-cert.pem"
    )
  )
}

get_keycloak_tls_client_key_file <- function(
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  switch(
    cert_variant,
    valid = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_CLIENT_KEY_FILE",
      "client-key.pem"
    ),
    wrong = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_ATTACKER_KEY_FILE",
      "attacker-key.pem"
    ),
    rogue = get_keycloak_tls_path(
      "SHINYOAUTH_KEYCLOAK_ROGUE_CLIENT_KEY_FILE",
      "rogue-client-key.pem"
    )
  )
}

req_apply_keycloak_ca <- function(req) {
  url <- req[["url"]] %||% NA_character_
  ca_file <- get_keycloak_tls_ca_file()

  if (
    is.character(url) &&
      length(url) == 1L &&
      !is.na(url) &&
      nzchar(url) &&
      grepl("^https://", url) &&
      is.character(ca_file) &&
      length(ca_file) == 1L &&
      !is.na(ca_file) &&
      nzchar(ca_file)
  ) {
    req <- httr2::req_options(req, cainfo = ca_file)
    if (identical(.Platform$OS.type, "windows")) {
      req <- httr2::req_options(req, ssl_options = 2L)
    }
  }

  req
}

req_apply_keycloak_client_certificate <- function(
  req,
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  httr2::req_options(
    req_apply_keycloak_ca(req),
    sslcert = get_keycloak_tls_client_cert_file(cert_variant),
    sslkey = get_keycloak_tls_client_key_file(cert_variant)
  )
}

tls_client_thumbprint <- function(cert_variant = c("valid", "wrong", "rogue")) {
  cert_variant <- match.arg(cert_variant)
  shinyOAuth:::tls_client_cert_thumbprint_s256(
    get_keycloak_tls_client_cert_file(cert_variant)
  )
}

keycloak_cache <- local({
  env <- new.env(parent = emptyenv())
  env$discovery <- NULL
  env$https_discovery <- NULL
  env$jwks <- NULL
  env
})

get_discovery_document <- function(force = FALSE) {
  if (!isTRUE(force) && !is.null(keycloak_cache$discovery)) {
    return(keycloak_cache$discovery)
  }

  disc_url <- paste0(get_issuer(), "/.well-known/openid-configuration")
  resp <- httr2::request(disc_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_perform()

  if (httr2::resp_is_error(resp)) {
    stop("Keycloak discovery request failed", call. = FALSE)
  }

  keycloak_cache$discovery <- httr2::resp_body_json(
    resp,
    simplifyVector = TRUE
  )
  keycloak_cache$discovery
}

get_https_discovery_document <- function(force = FALSE) {
  if (!isTRUE(force) && !is.null(keycloak_cache$https_discovery)) {
    return(keycloak_cache$https_discovery)
  }

  disc_url <- paste0(get_https_issuer(), "/.well-known/openid-configuration")
  resp <- httr2::request(disc_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_perform()

  if (httr2::resp_is_error(resp)) {
    stop("Keycloak HTTPS discovery request failed", call. = FALSE)
  }

  keycloak_cache$https_discovery <- httr2::resp_body_json(
    resp,
    simplifyVector = TRUE
  )
  keycloak_cache$https_discovery
}

get_jwks <- function(force = FALSE) {
  if (!isTRUE(force) && !is.null(keycloak_cache$jwks)) {
    return(keycloak_cache$jwks)
  }

  disc <- get_discovery_document(force = force)
  jwks_url <- disc[["jwks_uri"]] %||% NA_character_
  stopifnot(
    is.character(jwks_url) && length(jwks_url) == 1L && nzchar(jwks_url)
  )

  resp <- httr2::request(jwks_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_perform()

  if (httr2::resp_is_error(resp)) {
    stop("Keycloak JWKS request failed", call. = FALSE)
  }

  keycloak_cache$jwks <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  keycloak_cache$jwks
}

get_request_object_encryption_kid <- function(alg = "RSA-OAEP") {
  candidates <- try(
    shinyOAuth:::select_candidate_jwks_for_encryption(
      jwks_or_keys = get_jwks(),
      alg = alg
    ),
    silent = TRUE
  )
  if (inherits(candidates, "try-error") || length(candidates) == 0L) {
    return(NA_character_)
  }

  candidate_scores <- vapply(
    candidates,
    shinyOAuth:::rank_request_object_encryption_jwk,
    integer(1),
    alg = alg
  )
  candidates <- candidates[candidate_scores == max(candidate_scores)]

  for (candidate in candidates) {
    kid <- candidate[["kid"]] %||% NA_character_
    if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
      return(kid)
    }
  }

  NA_character_
}

keycloak_reachable <- function() {
  ok <- tryCatch(
    {
      disc <- get_discovery_document(force = TRUE)
      is.list(disc) &&
        identical(
          disc[["issuer"]] %||% NA_character_,
          get_issuer()
        )
    },
    error = function(...) FALSE
  )
  isTRUE(ok)
}

keycloak_https_reachable <- function() {
  ok <- tryCatch(
    {
      disc <- get_https_discovery_document(force = TRUE)
      is.list(disc) &&
        identical(
          disc[["issuer"]] %||% NA_character_,
          get_https_issuer()
        )
    },
    error = function(...) FALSE
  )
  isTRUE(ok)
}

maybe_skip_keycloak <- function() {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )
}

maybe_skip_keycloak_https <- function() {
  testthat::skip_if_not(
    keycloak_https_reachable(),
    "Keycloak HTTPS not reachable at localhost:8443"
  )
}

## Standard local_options for headless protocol testServer tests
local_test_options <- function(.local_envir = parent.frame()) {
  ca_file <- get_keycloak_tls_ca_file()

  # These tests intentionally bypass the real browser cookie boundary so they
  # can focus on OAuth/OIDC protocol behavior inside testServer. Browser-origin,
  # SameSite, and live redirect behavior are covered by the *_browser*.R and
  # *_e2e.R tests.
  withr::local_options(
    list(
      shinyOAuth.skip_browser_token = TRUE,
      shinyOAuth.timeout = 10
    ),
    .local_envir = .local_envir
  )

  if (is.character(ca_file) && length(ca_file) == 1L && nzchar(ca_file)) {
    withr::local_envvar(
      c(CURL_CA_BUNDLE = ca_file),
      .local_envir = .local_envir
    )
  }
}

## Standard skip checks for testServer tests
skip_common <- function() {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
}

skip_mtls_common <- function() {
  skip_common()
  maybe_skip_keycloak_https()
}

## ---------- Browser E2E helpers ----------

keycloak_browser_port_in_use <- function(port) {
  con <- suppressWarnings(try(
    socketConnection(
      host = "127.0.0.1",
      port = as.integer(port),
      server = FALSE,
      blocking = TRUE,
      open = "r+",
      timeout = 1
    ),
    silent = TRUE
  ))
  if (!inherits(con, "try-error")) {
    try(close(con), silent = TRUE)
    return(TRUE)
  }
  FALSE
}

keycloak_wait_for_login_or_auth_result <- function(
  drv,
  auth_selector = "#auth_state",
  timeout = 10000,
  interval = 0.25
) {
  deadline <- Sys.time() + (timeout / 1000)
  auth_selector_json <- jsonlite::toJSON(auth_selector, auto_unbox = TRUE)

  while (Sys.time() < deadline) {
    state <- drv$get_js(
      paste0(
        "(function () {",
        "  if (document.querySelector('#kc-login')) { return 'login'; }",
        "  var el = document.querySelector(",
        auth_selector_json,
        ");",
        "  if (!el) { return ''; }",
        "  var text = el.innerText || '';",
        "  if (text.includes('authenticated: TRUE')) { return 'done'; }",
        "  if ((text.includes('error_description:') && ",
        "      !text.includes('error_description: <none>')) || ",
        "      (text.includes('error_desc:') && ",
        "      !text.includes('error_desc: <none>'))) {",
        "    return 'done';",
        "  }",
        "  return '';",
        "})()"
      )
    )

    if (identical(state, "login") || identical(state, "done")) {
      return(state)
    }

    Sys.sleep(interval)
  }

  stop(
    "Timed out waiting for a Keycloak login form or auth result",
    call. = FALSE
  )
}

keycloak_submit_browser_login <- function(
  drv,
  username = "alice",
  password = username,
  auth_selector = "#auth_state",
  timeout = 20000,
  interval = 0.25
) {
  login_state <- keycloak_wait_for_login_or_auth_result(
    drv,
    auth_selector = auth_selector,
    timeout = timeout,
    interval = interval
  )
  if (identical(login_state, "done")) {
    return(invisible("already-authenticated"))
  }

  auth_selector_json <- jsonlite::toJSON(auth_selector, auto_unbox = TRUE)
  username_json <- jsonlite::toJSON(username, auto_unbox = TRUE)
  password_json <- jsonlite::toJSON(password, auto_unbox = TRUE)

  drv$run_js(
    paste0(
      "(function () {",
      "  var authState = document.querySelector(",
      auth_selector_json,
      ");",
      "  var authText = authState ? (authState.innerText || '') : '';",
      "  if (authText.indexOf('authenticated: TRUE') !== -1) {",
      "    return 'already-authenticated';",
      "  }",
      "  var login = document.querySelector('#kc-login');",
      "  var form = login && login.form ? login.form : document.querySelector('form');",
      "  var usernameInput = document.querySelector('#username');",
      "  var passwordInput = document.querySelector('#password');",
      "  if (!(form && login && usernameInput && passwordInput)) {",
      "    return 'login-form-missing';",
      "  }",
      "  function setValue(input, value) {",
      "    input.focus();",
      "    input.value = value;",
      "    input.dispatchEvent(new Event('input', { bubbles: true }));",
      "    input.dispatchEvent(new Event('change', { bubbles: true }));",
      "  }",
      "  setValue(usernameInput, ",
      username_json,
      ");",
      "  setValue(passwordInput, ",
      password_json,
      ");",
      "  HTMLFormElement.prototype.submit.call(form);",
      "  return 'submitted';",
      "})()"
    )
  )
}

keycloak_get_auth_state_robust <- function(
  drv,
  auth_selector = "#auth_state",
  max_attempts = 10,
  delay = 0.5
) {
  auth_selector_json <- jsonlite::toJSON(auth_selector, auto_unbox = TRUE)

  for (i in seq_len(max_attempts)) {
    auth_state <- drv$get_js(
      paste0(
        "(function () {",
        "  var el = document.querySelector(",
        auth_selector_json,
        ");",
        "  return el ? (el.innerText || '') : '';",
        "})()"
      )
    )

    if (
      nchar(auth_state) > 0 &&
        (grepl("authenticated: TRUE", auth_state, fixed = TRUE) ||
          !grepl("error_description: <none>", auth_state, fixed = TRUE))
    ) {
      return(trimws(auth_state))
    }

    Sys.sleep(delay)
  }

  ""
}

browser_cookie_name <- function(id, prefix = "shinyOAuth_sid") {
  ns_hash <- substr(as.character(openssl::sha256(paste0(id, "-"))), 1, 8)
  paste0(prefix, "-", id, "-", ns_hash)
}

browser_cookie_candidates <- function(id) {
  c(
    browser_cookie_name(id),
    browser_cookie_name(id, prefix = "__Host-shinyOAuth_sid")
  )
}

get_browser_cookie <- function(drv, name) {
  cookies <- drv$get_chromote_session()$Network$getAllCookies()[[
    "cookies",
    exact = TRUE
  ]]
  matches <- Filter(
    function(cookie) identical(cookie[["name"]], name),
    cookies
  )
  if (length(matches) == 0L) {
    return(NULL)
  }

  testthat::expect_length(matches, 1L)
  matches[[1]]
}

wait_for_browser_cookie <- function(
  drv,
  name,
  timeout = 8,
  idle_ms = 200
) {
  deadline <- Sys.time() + timeout

  repeat {
    cookie <- get_browser_cookie(drv, name)
    if (!is.null(cookie)) {
      return(cookie)
    }
    if (Sys.time() > deadline) {
      return(NULL)
    }
    drv$wait_for_idle(idle_ms)
  }
}

find_browser_token_cookie <- function(
  drv,
  id,
  timeout = 8,
  idle_ms = 200
) {
  deadline <- Sys.time() + timeout
  names <- browser_cookie_candidates(id)

  repeat {
    for (name in names) {
      cookie <- get_browser_cookie(drv, name)
      if (!is.null(cookie)) {
        return(cookie)
      }
    }
    if (Sys.time() > deadline) {
      return(NULL)
    }
    drv$wait_for_idle(idle_ms)
  }
}

## ---------- URL / cookie helpers ----------

parse_query_param <- function(url, name, decode = FALSE) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(NA_character_)
  }
  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  if (decode) {
    vals <- vapply(
      kv,
      function(p) if (length(p) > 1) utils::URLdecode(p[2]) else "",
      ""
    )
    names(vals) <- vapply(kv, function(p) utils::URLdecode(p[1]), "")
  } else {
    vals <- vapply(
      kv,
      function(p) if (length(p) > 1) p[2] else "",
      ""
    )
    names(vals) <- vapply(kv, function(p) p[1], "")
  }
  if (name %in% names(vals)) {
    vals[[name]]
  } else {
    NA_character_
  }
}

callback_query <- function(
  login_result,
  code = login_result[["code"]] %||% NA_character_,
  state = login_result[["state_payload"]] %||% NA_character_,
  iss = parse_query_param(
    login_result[["callback_url"]] %||% NA_character_,
    "iss",
    decode = TRUE
  )
) {
  callback_url <- login_result[["callback_url"]] %||%
    NA_character_
  response <- login_result[["response"]] %||% NA_character_

  if (
    !keycloak_nonempty_string(response) &&
      is.list(login_result[["form_post_fields"]])
  ) {
    response <- login_result[["form_post_fields"]][[
      "response",
      exact = TRUE
    ]] %||%
      NA_character_
  }
  if (
    !is.character(callback_url) ||
      length(callback_url) != 1L ||
      is.na(callback_url) ||
      !nzchar(callback_url) ||
      !grepl("?", callback_url, fixed = TRUE)
  ) {
    stop(
      "login_result$callback_url must be a non-empty callback URL",
      call. = FALSE
    )
  }

  if (keycloak_nonempty_string(response)) {
    return(paste0(
      "?response=",
      utils::URLencode(response, reserved = TRUE)
    ))
  }

  parts <- shiny::parseQueryString(
    sub("^\\?", "", sub("^[^?]*", "", callback_url)),
    nested = FALSE
  )
  parts[["code"]] <- code
  parts[["state"]] <- state
  parts[["iss"]] <- iss

  keep <- vapply(
    parts,
    function(value) {
      is.character(value) &&
        length(value) == 1L &&
        !is.na(value)
    },
    logical(1)
  )
  parts <- parts[keep]

  paste0(
    "?",
    paste(
      vapply(
        names(parts),
        function(name) {
          paste0(
            utils::URLencode(name, reserved = TRUE),
            "=",
            utils::URLencode(parts[[name]], reserved = TRUE)
          )
        },
        ""
      ),
      collapse = "&"
    )
  )
}

get_cookies <- function(resp) {
  sc <- httr2::resp_headers(resp)[
    tolower(names(httr2::resp_headers(resp))) == "set-cookie"
  ]
  if (length(sc) == 0) {
    return("")
  }
  kv <- vapply(sc, function(x) sub(";.*$", "", x), "")
  paste(kv, collapse = "; ")
}

merge_cookies <- function(cookie_hdr, resp) {
  jar <- character()

  add_cookie_pairs <- function(header_value) {
    if (!is.character(header_value) || length(header_value) != 1L) {
      return(invisible(NULL))
    }
    if (is.na(header_value) || !nzchar(header_value)) {
      return(invisible(NULL))
    }

    pairs <- strsplit(header_value, "; ", fixed = TRUE)[[1]]
    for (pair in pairs) {
      if (!nzchar(pair) || !grepl("=", pair, fixed = TRUE)) {
        next
      }
      nm <- sub("=.*$", "", pair)
      jar[[nm]] <<- pair
    }

    invisible(NULL)
  }

  add_cookie_pairs(cookie_hdr)
  add_cookie_pairs(get_cookies(resp))

  if (!length(jar)) {
    return("")
  }

  paste(unname(jar), collapse = "; ")
}

parse_callback_redirect <- function(loc, redirect_uri) {
  loc_code <- parse_query_param(loc, "code", decode = TRUE)
  loc_state <- parse_query_param(loc, "state", decode = TRUE)

  is_callback <-
    (!is.na(redirect_uri) &&
      nzchar(redirect_uri) &&
      startsWith(loc, redirect_uri)) ||
    (is.na(redirect_uri) &&
      is.character(loc_code) &&
      nzchar(loc_code) &&
      is.character(loc_state) &&
      nzchar(loc_state))

  list(
    is_callback = isTRUE(is_callback),
    code = loc_code,
    state = loc_state
  )
}

parse_form_post_authorization_response <- function(
  resp,
  redirect_uri = NA_character_
) {
  html <- tryCatch(httr2::resp_body_string(resp), error = function(...) "")
  if (!is.character(html) || length(html) != 1L || !nzchar(html)) {
    return(NULL)
  }
  if (!grepl("<form", html, ignore.case = TRUE, fixed = FALSE)) {
    return(NULL)
  }

  doc <- tryCatch(xml2::read_html(html), error = function(...) NULL)
  if (is.null(doc)) {
    return(NULL)
  }

  forms <- rvest::html_elements(doc, "form")
  if (length(forms) == 0L) {
    return(NULL)
  }

  for (form in forms) {
    method <- rvest::html_attr(form, "method") %||% ""
    if (!identical(tolower(method), "post")) {
      next
    }

    action <- rvest::html_attr(form, "action") %||% ""
    if (!keycloak_nonempty_string(action)) {
      next
    }

    base_url <- resp[["url"]] %||% redirect_uri
    action_url <- to_abs(base_url, action)
    if (
      keycloak_nonempty_string(redirect_uri) &&
        !startsWith(action_url, redirect_uri)
    ) {
      next
    }

    inputs <- rvest::html_elements(form, "input")
    names <- rvest::html_attr(inputs, "name")
    vals <- rvest::html_attr(inputs, "value")
    keep <- !is.na(names) & nzchar(names)
    if (!any(keep)) {
      next
    }

    vals[is.na(vals)] <- ""
    fields <- as.list(stats::setNames(vals[keep], names[keep]))
    code <- fields[["code"]] %||% NA_character_
    state <- fields[["state"]] %||% NA_character_
    response <- fields[["response"]] %||% NA_character_

    if (keycloak_nonempty_string(response)) {
      return(list(
        code = code,
        state_payload = state,
        callback_url = action_url,
        form_post_fields = fields,
        response = response,
        response_mode = "form_post.jwt"
      ))
    }

    if (keycloak_nonempty_string(code) && keycloak_nonempty_string(state)) {
      return(list(
        code = code,
        state_payload = state,
        callback_url = action_url,
        form_post_fields = fields,
        response_mode = "form_post"
      ))
    }
  }

  NULL
}

follow_once <- function(resp, cookie_hdr) {
  loc <- httr2::resp_header(resp, "location")
  if (is.null(loc) || !nzchar(loc)) {
    return(list(done = TRUE, url = NA_character_, resp = resp))
  }
  next_url <- to_abs(resp[["url"]] %||% loc, loc)
  r <- httr2::request(next_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
  list(
    done = (httr2::resp_status(r) < 300 || httr2::resp_status(r) >= 400),
    url = next_url,
    resp = r
  )
}

to_abs <- function(base, path) {
  if (grepl("^https?://", path)) {
    return(path)
  }
  u <- httr2::url_parse(base)
  paste0(
    u[["scheme"]],
    "://",
    u[["hostname"]],
    if (!is.na(u[["port"]])) {
      paste0(":", u[["port"]])
    } else {
      ""
    },
    path
  )
}

## ---------- Factory functions ----------

make_provider_for_issuer <- function(
  issuer = get_issuer(),
  token_auth_style = "body",
  allowed_token_types = c("Bearer"),
  use_par = FALSE,
  jarm_tolerate_duplicate_top_level_iss = TRUE,
  ...
) {
  prov <- shinyOAuth::oauth_provider_oidc_discover(
    issuer = issuer,
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    jarm_tolerate_duplicate_top_level_iss = jarm_tolerate_duplicate_top_level_iss,
    ...
  )
  if (!isTRUE(use_par)) {
    prov@par_url <- NA_character_
  }
  prov
}

make_provider <- function(
  token_auth_style = "body",
  allowed_token_types = c("Bearer"),
  use_par = FALSE,
  jarm_tolerate_duplicate_top_level_iss = TRUE,
  ...
) {
  make_provider_for_issuer(
    issuer = get_issuer(),
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    use_par = use_par,
    jarm_tolerate_duplicate_top_level_iss = jarm_tolerate_duplicate_top_level_iss,
    ...
  )
}

make_mtls_provider <- function(
  token_auth_style = "tls_client_auth",
  allowed_token_types = c("Bearer"),
  use_par = FALSE,
  ...
) {
  prov <- shinyOAuth::oauth_provider_oidc_discover(
    issuer = get_https_issuer(),
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    ...
  )

  if (!isTRUE(use_par)) {
    prov@par_url <- NA_character_
  }
  prov
}

make_dpop_private_key <- function() {
  openssl::rsa_keygen()
}

get_pjwt_key <- function() {
  path <- NULL
  if (requireNamespace("testthat", quietly = TRUE)) {
    path <- testthat::test_path("keys", "test_rsa")
  }
  if (is.null(path) || !file.exists(path)) {
    path <- file.path("integration", "keycloak", "keys", "test_rsa")
  }
  if (!file.exists(path)) {
    return(NULL)
  }

  key <- try(openssl::read_key(path), silent = TRUE)
  if (inherits(key, "try-error")) {
    return(NULL)
  }

  key
}

get_pjwt_public_key_pem <- function() {
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  paste(capture.output(openssl::write_pem(key$pubkey)), collapse = "\n")
}

keycloak_temp_client_id <- function(prefix) {
  stopifnot(keycloak_nonempty_string(prefix))

  paste0(
    prefix,
    "-",
    tolower(substr(shinyOAuth:::random_urlsafe(12), 1L, 12L))
  )
}

keycloak_default_redirect_uris <- function() {
  list(
    "http://localhost:3000/*",
    "http://127.0.0.1:3000/*",
    "http://localhost:8100/*",
    "http://127.0.0.1:8100/*"
  )
}

keycloak_oidc_client_body <- function(
  client_id,
  public_client = FALSE,
  redirect_uris = keycloak_default_redirect_uris(),
  web_origins = list("+"),
  standard_flow_enabled = TRUE,
  implicit_flow_enabled = FALSE,
  service_accounts_enabled = FALSE,
  direct_access_grants_enabled = FALSE,
  client_authenticator_type = "client-secret",
  attributes = list()
) {
  stopifnot(keycloak_nonempty_string(client_id))

  list(
    clientId = client_id,
    protocol = "openid-connect",
    publicClient = isTRUE(public_client),
    redirectUris = redirect_uris,
    webOrigins = web_origins,
    standardFlowEnabled = isTRUE(standard_flow_enabled),
    implicitFlowEnabled = isTRUE(implicit_flow_enabled),
    serviceAccountsEnabled = isTRUE(service_accounts_enabled),
    directAccessGrantsEnabled = isTRUE(direct_access_grants_enabled),
    clientAuthenticatorType = client_authenticator_type,
    attributes = attributes
  )
}

keycloak_create_temp_mtls_jar_client <- function(
  token,
  client_id = keycloak_temp_client_id("shiny-mtls-jar-pjwt"),
  encrypted = FALSE
) {
  public_key_pem <- get_pjwt_public_key_pem()
  if (!keycloak_nonempty_string(public_key_pem)) {
    testthat::skip("private_key_jwt test key not available")
  }

  attributes <- list(
    "pkce.code.challenge.method" = "S256",
    "x509.subjectdn" = paste(
      "CN=shiny-mtls-client,OU=Tests,O=shinyOAuth,",
      "L=Local,ST=NA,C=US",
      sep = ""
    ),
    "x509.allow.regex.pattern.comparison" = "false",
    "tls.client.certificate.bound.access.tokens" = "true",
    "use.jwks.url" = "false",
    "jwt.credential.public.key" = public_key_pem,
    "request.object.signature.alg" = "RS256"
  )

  if (isTRUE(encrypted)) {
    attributes[["request.object.encryption.alg"]] <- "RSA-OAEP"
    attributes[["request.object.encryption.enc"]] <- "A256CBC-HS512"
  }

  keycloak_create_client(
    token = token,
    body = keycloak_oidc_client_body(
      client_id = client_id,
      public_client = FALSE,
      service_accounts_enabled = FALSE,
      client_authenticator_type = "client-x509",
      attributes = attributes
    )
  )
}

make_public_client <- function(
  prov,
  client_id = "shiny-public",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  dpop_private_key = NULL,
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = FALSE
) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid,
    dpop_signing_alg = dpop_signing_alg,
    dpop_require_access_token = dpop_require_access_token
  )
}

make_shortlived_public_client <- function(
  prov,
  client_id = "shiny-shortlived",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  dpop_private_key = NULL,
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = FALSE
) {
  make_public_client(
    prov = prov,
    client_id = client_id,
    redirect_uri = redirect_uri,
    scopes = scopes,
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid,
    dpop_signing_alg = dpop_signing_alg,
    dpop_require_access_token = dpop_require_access_token
  )
}

make_dpop_public_client <- function(
  prov,
  client_id = "shiny-dpop-public",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  dpop_private_key = make_dpop_private_key(),
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = TRUE
) {
  make_public_client(
    prov = prov,
    client_id = client_id,
    redirect_uri = redirect_uri,
    scopes = scopes,
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid,
    dpop_signing_alg = dpop_signing_alg,
    dpop_require_access_token = dpop_require_access_token
  )
}

make_dpop_shortlived_public_client <- function(
  prov,
  client_id = "shiny-dpop-shortlived",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  dpop_private_key = make_dpop_private_key(),
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = TRUE
) {
  make_shortlived_public_client(
    prov = prov,
    client_id = client_id,
    redirect_uri = redirect_uri,
    scopes = scopes,
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid,
    dpop_signing_alg = dpop_signing_alg,
    dpop_require_access_token = dpop_require_access_token
  )
}

make_confidential_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid")
  )
}

make_mtls_confidential_client <- function(
  prov,
  client_id = "shiny-mtls-confidential",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file()
  )
}

make_mtls_service_client <- function(
  prov,
  client_id = "shiny-mtls-service",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file()
  )
}

get_mtls_endpoint_url <- function(provider, endpoint) {
  aliases <- provider@mtls_endpoint_aliases %||% list()
  alias <- aliases[[endpoint]] %||% NA_character_
  if (
    is.character(alias) &&
      length(alias) == 1L &&
      !is.na(alias) &&
      nzchar(alias)
  ) {
    return(alias)
  }

  switch(
    endpoint,
    token_endpoint = provider@token_url,
    userinfo_endpoint = provider@userinfo_url,
    introspection_endpoint = provider@introspection_url,
    revocation_endpoint = provider@revocation_url,
    stop("Unsupported mTLS endpoint: ", endpoint, call. = FALSE)
  )
}

perform_mtls_code_login <- function(
  client,
  username = "alice",
  password = username
) {
  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = "__SKIPPED__"
  )
  login <- perform_login_form_as(
    auth_url,
    username = username,
    password = password,
    redirect_uri = client@redirect_uri
  )
  state <- get_state_store_entry(client, auth_url)

  list(
    auth_url = auth_url,
    code = login[["code"]],
    state_payload = login[["state_payload"]],
    state = state,
    code_verifier = state[["entry"]][[
      "pkce_code_verifier",
      exact = TRUE
    ]],
    browser_token = state[["entry"]][[
      "browser_token",
      exact = TRUE
    ]]
  )
}

raw_mtls_token_request <- function(
  provider,
  params,
  cert_variant = c("valid", "wrong", "rogue", "none"),
  token_url = NULL
) {
  cert_variant <- match.arg(cert_variant)
  token_url <- token_url %||% get_mtls_endpoint_url(provider, "token_endpoint")

  req <- httr2::request(token_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_method("POST")

  if (!identical(cert_variant, "none")) {
    req <- req_apply_keycloak_client_certificate(req, cert_variant)
  }

  req <- do.call(httr2::req_body_form, c(list(req), params))
  req |> httr2::req_perform()
}

raw_mtls_auth_code_exchange <- function(
  client,
  code_login,
  cert_variant = c("valid", "wrong", "rogue", "none"),
  client_id = client@client_id
) {
  cert_variant <- match.arg(cert_variant)
  params <- list(
    grant_type = "authorization_code",
    code = code_login[["code"]],
    redirect_uri = client@redirect_uri,
    code_verifier = code_login[["code_verifier"]],
    client_id = client_id
  )

  raw_mtls_token_request(
    provider = client@provider,
    params = params,
    cert_variant = cert_variant
  )
}

raw_mtls_client_credentials_request <- function(
  client,
  cert_variant = c("valid", "wrong", "rogue", "none"),
  scope = NULL,
  client_id = client@client_id
) {
  cert_variant <- match.arg(cert_variant)
  params <- list(
    grant_type = "client_credentials",
    client_id = client_id
  )
  if (is.character(scope) && length(scope) > 0L && any(nzchar(scope))) {
    params[["scope"]] <- paste(scope, collapse = " ")
  }

  raw_mtls_token_request(
    provider = client@provider,
    params = params,
    cert_variant = cert_variant
  )
}

raw_mtls_userinfo_request <- function(
  client,
  access_token,
  token_type = "Bearer",
  cert_variant = c("valid", "wrong", "rogue", "none")
) {
  cert_variant <- match.arg(cert_variant)
  provider <- if (S7::S7_inherits(client, shinyOAuth::OAuthClient)) {
    client@provider
  } else {
    client
  }
  userinfo_url <- get_mtls_endpoint_url(provider, "userinfo_endpoint")

  req <- httr2::request(userinfo_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(
      Accept = "application/json",
      Authorization = paste(token_type, access_token)
    )

  if (!identical(cert_variant, "none")) {
    req <- req_apply_keycloak_client_certificate(req, cert_variant)
  }

  req |> httr2::req_perform()
}

safe_resp_body_json <- function(resp) {
  parsed <- try(
    httr2::resp_body_json(resp, simplifyVector = TRUE),
    silent = TRUE
  )
  if (inherits(parsed, "try-error") || !is.list(parsed)) {
    return(list())
  }
  parsed
}

expect_mtls_invalid_client <- function(resp) {
  testthat::expect_true(httr2::resp_status(resp) %in% c(400L, 401L))
  body <- safe_resp_body_json(resp)
  combo <- paste(
    body[["error"]] %||% "",
    body[["error_description"]] %||% ""
  )
  testthat::expect_match(
    combo,
    "invalid_client|unauthorized_client|invalid_client_credentials",
    ignore.case = TRUE
  )
  invisible(resp)
}

expect_mtls_sender_constraint_rejection <- function(resp) {
  testthat::expect_identical(httr2::resp_status(resp), 401L)

  body <- safe_resp_body_json(resp)
  challenge <- httr2::resp_header(resp, "www-authenticate") %||% ""
  combo <- paste(body[["error"]] %||% "", challenge)

  testthat::expect_match(challenge, "Bearer", ignore.case = TRUE)
  testthat::expect_match(combo, "invalid_token", fixed = TRUE)
  invisible(resp)
}

get_client_secret_jwt_secret <- function() {
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
}

make_client_secret_jwt_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = get_client_secret_jwt_secret(),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256"
  )
}

make_private_key_jwt_client <- function(prov) {
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-pjwt",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_private_key = key,
    client_assertion_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_
  )
}

make_private_key_jar_client <- function(
  prov,
  client_id = "shiny-jar-pjwt",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  response_mode = NULL
) {
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    client_assertion_private_key = key,
    client_assertion_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_,
    request_object_mode = "request",
    request_object_signing_alg = "RS256",
    response_mode = response_mode
  )
}

make_private_key_jar_jwe_client <- function(
  prov,
  client_id = "shiny-jar-pjwt-jwe",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid")
) {
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    client_assertion_private_key = key,
    client_assertion_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_,
    request_object_mode = "request",
    request_object_signing_alg = "RS256",
    request_object_encryption_alg = "RSA-OAEP",
    request_object_encryption_enc = "A256CBC-HS512",
    request_object_encryption_kid = get_request_object_encryption_kid()
  )
}

make_mtls_private_key_jar_client <- function(
  prov,
  client_id = "shiny-mtls-jar-pjwt",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file(),
    client_assertion_private_key = key,
    client_assertion_private_key_kid = NA_character_,
    request_object_mode = "request",
    request_object_signing_alg = "RS256"
  )
}

make_mtls_private_key_jar_jwe_client <- function(
  prov,
  client_id = "shiny-mtls-jar-pjwt-jwe",
  redirect_uri = "http://localhost:3000/callback",
  scopes = c("openid"),
  cert_variant = c("valid", "wrong", "rogue")
) {
  cert_variant <- match.arg(cert_variant)
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = redirect_uri,
    scopes = scopes,
    mtls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    mtls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    mtls_client_ca_file = get_keycloak_tls_ca_file(),
    client_assertion_private_key = key,
    client_assertion_private_key_kid = NA_character_,
    request_object_mode = "request",
    request_object_signing_alg = "RS256",
    request_object_encryption_alg = "RSA-OAEP",
    request_object_encryption_enc = "A256CBC-HS512",
    request_object_encryption_kid = get_request_object_encryption_kid()
  )
}

make_hmac_jar_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-jar-hmac",
    client_secret = "hs256-request-object-secret-32b!",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    request_object_mode = "request",
    request_object_signing_alg = "HS256"
  )
}

make_hmac_jar_jwe_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-jar-hmac-jwe",
    client_secret = "hs256-request-object-secret-32b!",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    request_object_mode = "request",
    request_object_signing_alg = "HS256",
    request_object_encryption_alg = "RSA-OAEP",
    request_object_encryption_enc = "A256CBC-HS512",
    request_object_encryption_kid = get_request_object_encryption_kid()
  )
}

## ---------- Login form driver ----------

#' Drive the Keycloak login form headlessly
#'
#' Given an authorization URL, fetches the HTML login page from Keycloak,
#' fills in credentials, submits the form, and follows redirects until the
#' authorization code is captured at the redirect_uri. This drives the flow
#' over HTTP without a real browser, so it is appropriate for protocol coverage
#' but does not prove cookie-boundary, SameSite, or live redirect behavior.
#'
#' @param auth_url Full authorization URL including state, PKCE, etc.
#' @param username Keycloak username (default "alice")
#' @param password Keycloak password (default "alice")
#' @param redirect_uri Optional redirect URI used to detect the final callback
#'   hop. When omitted, this is parsed from `auth_url` if present.
#' @return A list with `code` (authorization code), `state_payload`
#'   (the state returned on the callback), and `callback_url`
#'   (the final redirect URL back to the client).
perform_login_form_as <- function(
  auth_url,
  username = "alice",
  password = "alice",
  redirect_uri = NA_character_
) {
  code <- NA_character_
  callback_url <- NA_character_
  state_payload <- parse_query_param(auth_url, "state", decode = TRUE)

  if (!is.character(redirect_uri) || length(redirect_uri) != 1L) {
    redirect_uri <- NA_character_
  }
  if (is.na(redirect_uri) || !nzchar(redirect_uri)) {
    redirect_uri <- parse_query_param(auth_url, "redirect_uri", decode = TRUE)
  }

  resp1 <- httr2::request(auth_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
  stopifnot(!httr2::resp_is_error(resp1))
  cookie_hdr <- merge_cookies("", resp1)
  current_url <- auth_url
  cur_resp <- resp1

  for (i in seq_len(5)) {
    status <- httr2::resp_status(cur_resp)
    if (status < 300 || status >= 400) {
      break
    }

    loc <- httr2::resp_header(cur_resp, "location")
    stopifnot(nzchar(loc))

    callback <- parse_callback_redirect(loc, redirect_uri)
    if (isTRUE(callback[["is_callback"]])) {
      callback_url <- loc
      code <- callback[["code"]]
      if (
        is.character(callback[["state"]]) &&
          nzchar(callback[["state"]])
      ) {
        state_payload <- callback[["state"]]
      }
      return(list(
        code = code,
        state_payload = state_payload,
        callback_url = callback_url
      ))
    }

    step <- follow_once(cur_resp, cookie_hdr)
    cur_resp <- step[["resp"]]
    current_url <- step[["url"]] %||% current_url
    cookie_hdr <- merge_cookies(cookie_hdr, cur_resp)
  }

  form_post <- parse_form_post_authorization_response(
    cur_resp,
    redirect_uri = redirect_uri
  )
  if (!is.null(form_post)) {
    return(form_post)
  }

  html <- httr2::resp_body_string(cur_resp)
  doc <- xml2::read_html(html)
  form <- rvest::html_element(doc, "form")
  stopifnot(!is.na(rvest::html_name(form)))
  action <- rvest::html_attr(form, "action")
  stopifnot(is.character(action) && nzchar(action))
  inputs <- rvest::html_elements(form, "input")
  names <- rvest::html_attr(inputs, "name")
  vals <- rvest::html_attr(inputs, "value")
  data <- as.list(stats::setNames(vals, names))
  data <- data[!is.na(names) & nzchar(names)]
  data[["username"]] <- username
  data[["password"]] <- password
  post_url <- to_abs(current_url, action)
  req_post <- httr2::request(post_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
    httr2::req_options(followlocation = FALSE)
  req_post <- do.call(httr2::req_body_form, c(list(req_post), data))
  post_resp <- httr2::req_perform(req_post)
  cookie_hdr <- merge_cookies(cookie_hdr, post_resp)
  cur_resp <- post_resp
  for (i in seq_len(5)) {
    status <- httr2::resp_status(cur_resp)
    if (status >= 300 && status < 400) {
      loc <- httr2::resp_header(cur_resp, "location")
      stopifnot(nzchar(loc))
      callback <- parse_callback_redirect(loc, redirect_uri)
      if (isTRUE(callback[["is_callback"]])) {
        callback_url <- loc
        code <- callback[["code"]]
        if (
          is.character(callback[["state"]]) &&
            nzchar(callback[["state"]])
        ) {
          state_payload <- callback[["state"]]
        }
        break
      }
      step <- follow_once(cur_resp, cookie_hdr)
      cur_resp <- step[["resp"]]
      current_url <- step[["url"]] %||% current_url
      cookie_hdr <- merge_cookies(cookie_hdr, cur_resp)
    } else {
      break
    }
  }
  form_post <- parse_form_post_authorization_response(
    cur_resp,
    redirect_uri = redirect_uri
  )
  if (!is.null(form_post)) {
    return(form_post)
  }

  stopifnot(is.character(code) && nzchar(code))
  list(
    code = code,
    state_payload = state_payload,
    callback_url = callback_url
  )
}

#' Convenience wrapper: login as alice (default)
perform_login_form <- function(auth_url, redirect_uri = NA_character_) {
  perform_login_form_as(
    auth_url,
    "alice",
    "alice",
    redirect_uri = redirect_uri
  )
}

## ---------- State store manipulation helpers ----------

#' Decrypt state and get the cache key
#' @return list(sealed, dec, key) where sealed is the raw state param,
#'   dec is the decrypted payload, and key is the cache key
get_state_info <- function(client, auth_url) {
  sealed <- parse_query_param(auth_url, "state")
  if (
    is.character(sealed) &&
      length(sealed) == 1L &&
      !is.na(sealed) &&
      nzchar(sealed)
  ) {
    dec <- shinyOAuth:::state_payload_decrypt_validate(client, sealed)
    key <- shinyOAuth:::state_cache_key(dec[["state"]])
  } else {
    keys <- sort(client@state_store$keys())
    if (length(keys) != 1L || !nzchar(keys[[1]])) {
      stop(
        "Could not infer a unique state-store key from the authorization URL",
        call. = FALSE
      )
    }
    dec <- NULL
    key <- keys[[1]]
  }
  list(sealed = sealed, dec = dec, key = key)
}

#' Get the state store entry for the given auth URL
get_state_store_entry <- function(client, auth_url) {
  info <- get_state_info(client, auth_url)
  orig <- client@state_store$get(info[["key"]], missing = NULL)
  stopifnot(is.list(orig))
  list(info = info, entry = orig)
}

resolve_state_store_key <- function(state_ref) {
  if (
    is.list(state_ref) &&
      keycloak_nonempty_string(state_ref[["key"]] %||% NA_character_)
  ) {
    return(state_ref[["key"]])
  }

  if (is.list(state_ref)) {
    nested_info <- state_ref[["info"]] %||% NULL
    if (is.list(nested_info)) {
      return(resolve_state_store_key(nested_info))
    }
  }

  if (keycloak_nonempty_string(state_ref)) {
    return(state_ref)
  }

  stop("state_ref must be a state-store key or state-info list", call. = FALSE)
}

#' Expect a pending state-store entry to still exist
#'
#' @param client OAuth client under test.
#' @param state_ref Output from `get_state_info()`, `get_state_store_entry()`, or
#'   a state-store key string.
#' @param info Optional failure message for `testthat`.
#'
#' @return Invisibly returns the cached state-store entry.
#' @keywords internal
#' @noRd
expect_state_store_entry_present <- function(client, state_ref, info = NULL) {
  key <- resolve_state_store_key(state_ref)
  entry <- client@state_store$get(key, missing = NULL)

  testthat::expect_false(
    is.null(entry),
    info = info %||% paste("Expected state-store entry to remain pending:", key)
  )

  invisible(entry)
}

#' Expect a state-store entry to be consumed
#'
#' @param client OAuth client under test.
#' @param state_ref Output from `get_state_info()`, `get_state_store_entry()`, or
#'   a state-store key string.
#' @param info Optional failure message for `testthat`.
#'
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
expect_state_store_entry_consumed <- function(client, state_ref, info = NULL) {
  key <- resolve_state_store_key(state_ref)

  testthat::expect_null(
    client@state_store$get(key, missing = NULL),
    info = info %||% paste("Expected state-store entry to be consumed:", key)
  )

  invisible(NULL)
}

#' Expect a specific number of pending state-store entries
#'
#' @param client OAuth client under test.
#' @param n Expected number of pending entries.
#' @param info Optional failure message for `testthat`.
#'
#' @return Invisibly returns the current state-store keys.
#' @keywords internal
#' @noRd
expect_state_store_size <- function(client, n, info = NULL) {
  keys <- client@state_store$keys()
  testthat::expect_equal(
    length(keys),
    n,
    info = info %||% paste("Expected", n, "pending state-store entr(y/ies)")
  )

  invisible(keys)
}

#' Replace state store entry with a modified copy
set_state_store_entry <- function(client, key, new_entry) {
  client@state_store$set(key = key, value = new_entry)
}

decode_compact_jwt_payload <- function(jwt) {
  shinyOAuth:::parse_jwt_payload(jwt)
}

#' Normalize scalar or vector token claims to characters
#'
#' Used by the Keycloak protocol-integration tests so JWT claims can be checked
#' consistently regardless of whether a provider returns scalars, vectors, or
#' short lists.
#'
#' @param value Claim value to normalize.
#' @return Character vector containing non-missing, non-empty values.
#' @keywords internal
#' @noRd
normalize_claim_values <- function(value) {
  if (is.null(value)) {
    return(character(0))
  }

  out <- unlist(value, use.names = FALSE)
  out <- as.character(out)
  out <- out[!is.na(out)]
  out[nzchar(out)]
}

#' Assert shared Keycloak login security invariants
#'
#' Used after `oauth_module_server()` finishes a headless protocol login in the
#' Keycloak integration tests.
#'
#' @param authenticated Module `authenticated` flag.
#' @param error Module `error` value.
#' @param error_description Module `error_description` value.
#' @param error_uri Module `error_uri` value.
#' @param token [shinyOAuth::OAuthToken] returned by the module.
#' @param client [shinyOAuth::OAuthClient] used for the login.
#' @param expected_scopes Expected scopes. Defaults to `client@scopes`.
#' @param expected_username Optional expected `preferred_username`.
#' @return No return value; called for its expectations.
#' @keywords internal
#' @noRd
expect_keycloak_module_login_invariants <- function(
  authenticated,
  error,
  error_description,
  error_uri,
  token,
  client,
  expected_scopes = client@scopes,
  expected_username = NULL
) {
  testthat::expect_true(isTRUE(authenticated))
  testthat::expect_null(error)
  testthat::expect_null(error_description)
  testthat::expect_null(error_uri)
  testthat::expect_false(is.null(token))
  testthat::expect_true(
    is.character(token@access_token) &&
      length(token@access_token) == 1L &&
      !is.na(token@access_token) &&
      nzchar(token@access_token)
  )

  allowed_token_types <- normalize_claim_values(
    client@provider@allowed_token_types
  )
  if (length(allowed_token_types) > 0L) {
    testthat::expect_true(
      tolower(token@token_type %||% "") %in% tolower(allowed_token_types),
      info = paste0(
        "Unexpected token_type: ",
        token@token_type %||% "<missing>"
      )
    )
  }

  expect_oidc_claims <-
    "openid" %in%
    normalize_claim_values(client@scopes) ||
    isTRUE(client@provider@id_token_required) ||
    isTRUE(client@provider@id_token_validation) ||
    isTRUE(client@provider@use_nonce)

  id_claims <- list()
  if (isTRUE(expect_oidc_claims)) {
    testthat::expect_true(
      is.character(token@id_token) &&
        length(token@id_token) == 1L &&
        !is.na(token@id_token) &&
        nzchar(token@id_token)
    )
    testthat::expect_true(isTRUE(token@id_token_validated))

    id_claims <- token@id_token_claims
    testthat::expect_identical(
      id_claims[["iss"]] %||% NA_character_,
      client@provider@issuer
    )
    testthat::expect_true(
      client@client_id %in%
        normalize_claim_values(
          id_claims[["aud"]] %||% NULL
        )
    )
    testthat::expect_true(
      is.character(id_claims[["sub"]]) &&
        length(id_claims[["sub"]]) == 1L &&
        !is.na(id_claims[["sub"]]) &&
        nzchar(id_claims[["sub"]])
    )

    if (isTRUE(client@provider@use_nonce)) {
      testthat::expect_true(
        is.character(id_claims[["nonce"]]) &&
          length(id_claims[["nonce"]]) == 1L &&
          !is.na(id_claims[["nonce"]]) &&
          nzchar(id_claims[["nonce"]])
      )
    }

    max_age_info <- shinyOAuth:::inspect_auth_max_age(
      client@provider@extra_auth_params
    )
    if (!is.null(max_age_info[["value"]])) {
      auth_time <- suppressWarnings(as.numeric(
        id_claims[["auth_time"]] %||% NA_real_
      ))
      testthat::expect_true(is.finite(auth_time))
    }
  }

  if (isTRUE(client@provider@userinfo_required)) {
    userinfo <- token@userinfo %||% list()
    testthat::expect_true(is.list(userinfo) && length(userinfo) > 0L)
    testthat::expect_true(
      is.character(userinfo[["sub"]]) &&
        length(userinfo[["sub"]]) == 1L &&
        !is.na(userinfo[["sub"]]) &&
        nzchar(userinfo[["sub"]])
    )

    if (length(id_claims) > 0L && isTRUE(token@id_token_validated)) {
      testthat::expect_identical(
        userinfo[["sub"]],
        id_claims[["sub"]]
      )
    }

    if (
      is.character(expected_username) &&
        length(expected_username) == 1L &&
        !is.na(expected_username) &&
        nzchar(expected_username)
    ) {
      testthat::expect_identical(
        userinfo[["preferred_username"]],
        expected_username
      )
    }
  }

  expected_scopes <- normalize_claim_values(expected_scopes)
  if (length(expected_scopes) > 0L) {
    testthat::expect_true(
      all(expected_scopes %in% normalize_claim_values(token@granted_scopes))
    )
  }
}

access_token_cnf_jkt <- function(access_token) {
  payload <- decode_compact_jwt_payload(access_token)
  cnf <- payload[["cnf"]] %||% list()
  cnf[["jkt"]] %||% NA_character_
}

access_token_cnf_x5t_s256 <- function(access_token) {
  payload <- decode_compact_jwt_payload(access_token)
  cnf <- payload[["cnf"]] %||% list()
  cnf[["x5t#S256"]] %||% NA_character_
}

## ---------- Standard testServer args ----------

default_module_args <- function(client, ...) {
  list(
    id = "auth",
    client = client,
    auto_redirect = FALSE,
    indefinite_session = TRUE,
    ...
  )
}
