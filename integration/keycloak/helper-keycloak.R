## Shared helpers for Keycloak integration tests
##
## Sourced by individual test files to avoid duplicating infrastructure code.
## Provides: connectivity checks, query parsing, cookie handling,
## login-form driving, and factory functions for providers/clients.

get_issuer <- function() {
  "http://localhost:8080/realms/shinyoauth"
}

keycloak_cache <- local({
  env <- new.env(parent = emptyenv())
  env$discovery <- NULL
  env$jwks <- NULL
  env
})

get_discovery_document <- function(force = FALSE) {
  if (!isTRUE(force) && !is.null(keycloak_cache$discovery)) {
    return(keycloak_cache$discovery)
  }

  disc_url <- paste0(get_issuer(), "/.well-known/openid-configuration")
  resp <- httr2::request(disc_url) |>
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

get_jwks <- function(force = FALSE) {
  if (!isTRUE(force) && !is.null(keycloak_cache$jwks)) {
    return(keycloak_cache$jwks)
  }

  disc <- get_discovery_document(force = force)
  jwks_url <- disc$jwks_uri %||% NA_character_
  stopifnot(
    is.character(jwks_url) && length(jwks_url) == 1L && nzchar(jwks_url)
  )

  resp <- httr2::request(jwks_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_perform()

  if (httr2::resp_is_error(resp)) {
    stop("Keycloak JWKS request failed", call. = FALSE)
  }

  keycloak_cache$jwks <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  keycloak_cache$jwks
}

keycloak_reachable <- function() {
  ok <- tryCatch(
    {
      disc <- get_discovery_document(force = TRUE)
      is.list(disc) && identical(disc$issuer %||% NA_character_, get_issuer())
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

## Standard local_options for testServer-based tests
local_test_options <- function(.local_envir = parent.frame()) {
  withr::local_options(
    list(
      shinyOAuth.skip_browser_token = TRUE,
      shinyOAuth.timeout = 10
    ),
    .local_envir = .local_envir
  )
}

## Standard skip checks for testServer tests
skip_common <- function() {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
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
  vals[[name]] %||% NA_character_
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

follow_once <- function(resp, cookie_hdr) {
  loc <- httr2::resp_header(resp, "location")
  if (is.null(loc) || !nzchar(loc)) {
    return(list(done = TRUE, url = NA_character_, resp = resp))
  }
  r <- httr2::request(loc) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
  list(
    done = (httr2::resp_status(r) < 300 || httr2::resp_status(r) >= 400),
    url = loc,
    resp = r
  )
}

to_abs <- function(base, path) {
  if (grepl("^https?://", path)) {
    return(path)
  }
  u <- httr2::url_parse(base)
  paste0(
    u$scheme,
    "://",
    u$hostname,
    if (!is.na(u$port)) paste0(":", u$port) else "",
    path
  )
}

## ---------- Factory functions ----------

make_provider <- function(
  token_auth_style = "body",
  allowed_token_types = c("Bearer"),
  ...
) {
  shinyOAuth::oauth_provider_oidc_discover(
    issuer = get_issuer(),
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    ...
  )
}

make_dpop_private_key <- function() {
  openssl::rsa_keygen()
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

## ---------- Login form driver ----------

#' Drive the Keycloak login form headlessly
#'
#' Given an authorization URL, fetches the HTML login page from Keycloak,
#' fills in credentials, submits the form, and follows redirects until the
#' authorization code is captured at the redirect_uri.
#'
#' @param auth_url Full authorization URL including state, PKCE, etc.
#' @param username Keycloak username (default "alice")
#' @param password Keycloak password (default "alice")
#' @return A list with `code` (authorization code) and `state_payload`
#'   (the state query parameter from the auth URL).
perform_login_form_as <- function(
  auth_url,
  username = "alice",
  password = "alice"
) {
  resp1 <- httr2::request(auth_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
  stopifnot(!httr2::resp_is_error(resp1))
  html <- httr2::resp_body_string(resp1)
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
  cookie_hdr <- get_cookies(resp1)
  post_url <- to_abs(auth_url, action)
  req_post <- httr2::request(post_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
    httr2::req_options(followlocation = FALSE)
  req_post <- do.call(httr2::req_body_form, c(list(req_post), data))
  post_resp <- httr2::req_perform(req_post)
  code <- NA_character_
  cur_resp <- post_resp
  redirect_uri <- parse_query_param(auth_url, "redirect_uri", decode = TRUE)
  for (i in seq_len(5)) {
    status <- httr2::resp_status(cur_resp)
    if (status >= 300 && status < 400) {
      loc <- httr2::resp_header(cur_resp, "location")
      stopifnot(nzchar(loc))
      if (!is.na(redirect_uri) && startsWith(loc, redirect_uri)) {
        code <- parse_query_param(loc, "code", decode = TRUE)
        break
      }
      step <- follow_once(cur_resp, cookie_hdr)
      cur_resp <- step$resp
    } else {
      break
    }
  }
  stopifnot(is.character(code) && nzchar(code))
  list(code = code, state_payload = parse_query_param(auth_url, "state"))
}

#' Convenience wrapper: login as alice (default)
perform_login_form <- function(auth_url) {
  perform_login_form_as(auth_url, "alice", "alice")
}

## ---------- State store manipulation helpers ----------

#' Decrypt state and get the cache key
#' @return list(sealed, dec, key) where sealed is the raw state param,
#'   dec is the decrypted payload, and key is the cache key
get_state_info <- function(client, auth_url) {
  sealed <- parse_query_param(auth_url, "state")
  dec <- shinyOAuth:::state_payload_decrypt_validate(client, sealed)
  key <- shinyOAuth:::state_cache_key(dec$state)
  list(sealed = sealed, dec = dec, key = key)
}

#' Get the state store entry for the given auth URL
get_state_store_entry <- function(client, auth_url) {
  info <- get_state_info(client, auth_url)
  orig <- client@state_store$get(info$key, missing = NULL)
  stopifnot(is.list(orig))
  list(info = info, entry = orig)
}

#' Replace state store entry with a modified copy
set_state_store_entry <- function(client, key, new_entry) {
  client@state_store$set(key = key, value = new_entry)
}

decode_compact_jwt_payload <- function(jwt) {
  shinyOAuth:::parse_jwt_payload(jwt)
}

access_token_cnf_jkt <- function(access_token) {
  payload <- decode_compact_jwt_payload(access_token)
  cnf <- payload$cnf %||% list()
  cnf$jkt %||% NA_character_
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
