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
  url <- req$url %||% NA_character_
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
  jwks_url <- disc$jwks_uri %||% NA_character_
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

keycloak_https_reachable <- function() {
  ok <- tryCatch(
    {
      disc <- get_https_discovery_document(force = TRUE)
      is.list(disc) &&
        identical(
          disc$issuer %||% NA_character_,
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

## Standard local_options for testServer-based tests
local_test_options <- function(.local_envir = parent.frame()) {
  ca_file <- get_keycloak_tls_ca_file()

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

follow_once <- function(resp, cookie_hdr) {
  loc <- httr2::resp_header(resp, "location")
  if (is.null(loc) || !nzchar(loc)) {
    return(list(done = TRUE, url = NA_character_, resp = resp))
  }
  next_url <- to_abs(resp$url %||% loc, loc)
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
  use_par = FALSE,
  ...
) {
  prov <- shinyOAuth::oauth_provider_oidc_discover(
    issuer = get_issuer(),
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    ...
  )
  if (!isTRUE(use_par)) {
    prov@par_url <- NA_character_
  }
  prov
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
    tls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    tls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    tls_client_ca_file = get_keycloak_tls_ca_file()
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
    tls_client_cert_file = get_keycloak_tls_client_cert_file(cert_variant),
    tls_client_key_file = get_keycloak_tls_client_key_file(cert_variant),
    tls_client_ca_file = get_keycloak_tls_ca_file()
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
    code = login$code,
    state_payload = login$state_payload,
    state = state,
    code_verifier = state$entry$pkce_code_verifier,
    browser_token = state$entry$browser_token
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
    code = code_login$code,
    redirect_uri = client@redirect_uri,
    code_verifier = code_login$code_verifier,
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
    params$scope <- paste(scope, collapse = " ")
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
  combo <- paste(body$error %||% "", body$error_description %||% "")
  testthat::expect_match(
    combo,
    "invalid_client|unauthorized_client|invalid_client_credentials",
    ignore.case = TRUE
  )
  invisible(resp)
}

expect_mtls_sender_constraint_rejection <- function(resp) {
  testthat::expect_true(httr2::resp_status(resp) %in% c(400L, 401L, 403L))
  body <- safe_resp_body_json(resp)
  challenge <- httr2::resp_header(resp, "www-authenticate") %||% ""
  combo <- paste(body$error %||% "", body$error_description %||% "", challenge)
  testthat::expect_match(
    combo,
    "invalid_token|certificate|cnf|mtls|tls|unauthorized",
    ignore.case = TRUE
  )
  invisible(resp)
}

make_client_secret_jwt_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = "secretjwt",
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
    client_private_key = key,
    client_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_
  )
}

make_private_key_jar_client <- function(prov) {
  key <- get_pjwt_key()
  if (is.null(key)) {
    return(NULL)
  }

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-jar-pjwt",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_private_key = key,
    client_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_,
    authorization_request_mode = "request",
    authorization_request_signing_alg = "RS256"
  )
}

make_hmac_jar_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-jar-hmac",
    client_secret = "hs256-request-object-secret-32b!",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    authorization_request_mode = "request",
    authorization_request_signing_alg = "HS256"
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
    if (isTRUE(callback$is_callback)) {
      callback_url <- loc
      code <- callback$code
      if (is.character(callback$state) && nzchar(callback$state)) {
        state_payload <- callback$state
      }
      return(list(
        code = code,
        state_payload = state_payload,
        callback_url = callback_url
      ))
    }

    step <- follow_once(cur_resp, cookie_hdr)
    cur_resp <- step$resp
    current_url <- step$url %||% current_url
    cookie_hdr <- merge_cookies(cookie_hdr, cur_resp)
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
      if (isTRUE(callback$is_callback)) {
        callback_url <- loc
        code <- callback$code
        if (is.character(callback$state) && nzchar(callback$state)) {
          state_payload <- callback$state
        }
        break
      }
      step <- follow_once(cur_resp, cookie_hdr)
      cur_resp <- step$resp
      current_url <- step$url %||% current_url
      cookie_hdr <- merge_cookies(cookie_hdr, cur_resp)
    } else {
      break
    }
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
    key <- shinyOAuth:::state_cache_key(dec$state)
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

access_token_cnf_x5t_s256 <- function(access_token) {
  payload <- decode_compact_jwt_payload(access_token)
  cnf <- payload$cnf %||% list()
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
