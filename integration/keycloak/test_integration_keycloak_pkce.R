## Integration tests: Keycloak PKCE authorization-code flow
##
## Goal: Demonstrate that PKCE is enforced for the public client and that tampering
## with the stored code_verifier (missing or incorrect) breaks the flow.
##
## We exercise three scenarios against the imported realm:
## 1. Happy path: public client `shiny-public` completes code flow with PKCE (S256)
## 2. Unhappy path: code_verifier removed from state store prior to callback
## 3. Unhappy path: code_verifier replaced with a different valid verifier (mismatch)
##
## Proof PKCE works: scenarios (2) and (3) fail while (1) succeeds.
## (2) fails locally before token exchange (state validation); (3) fails during token exchange
## with server-side rejection (invalid_grant) surfaced as an HTTP/token error.
##
## These tests follow the pattern used in `test_integration_keycloak_code_jwt_auth.R` to
## drive the login form headlessly (no browser) and capture the authorization code.

get_issuer <- function() {
  "http://localhost:8080/realms/shinyoauth"
}

keycloak_reachable <- function() {
  issuer <- get_issuer()
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
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

make_provider <- function() {
  shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
}

make_public_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "", # public client (no secret)
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid")
  )
}

## Helper to drive the login form and return list(code = ..., state_payload = ...)
perform_login_form <- function(auth_url) {
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
  data[["username"]] <- "alice"
  data[["password"]] <- "alice"
  cookie_hdr <- get_cookies(resp1)
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
  post_url <- to_abs(auth_url, action)
  req_post <- httr2::request(post_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
    httr2::req_options(followlocation = FALSE)
  req_post <- do.call(httr2::req_body_form, c(list(req_post), data))
  post_resp <- httr2::req_perform(req_post)
  # Follow redirects up to 5 times looking for code param at redirect_uri
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

testthat::test_that("Keycloak PKCE happy path (public client)", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 10
  ))
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))
      # Drive login form -> obtain code
      res <- perform_login_form(url)
      # Callback
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      # Assertions
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))
      testthat::expect_true(prov@use_pkce) # Provider PKCE enabled
    }
  )
})

testthat::test_that("Keycloak PKCE unhappy path: missing code_verifier", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 10
  ))
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      # Extract & decrypt payload to derive cache key
      sealed <- parse_query_param(url, "state")
      dec <- shinyOAuth:::state_payload_decrypt_validate(client, sealed)
      key <- shinyOAuth:::state_cache_key(dec$state)
      # Tamper: remove code_verifier from state store prior to login form
      orig <- client@state_store$get(key, missing = NULL)
      testthat::expect_true(is.list(orig))
      client@state_store$set(
        key = key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = NULL,
          nonce = orig$nonce
        )
      )
      # Proceed with login form to get code
      res <- perform_login_form(url)
      # Callback (should fail fast before token exchange)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      # Error description should mention PKCE/code verifier
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "code verifier|PKCE",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Keycloak PKCE unhappy path: wrong code_verifier", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 10
  ))
  prov <- make_provider()
  client <- make_public_client(prov)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      sealed <- parse_query_param(url, "state")
      dec <- shinyOAuth:::state_payload_decrypt_validate(client, sealed)
      key <- shinyOAuth:::state_cache_key(dec$state)
      # Tamper: replace code_verifier with a different valid one that won't match the original challenge
      orig <- client@state_store$get(key, missing = NULL)
      testthat::expect_true(is.list(orig))
      # Generate a different verifier (ensure different by simple loop)
      new_ver <- orig$pkce_code_verifier
      for (i in 1:5) {
        cand <- paste0(
          sample(c(letters, LETTERS, 0:9, '-', '_', '.', '~'), 64, TRUE),
          collapse = ''
        )
        if (!identical(cand, new_ver)) {
          new_ver <- cand
          break
        }
      }
      client@state_store$set(
        key = key,
        value = list(
          browser_token = orig$browser_token,
          pkce_code_verifier = new_ver,
          nonce = orig$nonce
        )
      )
      # Complete login form
      res <- perform_login_form(url)
      # Callback -> expect token exchange failure (server-side invalid_grant)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      # Should reference token exchange or HTTP failure; be tolerant of wording
      testthat::expect_true(grepl(
        "Token exchange failed|invalid_grant|http_",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})
