# Full authorization-code flow against Keycloak using JWT client authentication

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

make_provider <- function(style) {
  shinyOAuth::oauth_provider_oidc_discover(
    issuer = get_issuer(),
    token_auth_style = style
  )
}

# Resolve optional JWT inputs from repo test key
get_pjwt_key <- function() {
  # Use the repository-generated test key (resolve path robustly under testthat)
  path <- NULL
  if (requireNamespace("testthat", quietly = TRUE)) {
    # When running via test_dir('integration/keycloak'), this points at .../integration/keycloak
    path <- testthat::test_path("keys", "test_rsa")
  }
  if (is.null(path) || !file.exists(path)) {
    # Fallback when run from repo root or other working directories
    path <- file.path("integration", "keycloak", "keys", "test_rsa")
  }
  if (!file.exists(path)) {
    return(NULL)
  }
  # Prefer returning an openssl::key object to avoid parsing differences
  pk <- try(openssl::read_key(path), silent = TRUE)
  if (inherits(pk, "try-error")) {
    return(NULL)
  }
  pk
}

maybe_skip_keycloak <- function() {
  testthat::skip_if_not(
    keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )
}

parse_query_param <- function(url, name) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(NA_character_)
  }
  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  vals <- vapply(
    kv,
    function(p) if (length(p) > 1) utils::URLdecode(p[2]) else "",
    ""
  )
  names(vals) <- vapply(kv, function(p) utils::URLdecode(p[1]), "")
  vals[[name]] %||% NA_character_
}

get_cookies <- function(resp) {
  sc <- httr2::resp_headers(resp)[
    tolower(names(httr2::resp_headers(resp))) == "set-cookie"
  ]
  if (length(sc) == 0) {
    return("")
  }
  # Extract name=value before semicolon; join with '; '
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

cases <- list(
  list(
    name = "client_secret_jwt",
    style = "client_secret_jwt",
    include = function() TRUE,
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-csjwt",
        client_secret = "secretjwt",
        redirect_uri = "http://localhost:3000/callback",
        scopes = c("openid"),
        client_assertion_alg = "HS256"
      )
    }
  ),
  list(
    name = "private_key_jwt",
    style = "private_key_jwt",
    include = function() !is.null(get_pjwt_key()),
    client = function(prov) {
      shinyOAuth::oauth_client(
        provider = prov,
        client_id = "shiny-pjwt",
        client_secret = "", # not used
        redirect_uri = "http://localhost:3000/callback",
        scopes = c("openid"),
        client_private_key = get_pjwt_key(),
        client_private_key_kid = NA_character_,
        client_assertion_alg = NA_character_
      )
    }
  )
)

for (case in cases) {
  testthat::test_that(
    paste0("Keycloak code flow using JWT auth: ", case$name),
    {
      maybe_skip_keycloak()
      testthat::skip_if_not_installed("xml2")
      testthat::skip_if_not_installed("rvest")
      if (!isTRUE(case$include())) {
        testthat::skip(paste("Skipping", case$name, "— prerequisites not met"))
      }

      withr::local_options(list(
        shinyOAuth.skip_browser_token = TRUE,
        shinyOAuth.timeout = 10,
        shinyOAuth.disable_watchdog_warning = TRUE
      ))

      prov <- make_provider(case$style)
      client <- case$client(prov)

      # Drive the module inside a Shiny test server; build the real auth URL
      x <- shinyOAuth::use_shinyOAuth() # ensure resources loaded to silence watchdog
      shiny::testServer(
        app = shinyOAuth::oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        ),
        expr = {
          # 1) Build auth URL and capture state
          url <- values$build_auth_url()
          testthat::expect_true(is.character(url) && nzchar(url))
          st <- parse_query_param(url, "state")
          redirect_uri <- parse_query_param(url, "redirect_uri")
          testthat::expect_true(is.character(st) && nzchar(st))
          testthat::expect_true(
            is.character(redirect_uri) && nzchar(redirect_uri)
          )

          # 2) Fetch login page (no redirects), capture cookies, parse form
          resp1 <- httr2::request(url) |>
            httr2::req_error(is_error = function(resp) FALSE) |>
            httr2::req_headers(Accept = "text/html") |>
            httr2::req_options(followlocation = FALSE) |>
            httr2::req_perform()

          testthat::expect_false(httr2::resp_is_error(resp1))
          html <- httr2::resp_body_string(resp1)
          doc <- xml2::read_html(html)
          form <- rvest::html_element(doc, "form")
          testthat::expect_true(!is.na(rvest::html_name(form)))
          action <- rvest::html_attr(form, "action")
          testthat::expect_true(is.character(action) && nzchar(action))

          # Collect all inputs and seed form data
          inputs <- rvest::html_elements(form, "input")
          names <- rvest::html_attr(inputs, "name")
          vals <- rvest::html_attr(inputs, "value")
          data <- as.list(stats::setNames(vals, names))
          data <- data[!is.na(names) & nzchar(names)]
          data[["username"]] <- "alice"
          data[["password"]] <- "alice"

          cookie_hdr <- get_cookies(resp1)

          # Normalize action to absolute
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
          post_url <- to_abs(url, action)

          # 3) Submit login form, follow redirects to capture final code
          req_post <- httr2::request(post_url) |>
            httr2::req_error(is_error = function(resp) FALSE) |>
            httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
            httr2::req_options(followlocation = FALSE)
          req_post <- do.call(httr2::req_body_form, c(list(req_post), data))
          post_resp <- httr2::req_perform(req_post)

          code <- NA_character_
          cur_resp <- post_resp
          for (i in seq_len(5)) {
            status <- httr2::resp_status(cur_resp)
            if (status >= 300 && status < 400) {
              loc <- httr2::resp_header(cur_resp, "location")
              testthat::expect_true(nzchar(loc))
              if (startsWith(loc, redirect_uri)) {
                code <- parse_query_param(loc, "code")
                break
              }
              step <- follow_once(cur_resp, cookie_hdr)
              cur_resp <- step$resp
            } else {
              break
            }
          }

          testthat::expect_true(is.character(code) && nzchar(code))

          # 4) Simulate provider callback into the module
          values$.process_query(paste0(
            "?code=",
            utils::URLencode(code),
            "&state=",
            utils::URLencode(st)
          ))
          session$flushReact()

          # 5) Assertions: authenticated with a token
          testthat::expect_true(isTRUE(values$authenticated))
          testthat::expect_null(values$error)
          testthat::expect_false(is.null(values$token))
          testthat::expect_true(nzchar(values$token@access_token))

          # Optional: refresh round-trip could be added here when offline tokens are enabled
          # This test focuses on full code exchange using JWT client auth. Refresh is covered separately.
        }
      )
    }
  )
}
