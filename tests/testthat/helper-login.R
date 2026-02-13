## Helpers for login/callback tests

# NOTE: decode = FALSE by default because most usages extract `state` which
# is then passed back to .process_query(). Keeping the value URL-encoded
# ensures shiny::parseQueryString correctly parses special characters.
# For other parameters like redirect_uri or code, pass decode = TRUE.
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

valid_browser_token <- function() paste(rep("ab", 64), collapse = "")

# Centralized polling helper for async test assertions.
# Polls `condition_fn` until it returns TRUE, flushing the Shiny reactive loop
# and `later` callbacks each iteration.
# Timeout (seconds) defaults to env var SHINYOAUTH_TEST_POLL_TIMEOUT, then 5s.
# Poll interval defaults to env var SHINYOAUTH_TEST_POLL_INTERVAL, then 0.05s.
poll_for_async <- function(
  condition_fn,
  session = NULL,
  timeout = NULL,
  interval = NULL
) {
  timeout <- timeout %||%
    as.numeric(Sys.getenv("SHINYOAUTH_TEST_POLL_TIMEOUT", unset = "5"))
  interval <- interval %||%
    as.numeric(Sys.getenv("SHINYOAUTH_TEST_POLL_INTERVAL", unset = "0.05"))

  deadline <- Sys.time() + timeout
  while (!isTRUE(condition_fn()) && Sys.time() < deadline) {
    later::run_now(interval)
    if (!is.null(session)) {
      session$flushReact()
    }
    Sys.sleep(interval / 5)
  }
}

make_test_provider <- function(
  use_pkce = TRUE,
  use_nonce = FALSE,
  userinfo_signed_jwt_required = FALSE
) {
  # Provide issuer when nonce is requested to satisfy fail-fast validation
  issuer <- if (isTRUE(use_nonce) || isTRUE(userinfo_signed_jwt_required)) {
    "https://issuer.example.com"
  } else {
    NA_character_
  }
  oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = if (isTRUE(userinfo_signed_jwt_required)) {
      "https://example.com/userinfo"
    } else {
      NA_character_
    },
    introspection_url = NA_character_,
    issuer = issuer,
    use_nonce = use_nonce,
    use_pkce = use_pkce,
    pkce_method = "S256",
    userinfo_required = if (isTRUE(userinfo_signed_jwt_required)) {
      TRUE
    } else {
      FALSE
    },
    userinfo_signed_jwt_required = userinfo_signed_jwt_required,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    # Disable token_type enforcement in test helper; tested separately in test-token-type-policy.R
    allowed_token_types = character(),
    leeway = 60
  )
}

make_test_client <- function(
  use_pkce = TRUE,
  use_nonce = FALSE,
  userinfo_signed_jwt_required = FALSE,
  state_max_age = 600,
  state_payload_max_age = 300,
  scopes = character(0),
  claims = NULL,
  introspect = FALSE,
  introspect_elements = character(0)
) {
  prov <- make_test_provider(
    use_pkce = use_pkce,
    use_nonce = use_nonce,
    userinfo_signed_jwt_required = userinfo_signed_jwt_required
  )
  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "", # public client
    redirect_uri = "http://localhost:8100",
    scopes = scopes,
    claims = claims,
    state_store = cachem::cache_mem(max_age = state_max_age),
    state_payload_max_age = state_payload_max_age,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    introspect = introspect,
    introspect_elements = introspect_elements
  )
}
