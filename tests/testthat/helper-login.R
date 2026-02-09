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

make_test_provider <- function(use_pkce = TRUE, use_nonce = FALSE) {
  # Provide issuer when nonce is requested to satisfy fail-fast validation
  issuer <- if (isTRUE(use_nonce)) {
    "https://issuer.example.com"
  } else {
    NA_character_
  }
  oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = issuer,
    use_nonce = use_nonce,
    use_pkce = use_pkce,
    pkce_method = "S256",
    userinfo_required = FALSE,
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
  state_max_age = 600,
  state_payload_max_age = 300,
  scopes = character(0),
  claims = NULL,
  introspect = FALSE,
  introspect_elements = character(0)
) {
  prov <- make_test_provider(use_pkce = use_pkce, use_nonce = use_nonce)
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
