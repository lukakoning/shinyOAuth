# Tests for OIDC openid scope enforcement (OIDC Core §3.1.2.1)

# Reset rlang's once-per-session guard so each test can observe the warning
reset_openid_warn <- function() {
  rlang::reset_warning_verbosity("shinyOAuth_missing_openid_scope")
}

# Helper: build a provider with an issuer (OIDC mode) or without
make_oidc_provider <- function(issuer = "https://issuer.example.com") {
  oauth_provider(
    name = "oidc-test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = issuer,
    use_nonce = !is.na(issuer),
    use_pkce = TRUE,
    pkce_method = "S256",
    # Explicitly disable flags that auto-enable with issuer, so make_test_client
    # pattern stays focused on scope enforcement:
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    allowed_token_types = character(),
    leeway = 60
  )
}

make_oidc_client <- function(
  scopes = character(0),
  issuer = "https://issuer.example.com"
) {
  prov <- make_oidc_provider(issuer = issuer)
  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = scopes,
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

# ---- Tests for ensure_openid_scope() helper directly -----------------------

test_that("ensure_openid_scope prepends openid for OIDC provider when missing", {
  reset_openid_warn()
  prov <- make_oidc_provider()
  expect_warning(
    result <- shinyOAuth:::ensure_openid_scope(c("profile", "email"), prov),
    "openid"
  )
  expect_equal(result, c("openid", "profile", "email"))
})

test_that("ensure_openid_scope is no-op when openid already present", {
  prov <- make_oidc_provider()
  result <- shinyOAuth:::ensure_openid_scope(
    c("openid", "profile", "email"),
    prov
  )
  expect_equal(result, c("openid", "profile", "email"))
})

test_that("ensure_openid_scope is no-op for non-OIDC provider (no issuer)", {
  prov <- make_oidc_provider(issuer = NA_character_)
  result <- shinyOAuth:::ensure_openid_scope(c("profile", "email"), prov)
  expect_equal(result, c("profile", "email"))
})

test_that("ensure_openid_scope injects openid when scopes are empty", {
  reset_openid_warn()
  prov <- make_oidc_provider()
  expect_warning(
    result <- shinyOAuth:::ensure_openid_scope(character(0), prov),
    "openid"
  )
  expect_equal(result, "openid")
})

# ---- Tests for build_auth_url() integration --------------------------------

test_that("build_auth_url auto-prepends openid for OIDC provider", {
  reset_openid_warn()
  cli <- make_oidc_client(scopes = c("profile", "email"))
  tok <- valid_browser_token()
  expect_warning(
    url <- shinyOAuth:::prepare_call(cli, browser_token = tok),
    "openid"
  )
  scope_val <- parse_query_param(url, "scope", decode = TRUE)
  scope_tokens <- strsplit(scope_val, " ")[[1]]
  expect_true("openid" %in% scope_tokens)
  expect_true("profile" %in% scope_tokens)
  expect_true("email" %in% scope_tokens)
  # openid should come first
  expect_equal(scope_tokens[1], "openid")
})

test_that("build_auth_url does not duplicate openid when already present", {
  cli <- make_oidc_client(scopes = c("openid", "profile"))
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  scope_val <- parse_query_param(url, "scope", decode = TRUE)
  scope_tokens <- strsplit(scope_val, " ")[[1]]
  expect_equal(sum(scope_tokens == "openid"), 1L)
})

test_that("build_auth_url injects openid when OIDC provider has empty scopes", {
  reset_openid_warn()
  cli <- make_oidc_client(scopes = character(0))
  tok <- valid_browser_token()
  expect_warning(
    url <- shinyOAuth:::prepare_call(cli, browser_token = tok),
    "openid"
  )
  scope_val <- parse_query_param(url, "scope", decode = TRUE)
  expect_equal(scope_val, "openid")
})

test_that("build_auth_url leaves scopes unchanged for non-OIDC provider", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("repo", "user")
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  scope_val <- parse_query_param(url, "scope", decode = TRUE)
  scope_tokens <- strsplit(scope_val, " ")[[1]]
  expect_false("openid" %in% scope_tokens)
  expect_setequal(scope_tokens, c("repo", "user"))
})

test_that("ensure_openid_scope is case-sensitive (OpenID != openid)", {
  reset_openid_warn()
  prov <- make_oidc_provider()
  # "OpenID" is not the spec-required lowercase "openid"
  expect_warning(
    result <- shinyOAuth:::ensure_openid_scope(c("OpenID", "profile"), prov),
    "openid"
  )
  expect_equal(result, c("openid", "OpenID", "profile"))
})

# ---- Tests for space-delimited scope strings (GH bug: duplicate openid) ----

test_that("ensure_openid_scope detects openid inside a space-delimited string", {
  prov <- make_oidc_provider()
  # Single string "openid profile" — openid is present but embedded in one element

  result <- shinyOAuth:::ensure_openid_scope("openid profile", prov)
  tokens <- result
  expect_equal(sum(tokens == "openid"), 1L)
  expect_true("profile" %in% tokens)
})

test_that("ensure_openid_scope does not duplicate openid from space-delimited input", {
  prov <- make_oidc_provider()
  # Simulates what happens when OAuthClient() is called directly with
  # scopes = "openid profile email" (a single space-delimited string)
  result <- shinyOAuth:::ensure_openid_scope("openid profile email", prov)
  expect_equal(sum(result == "openid"), 1L)
  expect_setequal(result, c("openid", "profile", "email"))
})

test_that("ensure_openid_scope prepends openid for space-delimited string missing it", {
  reset_openid_warn()
  prov <- make_oidc_provider()
  expect_warning(
    result <- shinyOAuth:::ensure_openid_scope("profile email", prov),
    "openid"
  )
  expect_equal(result[1], "openid")
  expect_equal(sum(result == "openid"), 1L)
  expect_true("profile" %in% result)
  expect_true("email" %in% result)
})

test_that("build_auth_url does not duplicate openid with space-delimited scopes", {
  # Use the low-level OAuthClient() directly to bypass oauth_client()'s
  # as_scope_tokens() normalization — this is the path that triggered the bug.
  prov <- make_oidc_provider()
  cli <- OAuthClient(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = "openid profile",
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    scope_validation = "warn",
    introspect = FALSE
  )
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  scope_val <- parse_query_param(url, "scope", decode = TRUE)
  scope_tokens <- strsplit(scope_val, " ")[[1]]
  # openid must appear exactly once — no duplication
  expect_equal(sum(scope_tokens == "openid"), 1L)
  expect_true("profile" %in% scope_tokens)
})
