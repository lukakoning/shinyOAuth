ordinary_oidc_fixture <- function() {
  provider <- oauth_provider(
    "ordinary-oidc",
    "https://issuer.example/auth",
    "https://issuer.example/token",
    issuer = "https://issuer.example",
    id_token_validation = TRUE,
    use_nonce = TRUE,
    userinfo_required = FALSE,
    token_auth_style = "body"
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "offline_access", "read", "write"),
    scope_validation = "none"
  )
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  state <- new.env(parent = emptyenv())
  state[["nonce"]] <- NULL
  state[["requested"]] <- character()
  state[["extra"]] <- character()
  state[["requests"]] <- list()
  authorize <- function(url) {
    state[["nonce"]] <- parse_query_param(url, "nonce", decode = TRUE)
    state[["requested"]] <- normalize_scope_tokens(
      parse_query_param(url, "scope", decode = TRUE)
    )
    invisible(url)
  }
  request <- function(req, ...) {
    body <- lapply(req[["body"]][["data"]], function(value) {
      utils::URLdecode(gsub("+", " ", as.character(value), fixed = TRUE))
    })
    state[["requests"]][[length(state[["requests"]]) + 1L]] <- body
    code <- identical(body[["grant_type"]], "authorization_code")
    requested <- if (code) {
      state[["requested"]]
    } else {
      normalize_scope_tokens(body[["scope"]] %||% "openid read")
    }
    response <- list(
      access_token = paste0("access-", length(state[["requests"]])),
      token_type = "Bearer",
      expires_in = 3600,
      scope = paste(
        c(intersect(requested, c("openid", "read")), state[["extra"]]),
        collapse = " "
      )
    )
    if (!code || "offline_access" %in% requested) {
      response[["refresh_token"]] <- paste0(
        "refresh-",
        length(state[["requests"]])
      )
    }
    if (code) {
      response[["id_token"]] <- jose::jwt_encode_sig(
        jose::jwt_claim(
          iss = provider@issuer,
          aud = client@client_id,
          sub = "alice",
          iat = as.numeric(Sys.time()),
          exp = as.numeric(Sys.time()) + 3600,
          nonce = state[["nonce"]]
        ),
        key
      )
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(response, auto_unbox = TRUE))
    )
  }
  list(
    client = client,
    jwk = jwk,
    state = state,
    authorize = authorize,
    request = request
  )
}

ordinary_manager_fixture <- function(client) {
  manager <- oauth_connections(
    list(a = client),
    "https://app.example",
    retention = "browser",
    store = oauth_connection_store_memory(),
    owner_policy = oauth_browser_owner(),
    keys = list(
      credentials = openssl::rand_bytes(32L),
      owner = openssl::rand_bytes(32L)
    )
  )
  list(
    manager = manager,
    ui = oauth_connections_ui(shiny::fluidPage(), "health", manager)
  )
}
