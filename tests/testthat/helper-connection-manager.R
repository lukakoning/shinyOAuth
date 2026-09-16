manager_test_request <- function(
  cookie = NULL,
  method = "GET",
  path = "/",
  query = ""
) {
  list(
    REQUEST_METHOD = method,
    PATH_INFO = path,
    SCRIPT_NAME = "",
    QUERY_STRING = query,
    HTTP_HOST = "app.example",
    "rook.url_scheme" = "https",
    HTTP_COOKIE = cookie
  )
}

manager_test_session <- function(cookie = NULL) {
  session_env <- new.env(parent = asNamespace("shiny"))
  session_env[["request_data"]] <- list(
    HTTP_ORIGIN = "https://app.example",
    HTTP_COOKIE = cookie
  )
  R6::R6Class(
    inherit = shiny::MockShinySession,
    portable = FALSE,
    lock_objects = FALSE,
    parent_env = session_env,
    active = list(request = function(value) {
      if (!missing(value)) {
        request_data <<- value
      }
      request_data
    })
  )[["new"]]()
}

manager_test_cookie <- function(f) {
  response <- f[["ui"]](manager_test_request())
  sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
}

manager_test_fixture <- function(
  retention = "browser",
  owner = NULL,
  api_origin = "https://api.example"
) {
  redirects <- paste0("https://app.example/callback/", c("a", "b"))
  clients <- lapply(c("a", "b"), function(id) {
    client <- oauth_client(
      provider = make_test_provider(),
      client_id = paste0("client-", id),
      client_secret = "",
      redirect_uri = paste0("https://app.example/callback/", id),
      scopes = c("read", "write"),
      state_key = strrep(id, 64L),
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    connection_test_client(
      client,
      c(api = paste0(api_origin, "/", id)),
      "read",
      paste("Site", id)
    )
  })
  names(clients) <- c("a", "b")
  owner <- owner %||%
    if (retention == "browser") oauth_browser_owner() else NULL
  manager <- oauth_connections(
    clients,
    "https://app.example",
    retention = retention,
    store = oauth_connection_store_memory(),
    owner_policy = owner,
    keys = list(
      credentials = openssl::rand_bytes(32L),
      owner = openssl::rand_bytes(32L)
    )
  )
  ui <- oauth_connections_ui(shiny::fluidPage("Connections"), "health", manager)
  list(manager = manager, ui = ui)
}

manager_test_token <- function(
  access = "synthetic-access",
  refresh = "synthetic-refresh"
) {
  OAuthToken(
    access_token = access,
    refresh_token = refresh,
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = c("read", "write"),
    granted_scopes_verified = TRUE,
    extra_fields = list(patient = "synthetic-patient")
  )
}

manager_test_accept <- function(
  controller,
  client = "a",
  token = manager_test_token()
) {
  before <- vapply(
    controller[["records"]](),
    function(row) row[["stored"]][["id"]],
    character(1)
  )
  hooks <- controller[["hooks"]](client)
  context <- hooks[["prepare"]]()
  hooks[["accept"]](token, context, as.numeric(Sys.time()) - 100)
  rows <- controller[["records"]]()
  ids <- vapply(rows, function(row) row[["stored"]][["id"]], character(1))
  setdiff(ids, before)[[1L]]
}
