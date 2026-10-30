# Keep and use multiple OAuth authorizations

## Why keep several authorizations?

A user may want to connect a calendar and a records service, or use two
accounts at the same service. Each authorization gives the app
permission to access data. The connection manager saves these
authorizations so users can choose which one to use and disconnect them
separately.

Login redirects leave the current Shiny session. Browser retention lets
the app find the saved authorizations when the user returns, so
connecting a second service does not discard the first.

For one login per Shiny session, start with
[Usage](https://lukakoning.github.io/shinyOAuth/articles/usage.md). For
one login that needs different tokens for several APIs, see [Token
targets](https://lukakoning.github.io/shinyOAuth/articles/token-targets.md).

## Client configuration and connections

A client describes an app registration: the service, credentials,
requested permissions and allowed API addresses. A connection represents
one successful authorization using that client. The manager holds the
clients and saved connections; your server selects a connection when
making a request.

One client can have several connections. Connecting the same service
again adds another authorization; the provider decides whether to show
an account chooser or reuse the account already signed in there.

## Register two clients

This template connects two fictional services and reads records from
either one. Replace the endpoints, credentials, scope names and API
paths with your providers’ values. The example uses shared-secret client
authentication and PKCE.

Register these callback addresses, where the browser returns after
login:

| Service | Local callback URL                 |
|---------|------------------------------------|
| A       | `http://127.0.0.1:8100/callback/a` |
| B       | `http://127.0.0.1:8100/callback/b` |

Use these HTTP addresses only for local development if your providers
permit them. For deployment, register matching public HTTPS URLs and
remove `allow_http_loopback`. Store IDs and secrets in the environment
variables below. Copy the next three code blocks into `app.R`, in order.

### 1. Configure clients outside `server()`

``` r

library(shiny)
library(shinyOAuth)

app_origin <- "http://127.0.0.1:8100"
callbacks <- paste0(app_origin, c("/callback/a", "/callback/b"))

provider_a <- oauth_provider(
  name = "Service A",
  auth_url = "https://login.a.example/authorize",
  token_url = "https://login.a.example/token",
  token_auth_style = "header",
  use_pkce = TRUE,
  pkce_method = "S256"
)
provider_b <- oauth_provider(
  name = "Service B",
  auth_url = "https://login.b.example/authorize",
  token_url = "https://login.b.example/token",
  token_auth_style = "header",
  use_pkce = TRUE,
  pkce_method = "S256"
)

client_a <- oauth_client(
  provider_a,
  client_id = Sys.getenv("SERVICE_A_CLIENT_ID"),
  client_secret = Sys.getenv("SERVICE_A_CLIENT_SECRET"),
  redirect_uri = callbacks[[1]],
  scopes = "records.read",
  resource_bases = c(api = "https://api.a.example/v1"),
  required_scopes = "records.read",
  label = "Service A",
  authorization_server_mode = "multi_redirect_uri",
  authorization_server_redirect_uris = callbacks
)
client_b <- oauth_client(
  provider_b,
  client_id = Sys.getenv("SERVICE_B_CLIENT_ID"),
  client_secret = Sys.getenv("SERVICE_B_CLIENT_SECRET"),
  redirect_uri = callbacks[[2]],
  scopes = "records.read",
  resource_bases = c(api = "https://api.b.example/v1"),
  required_scopes = "records.read",
  label = "Service B",
  authorization_server_mode = "multi_redirect_uri",
  authorization_server_redirect_uris = callbacks
)

clients <- list(a = client_a, b = client_b)
```

The names `a` and `b` let your app choose a service. Within either
client, `api` names its approved API base: requesting `"api", "records"`
on connection A calls `https://api.a.example/v1/records`.

Each service has its own callback route so the app can distinguish
returning responses. Give each client the complete `callbacks` vector.

### 2. Keep authorizations when the browser returns

``` r

# Temporary keys for this local demo, generated once per R process.
# In a deployment, load two independent 32-byte raw keys from secret storage.
keys <- list(
  credentials = openssl::rand_bytes(32),
  owner = openssl::rand_bytes(32)
)

manager <- oauth_connections(
  clients,
  app_origin = app_origin,
  retention = "browser",
  owner_policy = oauth_browser_owner(allow_http_loopback = TRUE),
  store = oauth_connection_store_memory(),
  keys = keys
)
```

Tokens stay encrypted on the server, while a cookie associates the saved
connections with this browser. The cookie does not identify a person.
Without browser retention, connections end with their Shiny session.

Create the manager, store and keys outside `server()`. This memory store
supports one R process and loses records on restart. For deployment,
load stable secret keys.

Saved connections also have inactivity and absolute expiry limits. The
Read handler below records user activity through `auth[["touch"]]()`.
Automatic refreshes and status reads leave the inactivity timer
unchanged.

### 3. Select a connection and make a request

``` r

base_ui <- fluidPage(
  h2("My connected services"),
  actionButton("connect_a", "Connect Service A"),
  actionButton("connect_b", "Connect Service B"),
  selectInput("connection_id", "Saved authorization", choices = character()),
  actionButton("read", "Read records"),
  actionButton("disconnect", "Disconnect selected"),
  actionButton("logout", "Disconnect all and leave"),
  textOutput("result"),
  textOutput("auth_error")
)
ui <- oauth_connections_ui(base_ui, "services", manager)

server <- function(input, output, session) {
  auth <- oauth_connections_server("services", manager)
  observeEvent(input[["connect_a"]], auth[["connect"]]("a"))
  observeEvent(input[["connect_b"]], auth[["connect"]]("b"))

  observe({
    rows <- auth[["connections"]]()
    ids <- vapply(rows, function(x) x[["connection_id"]], character(1))
    labels <- vapply(seq_along(rows), function(i) {
      paste(rows[[i]][["client_label"]], i, paste0("(", rows[[i]][["status"]], ")"))
    }, character(1))
    selected <- isolate(input[["connection_id"]])
    if (!length(selected) || !selected %in% ids) selected <- head(ids, 1)
    updateSelectInput(session, "connection_id",
      choices = setNames(ids, labels), selected = selected)
  })

  selected_connection <- reactive({
    rows <- auth[["connections"]]()
    ids <- vapply(rows, function(x) x[["connection_id"]], character(1))
    req(input[["connection_id"]], input[["connection_id"]] %in% ids)
    auth[["connection"]](input[["connection_id"]])
  })

  result <- eventReactive(input[["read"]], {
    auth[["touch"]]()
    connection <- selected_connection()
    req(connection[["is_usable"]]())
    message <- tryCatch({
      response <- connection[["request"]](
        "api", "records", required_scopes = "records.read"
      )
      httr2::resp_check_status(response)
      # Parse the body here according to your API's schema.
      paste("Records request succeeded; HTTP", httr2::resp_status(response))
    }, error = function(e) "Could not read records. Check the connection and try again.")
    list(connection_id = connection[["id"]], message = message)
  })

  output[["result"]] <- renderText({
    connection <- selected_connection()
    req(connection[["is_usable"]]())
    value <- result()
    req(identical(value[["connection_id"]], connection[["id"]]))
    value[["message"]]
  })
  observeEvent(input[["disconnect"]], {
    auth[["disconnect"]](selected_connection()[["id"]])
  })
  observeEvent(input[["logout"]], auth[["logout"]]())
  output[["auth_error"]] <- renderText({
    if (length(auth[["errors"]]())) "Authorization is unavailable. Try connecting again."
  })
}

runApp(shinyApp(ui, server, uiPattern = ".*"),
  host = "127.0.0.1", port = 8100, launch.browser = FALSE)
```

Open `http://127.0.0.1:8100` in a regular browser. Connect A, then B.
Select each authorization and read its records. The output checks the
connection ID so results from a previous selection do not remain
visible.

The UI wrapper and server module share the `"services"` ID. The wrapper
handles callbacks, and `uiPattern = ".*"` allows their routes. Selection
uses the opaque connection ID; the numeric label only distinguishes demo
rows.

## Requests, permissions and refresh

For an optional write action, request
`scopes = c("records.read", "records.write")` on the applicable client
and obtain a new authorization. Add an Update button to the UI, then use
an observer inside `server()` after `selected_connection`:

``` r

observeEvent(input[["write"]], {
  auth[["touch"]]()
  connection <- selected_connection()
  req(connection[["is_usable"]]())
  tryCatch({
    response <- connection[["request"]]("api", "records/example", method = "PUT",
      required_scopes = "records.write", configure = function(req) {
        req |>
          httr2::req_body_json(list(name = "Updated record")) |>
          httr2::req_headers(`If-Match` = 'W/"7"')
      })
    httr2::resp_check_status(response)
    showNotification("Record updated.")
  }, error = function(e) {
    showNotification("Could not update the record.", type = "error")
  })
})
```

The operation requires `records.write` even when basic read access is
still usable. `configure` adds the request body and application headers;
the connection keeps control of the destination and authentication. The
service still decides whether the user may change that particular
record.

If a refresh token is available, the manager attempts refresh at expiry.
`refresh_proactively = TRUE` starts earlier. An optional Refresh button
can run:

``` r

observeEvent(input[["refresh"]], {
  tryCatch(selected_connection()[["refresh"]](), error = function(e) {
    showNotification("Could not refresh. Connect again if access has ended.", type = "error")
  })
})
```

Add `actionButton("refresh", "Refresh selected")` to use it. For
background refresh, first follow [the async
setup](https://lukakoning.github.io/shinyOAuth/articles/usage.html#asynchronous-execution).
Saving an authorization does not itself request a refresh token.

## Disconnecting a service

`auth[["disconnect"]](id)` removes the selected local connection and
attempts remote revocation when configured. `auth[["logout"]]()`
disconnects all and ends this local owner session; it does not sign the
user out of the external services. Add each provider’s documented
`revocation_url` if revocation is supported.

A provider can reuse one upstream grant for several local connections,
so revoking one may affect the others even if their local summaries
still show them as active. `revoke = FALSE` removes local access without
requesting remote revocation.

## Deployment notes

Browser retention follows cookie boundaries, including sharing across
ports on one hostname. The [browser-boundary
explanation](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html#browser-binding-and-deployment-boundary)
describes this behavior. Browser retention is limited to one R process.
[oauth_connections()](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.html)
and
[oauth_browser_owner()](https://lukakoning.github.io/shinyOAuth/reference/oauth_browser_owner.html)
document retention, capacity and expiry settings.

If your app has its own verified account login, `retention = "account"`
with
[`oauth_account_owner()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_browser_owner.md)
can associate authorizations with that account. Browser retention alone
does not make that association. For subpaths and trusted proxies, see
[oauth_connections_ui()](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.html).

## Keep an ordinary OIDC login alongside SMART connections

An ordinary OIDC login can identify the app user while the manager holds
separate authorizations for access to hospital records.

For an OIDC client already inside the manager, read selected validated
identity fields in the owning server session:

``` r

identity <- selected_connection()[["identity"]](userinfo = c("name", "email"))
# identity[["id_token_claims"]] contains only iss and sub by default.
# identity[["userinfo"]] contains only the selected, previously fetched fields.
```

This reads previously fetched identity data; it does not perform a fresh
login or establish the account used for retention. See [the connection
reference](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.html).

To keep an ordinary login module outside the manager, use one callback
wrapper with `additional_clients`. Given an existing `login_provider`
and a reviewed SMART discovery result `site`:

``` r

callbacks <- c("https://app.example/login/callback", "https://app.example/fhir/callback")
login_client <- oauth_client(login_provider, "registered-login-app",
  redirect_uri = callbacks[[1]], scopes = c("openid", "profile"),
  authorization_server_mode = "multi_redirect_uri",
  authorization_server_redirect_uris = callbacks)
fhir_client <- smart_client(site, "registered-fhir-app", callbacks[[2]],
  scopes = c("launch/patient", "patient/Patient.r"),
  authorization_server_mode = "multi_redirect_uri",
  authorization_server_redirect_uris = callbacks)
manager <- oauth_connections(list(fhir = fhir_client), "https://app.example",
  retention = "browser", owner_policy = oauth_browser_owner(),
  store = oauth_connection_store_memory(), keys = keys)
base_ui <- fluidPage(actionButton("sign_in", "Sign in"),
  actionButton("connect_fhir", "Connect FHIR"))
ui <- oauth_connections_ui(base_ui, "health", manager,
  additional_clients = list(login = login_client))
server <- function(input, output, session) {
  login <- oauth_module_server("login", login_client, auto_redirect = FALSE)
  health <- oauth_connections_server("health", manager)
  observeEvent(input[["sign_in"]], login[["request_login"]]())
  observeEvent(input[["connect_fhir"]], health[["connect"]]("fhir"))
}
shinyApp(ui, server, uiPattern = ".*")
```

Supply credentials for the login registration and the deployment `keys`
described above. The example uses distinct callbacks and disables
automatic login so the ordinary login module does not interrupt other
authorizations.

Full navigation ends the ordinary module’s Shiny session. Its login is
separate from the manager’s retained connections. See
[oauth_connections_ui()](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.html)
for callback configuration details.
