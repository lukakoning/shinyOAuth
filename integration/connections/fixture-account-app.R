# Synthetic local login boundary, separate from the package's OAuth providers.
# The fixture is served only on loopback through its dedicated TLS proxy.
account_fixture_app <- function(
  origin,
  providers,
  async = FALSE,
  response_mode = "query",
  listen_port
) {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  logins <- new.env(parent = emptyenv())
  passwords <- c(alice = "alice-fixture-password", bob = "bob-fixture-password")
  cookie_name <- "__Host-fixture-account"
  random <- function() paste(format(openssl::rand_bytes(32)), collapse = "")
  cookie_id <- function(req) {
    cookie <- req$HTTP_COOKIE
    if (is.null(cookie)) {
      return(NULL)
    }
    entries <- trimws(strsplit(cookie, ";", fixed = TRUE)[[1L]])
    matches <- entries[startsWith(entries, paste0(cookie_name, "="))]
    if (length(matches) != 1L) {
      return(NULL)
    }
    value <- substring(matches, nchar(cookie_name) + 2L)
    if (grepl("^[a-f0-9]{64}$", value)) value else NULL
  }
  identity <- function(req) {
    id <- cookie_id(req)
    if (is.null(id)) {
      return(NULL)
    }
    record <- logins[[id]]
    if (is.null(record) || record$expires_at <= as.numeric(Sys.time())) {
      return(NULL)
    }
    record
  }
  retire <- function(req) {
    id <- cookie_id(req)
    if (!is.null(id) && exists(id, logins, inherits = FALSE)) {
      rm(list = id, envir = logins)
    }
  }
  response <- function(
    status,
    body = "",
    headers = list(),
    type = "text/html"
  ) {
    shiny::httpResponse(
      status,
      paste0(type, "; charset=UTF-8"),
      body,
      headers = c(
        list("Cache-Control" = "no-store", "Referrer-Policy" = "same-origin"),
        headers
      )
    )
  }
  login_page <- function() {
    response(
      200L,
      paste0(
        '<!doctype html><html><head><title>Fixture local login</title></head><body>',
        '<form method="post" action="/local/login">',
        '<input id="username" name="username" autocomplete="username">',
        '<input id="password" name="password" type="password" autocomplete="current-password">',
        '<button id="login" type="submit">Log in</button></form>',
        '<pre id="snapshot">{"account":null,"connections":[],"errors":[],"result":"login","result_revision":0}</pre>',
        '</body></html>'
      )
    )
  }
  local_auth <- function(req) {
    if (
      !identical(req$REQUEST_METHOD, "POST") ||
        !identical(req$HTTP_ORIGIN, origin)
    ) {
      return(response(403L, "Local login requires a same-origin form POST"))
    }
    if (identical(req$PATH_INFO, "/local/logout")) {
      retire(req)
      return(response(
        303L,
        headers = list(
          Location = origin,
          "Set-Cookie" = paste0(
            cookie_name,
            "=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
          )
        )
      ))
    }
    size <- suppressWarnings(as.integer(req$CONTENT_LENGTH))
    if (
      length(size) != 1L ||
        is.na(size) ||
        size < 1L ||
        size > 4096L ||
        !identical(req$CONTENT_TYPE, "application/x-www-form-urlencoded")
    ) {
      return(response(400L, "Invalid login form"))
    }
    body <- shiny::parseQueryString(rawToChar(req[["rook.input"]]$read(size)))
    if (
      !setequal(names(body), c("username", "password")) ||
        !body$username %in% names(passwords) ||
        !identical(unname(passwords[[body$username]]), body$password)
    ) {
      return(response(401L, "Invalid fixture credentials"))
    }
    retire(req)
    id <- random()
    now <- as.numeric(Sys.time())
    logins[[id]] <- list(
      subject = body$username,
      session_id = id,
      generation = random(),
      authenticated_at = now,
      expires_at = now + 600
    )
    response(
      303L,
      headers = list(
        Location = origin,
        "Set-Cookie" = paste0(
          cookie_name,
          "=",
          id,
          "; Secure; HttpOnly; SameSite=Lax; Path=/"
        )
      )
    )
  }
  callbacks <- paste0(origin, "/callback/", c("a", "b"))
  clients <- lapply(c("a", "b"), function(site) {
    base <- providers[[site]]
    provider <- shinyOAuth::oauth_provider(
      name = site,
      auth_url = paste0(base, "/authorize"),
      token_url = paste0(base, "/token"),
      revocation_url = paste0(base, "/revoke"),
      token_auth_style = "public",
      use_nonce = FALSE
    )
    shinyOAuth::oauth_client(
      provider,
      site,
      client_secret = "",
      scopes = "read",
      redirect_uri = paste0(origin, "/callback/", site),
      state_key = openssl::rand_bytes(32),
      response_mode = response_mode,
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = callbacks,
      resource_bases = c(api = paste0(base, "/api")),
      required_scopes = "read",
      label = site
    )
  })
  names(clients) <- c("a", "b")
  manager <- shinyOAuth::oauth_connections(
    clients,
    origin,
    retention = "account",
    owner = shinyOAuth::oauth_account_owner(
      function(session) identity(session$request),
      idle_timeout = 300,
      absolute_timeout = 600,
      reauth_after_seconds = 600
    ),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  base_ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::actionButton("connect_a", "Connect A"),
    shiny::actionButton("connect_b", "Connect B"),
    shiny::actionButton("read_a", "Read A"),
    shiny::actionButton("read_b", "Read B"),
    shiny::actionButton("refresh_a", "Refresh A"),
    shiny::actionButton("manager_logout", "Disconnect account grants"),
    shiny::tags$form(
      method = "post",
      action = paste0(origin, "/local/logout"),
      onsubmit = paste0(
        "event.preventDefault();fetch(this.action,{method:'POST',",
        "credentials:'same-origin',referrerPolicy:'same-origin'}).then(function(r){",
        "if(r.ok)window.location.replace(",
        jsonlite::toJSON(origin, auto_unbox = TRUE),
        ");});"
      ),
      shiny::tags$button(
        id = "local_logout",
        type = "submit",
        "Log out of local account"
      )
    ),
    shiny::verbatimTextOutput("snapshot"),
    shiny::verbatimTextOutput("result")
  )
  sessions <- 0L
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    number <- sessions
    health <- shinyOAuth::oauth_connections_server(
      "health",
      manager,
      async = async,
      refresh_check_interval = 500
    )
    result <- shiny::reactiveVal("ready")
    revision <- shiny::reactiveVal(0L)
    complete <- function(value) {
      result(value)
      revision(shiny::isolate(revision()) + 1L)
    }
    connection <- function(site) {
      rows <- Filter(
        function(row) {
          identical(row$client_label, site) &&
            row$status %in% c("active", "limited")
        },
        health$connections()
      )
      if (!length(rows)) {
        stop("No usable connection")
      }
      health$connection(rows[[1L]]$connection_id)
    }
    perform <- function(action) {
      tryCatch(
        {
          value <- action()
          if (inherits(value, "promise")) {
            promises::then(
              value,
              function(...) complete("refreshed"),
              function(...) complete("unavailable")
            )
          } else {
            complete(value)
          }
        },
        error = function(...) complete("unavailable")
      )
    }
    for (site in c("a", "b")) {
      local({
        selected <- site
        shiny::observeEvent(
          input[[paste0("connect_", selected)]],
          perform(function() {
            health$connect(selected)
            "connecting"
          })
        )
        shiny::observeEvent(
          input[[paste0("read_", selected)]],
          perform(function() {
            body <- httr2::resp_body_json(connection(selected)$request(
              "api",
              "records"
            ))
            paste0(body$site, ":", body$revision)
          })
        )
      })
    }
    shiny::observeEvent(
      input$refresh_a,
      perform(function() {
        value <- connection("a")$refresh()
        if (inherits(value, "promise")) value else "refreshed"
      })
    )
    shiny::observeEvent(
      input$manager_logout,
      perform(function() {
        health$logout(revoke = FALSE, reload = FALSE)
        "disconnected"
      })
    )
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText({
      shiny::invalidateLater(500, session)
      jsonlite::toJSON(
        list(
          account = identity(session$request)$subject,
          session = number,
          connections = health$connections(),
          errors = health$errors(),
          result = result(),
          result_revision = revision()
        ),
        auto_unbox = TRUE,
        null = "null"
      )
    })
  }
  wrapped <- shinyOAuth::oauth_connections_ui(
    base_ui,
    "health",
    manager,
    request_uri_resolver = function(req) {
      # This fixture's loopback TLS proxy preserves Host and does not accept
      # forwarded headers. Only its preconfigured public authority is valid.
      if (
        !identical(
          req$HTTP_HOST,
          httr2::url_parse(origin)$hostname |>
            paste0(":", httr2::url_parse(origin)$port)
        )
      ) {
        stop("Invalid fixture authority")
      }
      paste0(
        origin,
        req$PATH_INFO,
        if (nzchar(req$QUERY_STRING)) paste0("?", req$QUERY_STRING)
      )
    }
  )
  ui <- function(req) {
    if (req$PATH_INFO %in% c("/local/login", "/local/logout")) {
      return(local_auth(req))
    }
    if (!startsWith(req$PATH_INFO, "/callback/") && is.null(identity(req))) {
      return(login_page())
    }
    wrapped(req)
  }
  attr(ui, "http_methods_supported") <- c("GET", "POST")
  shiny::runApp(
    shiny::shinyApp(ui, server, uiPattern = ".*"),
    host = "127.0.0.1",
    port = listen_port,
    launch.browser = FALSE,
    quiet = TRUE
  )
}
