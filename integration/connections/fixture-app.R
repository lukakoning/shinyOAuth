# Invoked in an isolated R process by run-tests.R. Only public manager APIs are used.
retention_fixture_app <- function(
  origin,
  providers,
  async = FALSE,
  idle_timeout = 600,
  response_mode = "query"
) {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  callbacks <- paste0(origin, "/callback/", c("a", "b"))
  targets <- lapply(c("a", "b"), function(site) {
    base <- providers[[site]]
    provider <- shinyOAuth::oauth_provider(
      name = site,
      auth_url = paste0(base, "/authorize"),
      token_url = paste0(base, "/token"),
      revocation_url = paste0(base, "/revoke"),
      issuer_thus_oidc = FALSE,
      token_auth_style = "public",
      use_nonce = FALSE
    )
    client <- shinyOAuth::oauth_client(
      provider,
      client_id = site,
      client_secret = "",
      scopes = "read",
      redirect_uri = paste0(origin, "/callback/", site),
      state_key = openssl::rand_bytes(32),
      response_mode = response_mode,
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = callbacks
    )
    shinyOAuth::oauth_target(
      client,
      c(api = paste0(base, "/api")),
      "read",
      paste("Site", site)
    )
  })
  names(targets) <- c("a", "b")
  manager <- shinyOAuth::oauth_connections(
    targets,
    origin,
    retention = "browser",
    owner = shinyOAuth::oauth_browser_owner(
      idle_timeout = idle_timeout,
      absolute_timeout = 1200,
      allow_http_loopback = TRUE
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
    shiny::actionButton("refresh_b", "Refresh B"),
    shiny::actionButton("disconnect_b", "Disconnect B"),
    shiny::actionButton("logout", "Log out"),
    shiny::textInput("probe_id", "Connection ID for isolation check"),
    shiny::actionButton("probe", "Check access"),
    shiny::verbatimTextOutput("snapshot"),
    shiny::verbatimTextOutput("result")
  )
  sessions <- 0L
  post_owner_cookies <- logical()
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    session_number <- sessions
    health <- shinyOAuth::oauth_connections_server(
      "health",
      manager,
      async = async,
      refresh_check_interval = 500
    )
    result <- shiny::reactiveVal("ready")
    id_for <- function(site) {
      rows <- Filter(
        function(row) identical(row$target_label, paste("Site", site)),
        health$connections()
      )
      if (!length(rows)) {
        stop("Connection is unavailable")
      }
      rows[[1L]]$connection_id
    }
    perform <- function(action) {
      tryCatch(
        {
          value <- action()
          if (inherits(value, "promise")) {
            promises::then(
              value,
              function(...) result("refreshed"),
              function(...) result("unavailable")
            )
          } else {
            result(as.character(value))
          }
        },
        error = function(...) result("unavailable")
      )
    }
    for (site in c("a", "b")) {
      local({
        selected <- site
        shiny::observeEvent(
          input[[paste0("connect_", selected)]],
          health$connect(selected)
        )
        shiny::observeEvent(
          input[[paste0("read_", selected)]],
          perform(function() {
            response <- health$connection(id_for(selected))$request(
              "api",
              "records"
            )
            body <- httr2::resp_body_json(response)
            paste0(body$site, ":", body$revision)
          })
        )
        shiny::observeEvent(
          input[[paste0("refresh_", selected)]],
          perform(function() {
            value <- health$connection(id_for(selected))$refresh()
            if (inherits(value, "promise")) value else "refreshed"
          })
        )
      })
    }
    shiny::observeEvent(
      input$disconnect_b,
      perform(function() {
        health$disconnect(id_for("b"))
        "disconnected"
      })
    )
    shiny::observeEvent(input$logout, health$logout())
    shiny::observeEvent(
      input$probe,
      perform(function() {
        if (health$connection(input$probe_id)$is_usable()) {
          "usable"
        } else {
          "unavailable"
        }
      })
    )
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText(jsonlite::toJSON(
      list(
        session = session_number,
        connections = health$connections(),
        errors = health$errors(),
        post_owner_cookies = post_owner_cookies
      ),
      auto_unbox = TRUE,
      null = "null"
    ))
  }
  wrapped_ui <- shinyOAuth::oauth_connections_ui(base_ui, "health", manager)
  ui <- function(req) {
    if (
      identical(req$REQUEST_METHOD, "POST") &&
        startsWith(req$PATH_INFO, "/callback/")
    ) {
      # Record presence only, never the cookie value or callback body.
      post_owner_cookies <<- c(
        post_owner_cookies,
        is.character(req$HTTP_COOKIE) &&
          grepl("shinyOAuth-owner-", req$HTTP_COOKIE, fixed = TRUE)
      )
    }
    wrapped_ui(req)
  }
  attr(ui, "http_methods_supported") <- attr(
    wrapped_ui,
    "http_methods_supported"
  )
  app <- shiny::shinyApp(
    ui,
    server,
    uiPattern = ".*"
  )
  shiny::runApp(
    app,
    host = "127.0.0.1",
    port = as.integer(httr2::url_parse(origin)$port),
    launch.browser = FALSE,
    quiet = TRUE
  )
}
