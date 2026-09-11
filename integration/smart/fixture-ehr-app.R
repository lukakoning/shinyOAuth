# Uses only exported SMART/manager APIs. All records in this fixture are synthetic.
smart_ehr_fixture_app <- function(origin, providers, async = FALSE, response_mode = "query") {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  callbacks <- paste0(origin, "/callback/", c("a", "b"))
  targets <- lapply(c("a", "b"), function(site) {
    discovery <- shinyOAuth::smart_discover(paste0(providers[[site]], "/fhir"), allow_http_loopback = TRUE)
    shinyOAuth::smart_target(discovery, site, paste0(origin, "/callback/", site),
      scopes = c("patient/Patient.r", "online_access"), launch = "ehr", label = paste("Site", site),
      response_mode = response_mode, authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = callbacks)
  })
  names(targets) <- c("a", "b")
  manager <- shinyOAuth::oauth_connections(targets, origin, retention = "browser",
    owner = shinyOAuth::oauth_browser_owner(allow_http_loopback = TRUE),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  base_ui <- shiny::fluidPage(shinyOAuth::use_shinyOAuth(),
    shiny::actionButton("connect_a", "Reconnect A"), shiny::actionButton("read_a", "Read A"),
    shiny::actionButton("read_b", "Read B"), shiny::actionButton("refresh_a", "Refresh A"),
    shiny::actionButton("logout", "Log out"),
    shiny::verbatimTextOutput("snapshot"), shiny::verbatimTextOutput("result"))
  sessions <- 0L
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    number <- sessions
    health <- shinyOAuth::oauth_connections_server("health", manager, async = async, refresh_check_interval = 500)
    result <- shiny::reactiveVal("ready")
    connection <- function(site) {
      rows <- Filter(function(row) identical(row$target_label, paste("Site", site)), health$connections())
      if (!length(rows)) stop("Unavailable")
      health$connection(rows[[length(rows)]]$connection_id)
    }
    for (site in c("a", "b")) local({
      selected <- site
      shiny::observeEvent(input[[paste0("read_", selected)]], {
        result(tryCatch({
          conn <- connection(selected)
          ctx <- shinyOAuth::smart_context(conn)
          body <- httr2::resp_body_json(shinyOAuth::smart_patient(conn))
          stopifnot(identical(body$id, ctx$patient))
          paste0(body$fixture_site, ":", body$fixture_revision, ":context-", ctx$revision)
        }, error = function(...) "unavailable"))
      })
    })
    shiny::observeEvent(input$connect_a, health$connect("a"))
    shiny::observeEvent(input$refresh_a, {
      value <- tryCatch(connection("a")$refresh(), error = function(...) FALSE)
      if (inherits(value, "promise")) {
        promises::then(value, function(...) result("refreshed"), function(...) result("unavailable"))
      } else result(if (isTRUE(value)) "refreshed" else "unavailable")
    })
    shiny::observeEvent(input$logout, health$logout(revoke = FALSE))
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText(jsonlite::toJSON(list(session = number,
      connections = health$connections(), errors = health$errors()), auto_unbox = TRUE, null = "null"))
  }
  ui <- shinyOAuth::oauth_connections_ui(base_ui, "health", manager,
    launch_routes = list(shinyOAuth::smart_launch_route("/launch", c("a", "b"))))
  shiny::runApp(shiny::shinyApp(ui, server, uiPattern = ".*"), host = "127.0.0.1",
    port = as.integer(httr2::url_parse(origin)$port), launch.browser = FALSE, quiet = TRUE)
}
