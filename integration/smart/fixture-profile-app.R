# Browser app using exported APIs for both SMART launch modes and all supported
# registration types. Synthetic identity/context never enters general summaries.
smart_profile_app <- function(origin, providers, async = FALSE, response_mode = "query", registration, launch) {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  callbacks <- paste0(origin, "/callback/", c("a", "b"))
  targets <- lapply(c("a", "b"), function(site) {
    discovery <- shinyOAuth::smart_discover(paste0(providers[[site]], "/fhir"), allow_http_loopback = TRUE)
    args <- list(discovery = discovery, client_id = site, redirect_uri = paste0(origin, "/callback/", site),
      scopes = c(if (launch == "standalone") "launch/patient", "patient/Patient.rs", "user/Practitioner.r", "offline_access"),
      required_scopes = c("patient/Patient.r", "user/Practitioner.r"),
      launch = launch, identity = "fhirUser", label = paste("Site", site),
      token_auth_style = registration$style, response_mode = response_mode,
      authorization_server_mode = "multi_redirect_uri", authorization_server_redirect_uris = callbacks)
    if (registration$style == "header") args$client_secret <- registration$secret
    if (registration$style == "private_key_jwt") {
      args$client_assertion_private_key <- openssl::read_key(registration$private_pem)
      args$client_assertion_private_key_kid <- "fixture-client"
      args$client_assertion_alg <- "RS384"
    }
    do.call(shinyOAuth::smart_target, args)
  })
  names(targets) <- c("a", "b")
  manager <- shinyOAuth::oauth_connections(targets, origin, retention = "browser",
    owner = shinyOAuth::oauth_browser_owner(allow_http_loopback = TRUE),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  base_ui <- shiny::fluidPage(shinyOAuth::use_shinyOAuth(),
    lapply(c("a", "b"), function(site) shiny::tagList(
      shiny::actionButton(paste0("connect_", site), paste("Connect", site)),
      shiny::actionButton(paste0("read_", site), paste("Patient", site)),
      shiny::actionButton(paste0("user_", site), paste("User", site)),
      shiny::actionButton(paste0("search_", site), paste("Search", site)),
      shiny::actionButton(paste0("refresh_", site), paste("Refresh", site)))),
    shiny::actionButton("narrow_a", "Narrow A"), shiny::actionButton("widen_a", "Try broader scopes"),
    shiny::actionButton("disconnect_b", "Disconnect B"), shiny::actionButton("logout", "Log out"),
    shiny::verbatimTextOutput("snapshot"), shiny::verbatimTextOutput("result"))
  sessions <- 0L
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    number <- sessions
    health <- shinyOAuth::oauth_connections_server("health", manager, async = async)
    result <- shiny::reactiveVal("ready")
    connection <- function(site) {
      rows <- Filter(function(row) identical(row$target_label, paste("Site", site)), health$connections())
      if (!length(rows)) stop("Unavailable")
      health$connection(rows[[1L]]$connection_id)
    }
    perform <- function(fn) {
      value <- tryCatch(fn(), error = function(...) "unavailable")
      if (inherits(value, "promise")) {
        promises::then(value, function(...) result("refreshed"), function(...) result("unavailable"))
      } else result(if (isTRUE(value)) "refreshed" else value)
    }
    for (site in c("a", "b")) local({
      selected <- site
      shiny::observeEvent(input[[paste0("connect_", selected)]], health$connect(selected))
      shiny::observeEvent(input[[paste0("refresh_", selected)]], perform(function() connection(selected)$refresh()))
      shiny::observeEvent(input[[paste0("read_", selected)]], perform(function() {
        conn <- connection(selected)
        ctx <- shinyOAuth::smart_context(conn)
        body <- httr2::resp_body_json(shinyOAuth::smart_patient(conn))
        stopifnot(identical(body$id, ctx$patient), !identical(ctx$patient, sub("^Practitioner/", "", ctx$fhirUser)))
        paste0(body$fixture_site, ":", body$fixture_revision, ":context-", ctx$revision)
      }))
      shiny::observeEvent(input[[paste0("user_", selected)]], perform(function() {
        body <- httr2::resp_body_json(shinyOAuth::smart_fhir_user(connection(selected)))
        stopifnot(identical(body$resourceType, "Practitioner"), identical(body$id, paste0("clinician-", selected)))
        paste0(body$fixture_site, ":user")
      }))
      shiny::observeEvent(input[[paste0("search_", selected)]], perform(function() {
        response <- connection(selected)$request("fhir", "Patient", required_scopes = "patient/Patient.s")
        stopifnot(identical(httr2::resp_body_json(response)$resourceType, "Bundle"))
        paste0(selected, ":search")
      }))
    })
    limited <- c("patient/Patient.r", "user/Practitioner.r", "offline_access", "openid", "fhirUser")
    shiny::observeEvent(input$narrow_a, perform(function() connection("a")$refresh(scopes = limited)))
    shiny::observeEvent(input$widen_a, perform(function() connection("a")$refresh(scopes = c(limited, "patient/Patient.s"))))
    shiny::observeEvent(input$disconnect_b, health$disconnect(connection("b")$summary()$connection_id, revoke = FALSE))
    shiny::observeEvent(input$logout, health$logout(revoke = FALSE))
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText(jsonlite::toJSON(list(session = number,
      connections = health$connections(), errors = health$errors()), auto_unbox = TRUE, null = "null"))
  }
  routes <- if (launch == "ehr") list(shinyOAuth::smart_launch_route("/launch", c("a", "b"))) else list()
  ui <- shinyOAuth::oauth_connections_ui(base_ui, "health", manager, launch_routes = routes)
  shiny::runApp(shiny::shinyApp(ui, server, uiPattern = ".*"), host = "127.0.0.1",
    port = as.integer(httr2::url_parse(origin)$port), launch.browser = FALSE, quiet = TRUE)
}
