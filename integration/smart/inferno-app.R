# Runnable Shiny client for the independent Inferno verifier. All authorization,
# identity, resource and refresh operations use exported shinyOAuth APIs.
inferno_browser_app <- function(origin, listen_port, registrations, launch,
  async = FALSE, authorization_method = "GET") {
  # Inferno intentionally issues one-year ID tokens. Select that deployment's
  # bounded lifetime policy; all cryptographic and claim validation still runs.
  options(shinyOAuth.max_id_token_lifetime = 366 * 86400)
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  sites <- names(registrations)
  callbacks <- paste0(origin, "/callback/", sites)
  clients <- lapply(sites, function(site) {
    registration <- registrations[[site]]
    args <- list(discovery = shinyOAuth::smart_discover(registration$fhir_base),
      client_id = registration$client_id, redirect_uri = paste0(origin, "/callback/", site),
      scopes = c(if (launch == "standalone") "launch/patient", "patient/Patient.rs",
        "user/Practitioner.r", "offline_access"),
      required_scopes = c("patient/Patient.r", "user/Practitioner.r"),
      launch = launch, identity = "fhirUser", label = paste("Site", site),
      token_auth_style = registration$style, authorization_method = authorization_method,
      authorization_server_mode = if (length(sites) > 1L) "multi_redirect_uri" else "single",
      authorization_server_redirect_uris = if (length(sites) > 1L) callbacks else character())
    if (registration$style == "header") args$client_secret <- registration$secret
    if (registration$style == "private_key_jwt") {
      args$client_assertion_private_key <- openssl::read_key(registration$private_pem)
      args$client_assertion_private_key_kid <- registration$kid
      args$client_assertion_alg <- registration$algorithm
    }
    do.call(shinyOAuth::smart_client, args)
  })
  names(clients) <- sites
  manager <- shinyOAuth::oauth_connections(clients, origin, retention = "browser",
    owner = shinyOAuth::oauth_browser_owner(), store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  ui <- shiny::fluidPage(shinyOAuth::use_shinyOAuth(),
    lapply(sites, function(site) shiny::tagList(lapply(c("connect", "read", "user", "refresh"),
      function(action) shiny::actionButton(paste0(action, "_", site), paste(action, site))))),
    shiny::actionButton("logout", "Log out"),
    shiny::verbatimTextOutput("snapshot"), shiny::verbatimTextOutput("result"))
  sessions <- 0L
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    session_number <- sessions
    health <- shinyOAuth::oauth_connections_server("health", manager, async = async)
    result <- shiny::reactiveVal("ready")
    revision <- shiny::reactiveVal(0L)
    connection <- function(site) {
      rows <- Filter(function(row) identical(row$client_label, paste("Site", site)), health$connections())
      if (length(rows) != 1L) stop("Connection unavailable")
      health$connection(rows[[1L]]$connection_id)
    }
    perform <- function(action, fn) {
      finish <- function(ok) {
        result(paste0(action, if (isTRUE(ok)) ":ok" else ":unavailable"))
        revision(shiny::isolate(revision()) + 1L)
      }
      value <- tryCatch(fn(), error = function(...) FALSE)
      if (inherits(value, "promise")) {
        promises::then(value, finish, function(...) finish(FALSE))
      } else finish(value)
    }
    for (site in sites) local({
      selected <- site
      expected <- registrations[[selected]]
      shiny::observeEvent(input[[paste0("connect_", selected)]], health$connect(selected))
      shiny::observeEvent(input[[paste0("read_", selected)]], perform(paste0("read_", selected), function() {
        conn <- connection(selected)
        context <- shinyOAuth::smart_context(conn)
        body <- httr2::resp_body_json(shinyOAuth::smart_patient(conn))
        stopifnot(identical(body$resourceType, "Patient"), identical(body$id, expected$patient),
          identical(context$patient, expected$patient))
        TRUE
      }))
      shiny::observeEvent(input[[paste0("user_", selected)]], perform(paste0("user_", selected), function() {
        body <- httr2::resp_body_json(shinyOAuth::smart_fhir_user(connection(selected)))
        stopifnot(identical(body$resourceType, "Practitioner"), identical(body$id, expected$practitioner),
          !identical(body$id, expected$patient))
        TRUE
      }))
      shiny::observeEvent(input[[paste0("refresh_", selected)]],
        perform(paste0("refresh_", selected), function() connection(selected)$refresh()))
    })
    shiny::observeEvent(input$logout, health$logout(revoke = FALSE))
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText(jsonlite::toJSON(list(session = session_number,
      connections = health$connections(), errors = health$errors(), result = result(),
      result_revision = revision()), auto_unbox = TRUE, null = "null"))
  }
  routes <- if (launch == "ehr") list(shinyOAuth::smart_launch_route("/launch", sites)) else list()
  ui <- shinyOAuth::oauth_connections_ui(ui, "health", manager, launch_routes = routes,
    request_uri_resolver = function(req) {
      # The private loopback proxy preserves Host and does not accept forwarded
      # headers. Reconstruct only the preconfigured public HTTPS authority.
      url <- httr2::url_parse(origin)
      stopifnot(identical(req$HTTP_HOST, paste0(url$hostname, ":", url$port)))
      paste0(origin, req$PATH_INFO,
        if (nzchar(req$QUERY_STRING)) paste0("?", req$QUERY_STRING))
    })
  shiny::runApp(shiny::shinyApp(ui, server, uiPattern = ".*"), host = "127.0.0.1",
    port = listen_port, launch.browser = FALSE, quiet = TRUE)
}
