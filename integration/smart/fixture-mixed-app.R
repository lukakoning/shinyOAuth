# Ordinary OIDC remains an oauth_client; only the FHIR client opts into SMART.
smart_mixed_app <- function(origin, providers, async = FALSE, response_mode = "query",
  managed_oidc = FALSE, listen_port = NULL) {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  callbacks <- paste0(origin, "/callback/", c("a", "b"))
  site <- shinyOAuth::smart_discover(paste0(providers$a, "/fhir"))
  smart <- shinyOAuth::smart_client(site, "a", callbacks[[1]],
    scopes = c("launch/patient", "patient/Patient.rs", "user/Practitioner.r", "offline_access"),
    identity = "fhirUser", label = "SMART", response_mode = response_mode,
    authorization_server_mode = "multi_redirect_uri", authorization_server_redirect_uris = callbacks)
  provider <- shinyOAuth::oauth_provider(name = "OIDC", issuer = paste0(providers$b, "/fhir"),
    auth_url = paste0(providers$b, "/authorize"), token_url = paste0(providers$b, "/token"),
    jwks_uri = paste0(providers$b, "/keys"), userinfo_url = paste0(providers$b, "/userinfo"),
    token_auth_style = "public", use_pkce = TRUE, pkce_method = "S256", use_nonce = TRUE,
    id_token_required = TRUE, id_token_validation = TRUE, userinfo_required = TRUE,
    userinfo_id_token_match = TRUE)
  ordinary <- shinyOAuth::oauth_client(provider, "b", redirect_uri = callbacks[[2]],
    scopes = c("openid", "profile", "offline_access"), required_scopes = c("openid", "profile"),
    resource_bases = c(api = paste0(providers$b, "/api")), label = "OIDC", response_mode = response_mode,
    authorization_server_mode = "multi_redirect_uri", authorization_server_redirect_uris = callbacks)
  stopifnot(!length(ordinary@smart), !length(ordinary@scope_policy))
  clients <- if (managed_oidc) list(a = smart, b = ordinary) else list(a = smart)
  manager <- shinyOAuth::oauth_connections(clients, origin, retention = "browser",
    owner = shinyOAuth::oauth_browser_owner(), store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  base_ui <- shiny::fluidPage(shinyOAuth::use_shinyOAuth(),
    lapply(c("connect_a", "connect_b", "read_a", "read_b", "identity_b", "refresh_a", "refresh_b",
      "disconnect_a", "logout_b"), function(id) shiny::actionButton(id, id)),
    shiny::verbatimTextOutput("snapshot"), shiny::verbatimTextOutput("result"))
  sessions <- 0L
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    number <- sessions
    health <- shinyOAuth::oauth_connections_server("health", manager, async = async)
    login <- if (!managed_oidc) shinyOAuth::oauth_module_server("login", ordinary,
      auto_redirect = FALSE, async = async, refresh_proactively = TRUE,
      refresh_lead_seconds = 2, refresh_check_interval = 250) else NULL
    legacy <- if (!managed_oidc) shinyOAuth::oauth_connection(ordinary, shiny::reactive(login$token)) else NULL
    connection <- function(label) {
      if (label == "OIDC" && !managed_oidc) return(legacy)
      rows <- Filter(function(row) identical(row$client_label, label), health$connections())
      if (!length(rows)) stop("Unavailable")
      health$connection(tail(rows, 1)[[1]]$connection_id)
    }
    result <- shiny::reactiveVal("ready")
    revision <- shiny::reactiveVal(0L)
    complete <- function(value) {
      result(value)
      revision(shiny::isolate(revision()) + 1L)
    }
    perform <- function(fn) {
      value <- tryCatch(fn(), error = function(...) "unavailable")
      if (inherits(value, "promise")) promises::then(value, function(...) complete("refreshed"),
        function(...) complete("unavailable")) else complete(if (isTRUE(value)) "refreshed" else value)
    }
    shiny::observeEvent(input$connect_a, health$connect("a"))
    shiny::observeEvent(input$connect_b, if (managed_oidc) health$connect("b") else login$request_login())
    shiny::observeEvent(input$read_a, perform(function() {
      response <- shinyOAuth::smart_patient(connection("SMART"))
      paste0("a:", httr2::resp_body_json(response)$fixture_revision)
    }))
    shiny::observeEvent(input$read_b, perform(function() {
      response <- connection("OIDC")$request("api", "records")
      paste0("b:", httr2::resp_body_json(response)$revision)
    }))
    shiny::observeEvent(input$identity_b, perform(function() {
      value <- connection("OIDC")$identity(userinfo = "name")
      stopifnot(identical(value$id_token_claims$sub, "clinician-b"),
        identical(value$userinfo$name, "Synthetic OIDC Name"))
      if (!managed_oidc) stopifnot(!length(login$token@smart_context),
        is.null(login$token@extra_fields$patient))
      "identity:ok"
    }))
    shiny::observeEvent(input$refresh_a, perform(function() connection("SMART")$refresh()))
    if (managed_oidc) shiny::observeEvent(input$refresh_b,
      perform(function() connection("OIDC")$refresh()))
    shiny::observeEvent(input$disconnect_a, health$disconnect(connection("SMART")$id, revoke = FALSE))
    shiny::observeEvent(input$logout_b, if (managed_oidc) health$disconnect(connection("OIDC")$id,
      revoke = FALSE) else login$logout())
    output$result <- shiny::renderText(result())
    output$snapshot <- shiny::renderText(jsonlite::toJSON(list(session = number,
      connections = health$connections(), errors = health$errors(),
      oidc_authenticated = tryCatch(connection("OIDC")$is_usable(), error = function(...) FALSE),
      oidc_expiry = tryCatch(connection("OIDC")$summary()$expires_at, error = function(...) NULL),
      result = result(), result_revision = revision()), auto_unbox = TRUE, null = "null"))
  }
  ui <- shinyOAuth::oauth_connections_ui(base_ui, "health", manager,
    additional_clients = if (managed_oidc) list() else list(login = ordinary),
    request_uri_resolver = function(req) paste0(origin, req$PATH_INFO,
      if (nzchar(req$QUERY_STRING)) paste0("?", req$QUERY_STRING)))
  shiny::runApp(shiny::shinyApp(ui, server, uiPattern = ".*"), host = "127.0.0.1",
    port = listen_port, launch.browser = FALSE, quiet = TRUE)
}
