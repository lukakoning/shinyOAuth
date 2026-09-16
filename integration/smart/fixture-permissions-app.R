permissions_app <- function(origin, listen_port, fhir_base, ca, async) {
  Sys.setenv(CURL_CA_BUNDLE = ca)
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  client <- shinyOAuth::smart_client(
    shinyOAuth::smart_discover(fhir_base),
    client_id = "permissions",
    redirect_uri = paste0(origin, "/callback"),
    scopes = c("launch/patient", "patient/Patient.rs", "offline_access"),
    required_scopes = "patient/Patient.r",
    identity = "fhirUser",
    token_auth_style = "public",
    label = "FHIR"
  )
  manager <- shinyOAuth::oauth_connections(
    list(a = client),
    origin,
    retention = "browser",
    owner_policy = shinyOAuth::oauth_browser_owner(),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    lapply(
      c("connect", "read", "user", "search", "other", "observation", "narrow"),
      function(id) {
        shiny::actionButton(paste0(id, "_a"), id)
      }
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
      async = async
    )
    result <- shiny::reactiveVal("ready")
    revision <- shiny::reactiveVal(0L)
    connection <- function() {
      rows <- health[["connections"]]()
      stopifnot(length(rows) == 1L)
      health[["connection"]](rows[[1L]][["connection_id"]])
    }
    perform <- function(id, fn) {
      finish <- function(value) {
        result(paste0(id, ":", value))
        revision(shiny::isolate(revision()) + 1L)
      }
      value <- tryCatch(fn(), error = function(...) "unavailable")
      if (inherits(value, "promise")) {
        promises::then(value, function(...) finish("ok"), function(...) {
          finish("unavailable")
        })
      } else {
        finish(value)
      }
    }
    resource <- function(kind) {
      conn <- connection()
      response <- switch(
        kind,
        read = shinyOAuth::smart_patient(conn),
        user = shinyOAuth::smart_fhir_user(conn),
        search = conn[["request"]]("fhir", "Patient"),
        other = conn[["request"]]("fhir", "Patient/synthetic-p2"),
        observation = conn[["request"]](
          "fhir",
          "Observation/synthetic-observation"
        )
      )
      status <- httr2::resp_status(response)
      body <- httr2::resp_body_json(response)
      if (kind %in% c("read", "user")) {
        stopifnot(
          status == 200L,
          body[["resourceType"]] == "Patient",
          body[["id"]] == "synthetic-p1"
        )
      }
      if (kind == "search" && status == 200L) {
        stopifnot(
          body[["resourceType"]] == "Bundle",
          length(body[["entry"]]) == 1L,
          body[["entry"]][[1L]][["resource"]][["id"]] == "synthetic-p1"
        )
      }
      if (status >= 400L) {
        stopifnot(body[["resourceType"]] == "OperationOutcome")
      }
      as.character(status)
    }
    shiny::observeEvent(input[["connect_a"]], health[["connect"]]("a"))
    for (kind in c("read", "user", "search", "other", "observation")) {
      local({
        selected <- kind
        shiny::observeEvent(
          input[[paste0(selected, "_a")]],
          perform(paste0(selected, "_a"), function() resource(selected))
        )
      })
    }
    shiny::observeEvent(
      input[["narrow_a"]],
      perform("narrow_a", function() {
        value <- connection()[["refresh"]](
          scopes = c(
            "patient/Patient.r",
            "offline_access",
            "openid",
            "fhirUser"
          )
        )
        if (inherits(value, "promise")) value else "ok"
      })
    )
    output[["result"]] <- shiny::renderText(result())
    output[["snapshot"]] <- shiny::renderText(jsonlite::toJSON(
      list(
        session = number,
        connections = health[["connections"]](),
        errors = health[["errors"]](),
        result = result(),
        result_revision = revision()
      ),
      auto_unbox = TRUE,
      null = "null"
    ))
  }
  ui <- shinyOAuth::oauth_connections_ui(
    ui,
    "health",
    manager,
    request_uri_resolver = function(req) {
      url <- httr2::url_parse(origin)
      stopifnot(identical(
        req[["HTTP_HOST"]],
        paste0(url[["hostname"]], ":", url[["port"]])
      ))
      paste0(
        origin,
        req[["PATH_INFO"]],
        if (nzchar(req[["QUERY_STRING"]])) paste0("?", req[["QUERY_STRING"]])
      )
    }
  )
  shiny::runApp(
    shiny::shinyApp(ui, server, uiPattern = ".*"),
    host = "127.0.0.1",
    port = listen_port,
    launch.browser = FALSE,
    quiet = TRUE
  )
}
