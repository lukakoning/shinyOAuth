target_fixture_app <- function(
  origin,
  providers,
  async = FALSE,
  response_mode = "query"
) {
  if (async) {
    mirai::daemons(2L)
    on.exit(mirai::daemons(0L), add = TRUE)
  }
  base <- providers[["a"]]
  provider <- shinyOAuth::oauth_provider(
    "targets",
    paste0(base, "/authorize"),
    paste0(base, "/token"),
    revocation_url = paste0(base, "/revoke"),
    use_nonce = FALSE,
    token_auth_style = "public",
    token_target_mode = "rfc8707"
  )
  client <- shinyOAuth::oauth_client(
    provider,
    "a",
    client_secret = "",
    redirect_uri = paste0(origin, "/callback/a"),
    response_mode = response_mode,
    scopes = c("calendar.read", "calendar.write", "contacts.read"),
    token_targets = list(
      calendar = list(
        resource = "urn:calendar",
        scopes = c("calendar.read", "calendar.write"),
        resource_ids = "calendar"
      ),
      contacts = list(
        resource = "urn:contacts",
        scopes = "contacts.read",
        resource_ids = "contacts"
      )
    ),
    default_token_target = "calendar",
    resource_bases = c(
      calendar = paste0(base, "/api/calendar"),
      contacts = paste0(base, "/api/contacts")
    )
  )
  manager <- shinyOAuth::oauth_connections(
    list(a = client),
    origin,
    retention = "browser",
    owner_policy = shinyOAuth::oauth_browser_owner(allow_http_loopback = TRUE),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  ui <- shinyOAuth::oauth_connections_ui(
    shiny::fluidPage(
      shinyOAuth::use_shinyOAuth(),
      lapply(
        c(
          "connect",
          "reauthorize",
          "narrow",
          "contacts",
          "pending",
          "wrong_target",
          "logout"
        ),
        function(id) shiny::actionButton(id, id)
      ),
      shiny::verbatimTextOutput("snapshot"),
      shiny::verbatimTextOutput("result")
    ),
    "auth",
    manager
  )
  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_connections_server("auth", manager, async = async)
    result <- shiny::reactiveVal("ready")
    revision <- shiny::reactiveVal(0L)
    complete <- function(value) {
      result(value)
      revision(shiny::isolate(revision()) + 1L)
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
            complete(as.character(value))
          }
        },
        error = function(...) complete("unavailable")
      )
    }
    shiny::observeEvent(input[["connect"]], auth[["connect"]]("a"))
    shiny::observeEvent(
      input[["reauthorize"]],
      auth[["reauthorize"]](auth[["connection"]]()[["id"]])
    )
    shiny::observeEvent(input[["logout"]], auth[["logout"]]())
    shiny::observeEvent(
      input[["narrow"]],
      perform(function() {
        auth[["connection"]]()[["refresh"]](scopes = "calendar.read")
      })
    )
    shiny::observeEvent(
      input[["contacts"]],
      perform(function() {
        response <- auth[["connection"]]()[["request"]](
          "contacts",
          "records",
          target = "contacts",
          refresh = TRUE
        )
        httr2::resp_body_json(response)[["target"]]
      })
    )
    shiny::observeEvent(
      input[["wrong_target"]],
      perform(function() {
        auth[["connection"]]()[["request"]](
          "calendar",
          "records",
          target = "contacts",
          refresh = TRUE
        )
      })
    )
    shiny::observeEvent(input[["pending"]], {
      current <- auth[["connection"]]()
      complete("pending")
      promises::then(
        current[["access_token"]](
          target = "contacts",
          force_refresh = TRUE,
          async = TRUE
        ),
        function(...) {
          if (!session[["isClosed"]]()) complete("completed")
        },
        function(...) {
          if (!session[["isClosed"]]()) complete("unavailable")
        }
      )
      # Let the pending state flush while the worker is still acquiring a token.
      invisible(NULL)
    })
    output[["result"]] <- shiny::renderText(result())
    output[["snapshot"]] <- shiny::renderText({
      current <- auth[["connection"]]()
      jsonlite::toJSON(
        list(
          result = result(),
          result_revision = revision(),
          connections = Filter(
            function(row) row[["status"]] != "disconnected",
            auth[["connections"]]()
          ),
          history = auth[["connections"]](),
          errors = auth[["errors"]](),
          can_write = !is.null(current) &&
            current[["has_scopes"]]("calendar.write"),
          targets = if (is.null(current)) NULL else current[["targets"]]()
        ),
        auto_unbox = TRUE,
        null = "null"
      )
    })
  }
  shiny::runApp(
    shiny::shinyApp(ui, server, uiPattern = ".*"),
    host = "127.0.0.1",
    port = as.integer(httr2::url_parse(origin)[["port"]]),
    launch.browser = FALSE,
    quiet = TRUE
  )
}
