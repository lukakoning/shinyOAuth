#' Connect, restore and use several OAuth authorizations in a Shiny session
#'
#' Call once inside `server()` with the manager and ID used by
#' [oauth_connections_ui()]. The returned methods select stored connections by
#' opaque IDs and recheck the local owner for every operation. Tokens are kept
#' on the server and are not returned by summaries or test exports.
#'
#' @param id Module ID shared with [oauth_connections_ui()].
#' @param manager Configuration from [oauth_connections()].
#' @param async Whether authorization and refresh use the existing async worker
#'   transport. Owner checks and store mutations stay in the original R process.
#' @param refresh_proactively Refresh before expiry when a refresh credential is
#'   available. Otherwise the manager attempts refresh at expiry.
#' @param refresh_lead_seconds Non-negative number of seconds before expiry used
#'   for proactive refresh. Background checks never extend owner inactivity limits.
#' @param refresh_check_interval Positive polling interval in milliseconds, at
#'   least 100. Safely retryable automatic refresh failures wait at least 30 seconds;
#'   an uncertain refresh requires reconnecting.
#' @return A server-side list with:
#'   * `connect(target_id)`: request a new authorization without discarding others.
#'     EHR-only targets report `fresh_ehr_launch_required` and return `FALSE`;
#'     use their registered [smart_launch_route()] to start authorization.
#'   * `connections()`: reactive list of redacted connection summaries.
#'   * `connection(connection_id)`: an [OAuthConnectionRef] for requests and refresh.
#'   * `disconnect(connection_id, revoke = TRUE)`: remove local usability first,
#'     then return separate `local` and `remote` revocation results.
#'   * `disconnect_all(revoke = TRUE)`: cancel pending authorizations and disconnect
#'     this owner's stored connections; return a list of results.
#'   * `logout(revoke = TRUE, reload = TRUE)`: invalidate the local owner/session
#'     generation first, disconnect its connections, and normally reload the UI.
#'     This does not log the user out of the external OAuth provider or the app's
#'     own account authentication system.
#'   * `errors()`: reactive list of per-target module error codes, with no raw
#'     provider text. An ended owner is reported as `owner_unavailable`.
#' @details
#' References expire with this Shiny session even when their stored grants survive.
#' A new session obtains new references after owner verification. The existing
#' module never holds managed tokens, so its refresh observers cannot compete with
#' the manager. Refresh uses the store's revision and exclusive claim and preserves
#' the original authentication time and retention expiry.
#'
#' Remote revocation is best effort: at most ten seconds per disconnect/logout
#' batch, at most two seconds and one HTTP attempt per credential. Results are
#' `accepted`, `unsupported`, `missing`, `failed` or `not_attempted` for access and
#' refresh credentials. `accepted` describes the endpoint response, not proof of
#' prior token validity. Local disconnect remains effective if revocation fails.
#'
#' Use this API inside its owning session's reactive context. Session setup
#' requires a matching HTTP Origin on the Shiny request. Raw HTTP routes cannot
#' import credentials or select an owner. This initial manager supports one R
#' process. The two-site real-browser interoperability gate remains a separate
#' roadmap checkpoint; mocked Shiny tests do not establish that evidence.
#' @examples
#' \dontrun{
#' # Outside server(), using two separately registered OAuth clients:
#' targets <- list(
#'   hospital_a = oauth_target(client_a, c(fhir = "https://a.example/fhir")),
#'   hospital_b = oauth_target(client_b, c(fhir = "https://b.example/fhir"))
#' )
#' manager <- oauth_connections(
#'   targets, app_origin = "https://app.example", retention = "browser",
#'   store = oauth_connection_store_memory(), owner = oauth_browser_owner(),
#'   keys = deployment_keys
#' )
#' ui <- oauth_connections_ui(app_ui, "health", manager)
#' server <- function(input, output, session) {
#'   health <- oauth_connections_server("health", manager)
#'   shiny::observeEvent(input$connect, health$connect(input$target_id))
#'   data <- shiny::reactive({
#'     connection <- health$connection(input$connection_id)
#'     shiny::req(connection$is_usable())
#'     connection$request("fhir", "Patient/123")
#'   })
#' }
#' shiny::shinyApp(ui, server, uiPattern = ".*")
#' }
#' @export
oauth_connections_server <- function(
  id,
  manager,
  async = FALSE,
  refresh_proactively = FALSE,
  refresh_lead_seconds = 60,
  refresh_check_interval = 10000
) {
  connection_manager_bind(manager, id)
  if (!isTRUE(manager$state$ui_bound)) {
    err_config("Configure oauth_connections_ui() before starting its server")
  }
  connection_manager_flag(async, "async")
  connection_manager_flag(refresh_proactively, "refresh_proactively")
  if (
    !is.numeric(refresh_lead_seconds) ||
      length(refresh_lead_seconds) != 1L ||
      !is.finite(refresh_lead_seconds) ||
      refresh_lead_seconds < 0 ||
      !is.numeric(refresh_check_interval) ||
      length(refresh_check_interval) != 1L ||
      !is.finite(refresh_check_interval) ||
      refresh_check_interval < 100
  ) {
    err_config("Invalid connection refresh timing")
  }
  shiny::moduleServer(id, function(input, output, session) {
    controller <- connection_manager_controller(manager, session)
    session$onSessionEnded(controller$end)
    modules <- lapply(names(manager$targets), function(target_id) {
      oauth_module_server_impl(
        target_id,
        manager$targets[[target_id]]$client,
        auto_redirect = FALSE,
        async = async,
        request_uri_base_url = manager$app_origin,
        .managed = controller$hooks(target_id)
      )
    })
    names(modules) <- names(manager$targets)
    launch_error <- shiny::reactiveVal(NULL)
    shiny::observeEvent(input$smart_launch, {
      tryCatch({
        target_id <- controller$resume_launch(input$smart_launch)
        launch_error(NULL)
        modules[[target_id]]$request_login()
      }, error = function(...) launch_error("fresh_ehr_launch_required"))
    }, ignoreInit = FALSE)
    connection <- function(connection_id) {
      record <- controller$read(connection_id)
      OAuthConnectionRef$new(
        connection_id,
        record$target,
        resolve = function() {
          manager$state$signal()
          controller$read(connection_id)
        },
        refresh = function() controller$refresh(connection_id, async = async),
        touch = function() controller$guard(touch = TRUE)
      )
    }
    connections <- shiny::reactive({
      manager$state$signal()
      shiny::invalidateLater(refresh_check_interval, session)
      tryCatch(
        lapply(controller$records(), function(record) {
          connection(record$stored$id)$summary()
        }),
        error = function(...) list()
      )
    })
    errors <- shiny::reactive({
      manager$state$signal()
      shiny::invalidateLater(refresh_check_interval, session)
      available <- tryCatch(
        {
          controller$guard()
          TRUE
        },
        error = function(...) FALSE
      )
      if (!available) {
        return(list(owner = "owner_unavailable"))
      }
      Filter(Negate(is.null), c(lapply(modules, function(module) module$error),
        list(smart_launch = launch_error())))
    })
    shiny::observe({
      manager$state$signal()
      shiny::invalidateLater(refresh_check_interval, session)
      rows <- tryCatch(controller$records(), error = function(...) list())
      for (record in rows) {
        token <- record$token
        now <- as.numeric(Sys.time())
        lead <- if (refresh_proactively) refresh_lead_seconds else 0
        if (
          identical(record$status, "active") &&
            !is.null(token) &&
            !is.na(token@expires_at) &&
            token@expires_at <= now + lead &&
            is_valid_string(token@refresh_token) &&
            now >= (controller$next_refresh[[record$stored$id]] %||% 0)
        ) {
          result <- tryCatch(
            controller$refresh(record$stored$id, async = async, touch = FALSE),
            error = function(...) NULL
          )
          if (inherits(result, "promise")) {
            promises::catch(result, function(...) NULL)
          }
        }
      }
    })
    list(
      connect = function(target_id) {
        controller$guard(touch = TRUE)
        if (!is_valid_string(target_id) || !target_id %in% names(modules)) {
          err_input("Unknown connection target")
        }
        if (identical(manager$targets[[target_id]]$smart$launch, "ehr")) {
          launch_error("fresh_ehr_launch_required")
          return(invisible(FALSE))
        }
        modules[[target_id]]$request_login()
      },
      connections = connections,
      connection = connection,
      errors = errors,
      disconnect = controller$disconnect,
      disconnect_all = controller$disconnect_all,
      logout = function(revoke = TRUE, reload = TRUE) {
        connection_manager_flag(reload, "reload")
        result <- controller$logout(revoke)
        for (module in modules) {
          module$logout()
        }
        if (reload) {
          session$reload()
        }
        result
      }
    )
  })
}
