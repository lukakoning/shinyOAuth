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
#'   * `connect(client_name)`: request a new authorization without discarding others.
#'     EHR-only clients report `fresh_ehr_launch_required` and return `FALSE`;
#'     use their registered [smart_launch_route()] to start authorization.
#'   * `connections()`: reactive list of redacted connection summaries.
#'   * `connection(connection_id)`: an [OAuthConnection] for requests and refresh.
#'   * `touch()`: record explicit user activity after checking the current owner.
#'     Call from an input event handler; returns `TRUE` invisibly.
#'   * `disconnect(connection_id, revoke = TRUE)`: remove local usability first,
#'     then return separate `local` and `remote` revocation results.
#'   * `disconnect_all(revoke = TRUE)`: cancel pending authorizations and disconnect
#'     this owner's stored connections; return a list of results.
#'   * `logout(revoke = TRUE, reload = TRUE)`: invalidate the local owner/session
#'     generation first, disconnect its connections, and normally reload the UI.
#'     This does not log the user out of the external OAuth provider or the app's
#'     own account authentication system.
#'   * `errors()`: reactive list of per-client module error codes, with no raw
#'     provider text. An ended owner is reported as `owner_unavailable`.
#' @details
#' References expire with this Shiny session even when their stored grants survive.
#' A new session obtains new references after owner verification. The existing
#' module never holds managed tokens, so its refresh observers cannot compete with
#' the manager. Refresh uses the store's revision and exclusive claim and preserves
#' the original authentication time and retention expiry.
#' Reactive connection reads also recheck expiry at `refresh_check_interval`,
#' including references used without `connections()` or `errors()`. These checks
#' notify dependent expressions when lifecycle state changes; unchanged polling
#' does not rerun application requests or extend owner inactivity limits.
#' Notifications to application code reflect only this owner's record changes.
#' Resource requests and status reads never reset owner inactivity, including when
#' reactive expressions rerun after automatic refresh. Call `touch()` from a user
#' input event handler to count an application action as activity. Do not call it
#' from polling observers or ordinary reactive readers. Connecting, explicitly
#' refreshing and disconnecting also count as activity.
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
#' # Outside server(), using clients with resource_bases already configured:
#' clients <- list(hospital_a = client_a, hospital_b = client_b)
#' manager <- oauth_connections(
#'   clients, app_origin = "https://app.example", retention = "browser",
#'   store = oauth_connection_store_memory(), owner = oauth_browser_owner(),
#'   keys = deployment_keys
#' )
#' ui <- oauth_connections_ui(app_ui, "health", manager)
#' server <- function(input, output, session) {
#'   health <- oauth_connections_server("health", manager)
#'   shiny::observeEvent(input$connect, health$connect(input$client_name))
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
    modules <- lapply(names(manager$clients), function(client_name) {
      oauth_module_server_impl(
        client_name,
        manager$clients[[client_name]],
        auto_redirect = FALSE,
        async = async,
        request_uri_base_url = manager$app_origin,
        .managed = controller$hooks(client_name)
      )
    })
    names(modules) <- names(manager$clients)
    lifecycle <- shiny::reactiveVal(NULL)
    launch_error <- shiny::reactiveVal(NULL)
    shiny::observeEvent(
      input$smart_launch,
      {
        tryCatch(
          {
            client_name <- controller$resume_launch(input$smart_launch)
            launch_error(NULL)
            modules[[client_name]]$request_login()
          },
          error = function(...) launch_error("fresh_ehr_launch_required")
        )
      },
      ignoreInit = FALSE
    )
    connection <- function(connection_id) {
      record <- controller$read(connection_id)
      OAuthConnection$new(
        connection_id,
        record$client,
        resolve = function() {
          controller$changed()
          lifecycle()
          controller$read(connection_id)
        },
        refresh = function(scopes = NULL) {
          controller$refresh(connection_id, async = async, scopes = scopes)
        }
      )
    }
    connections <- shiny::reactive({
      controller$changed()
      lifecycle()
      tryCatch(
        lapply(controller$records(), function(record) {
          connection_record_summary(record, record$stored$id)
        }),
        error = function(...) list()
      )
    })
    errors <- shiny::reactive({
      controller$changed()
      lifecycle()
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
      Filter(
        Negate(is.null),
        c(
          lapply(modules, function(module) module$error),
          list(smart_launch = launch_error())
        )
      )
    })
    shiny::observe({
      controller$changed()
      shiny::invalidateLater(refresh_check_interval, session)
      rows <- tryCatch(controller$records(), error = function(...) NULL)
      # Only lifecycle transitions invalidate reference consumers on a poll.
      # Explicit store changes notify this owner's consumers through changed().
      lifecycle(list(
        available = !is.null(rows),
        records = lapply(rows, function(record) {
          list(id = record$stored$id, status = connection_record_status(record))
        })
      ))
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
      connect = function(client_name) {
        controller$guard(touch = TRUE)
        if (!is_valid_string(client_name) || !client_name %in% names(modules)) {
          err_input("Unknown connection client")
        }
        if (identical(manager$clients[[client_name]]@smart$launch, "ehr")) {
          launch_error("fresh_ehr_launch_required")
          return(invisible(FALSE))
        }
        modules[[client_name]]$request_login()
      },
      connections = connections,
      connection = connection,
      touch = function() {
        controller$guard(touch = TRUE)
        invisible(TRUE)
      },
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
