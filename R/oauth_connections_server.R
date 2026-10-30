#' Connect, restore and use several OAuth authorizations in a Shiny session
#'
#' Let users connect several accounts or services, choose a saved connection,
#' and call its API from your Shiny server. Call this once inside `server()` with
#' the manager and ID used by [oauth_connections_ui()]. Connection summaries show
#' status without exposing tokens; server code can obtain a current token from
#' the selected connection when another R package needs it.
#'
#' @param id Module ID shared with [oauth_connections_ui()].
#' @param manager Configuration from [oauth_connections()].
#' @param async Whether authorization and refresh use the existing async worker
#'   transport. Owner checks and store mutations stay in the original R process.
#' @param refresh_proactively Refresh before expiry when a refresh credential is
#'   available. Otherwise the manager attempts refresh at expiry.
#' @param refresh_lead_seconds Non-negative number of seconds before expiry used
#'   for proactive refresh. Background checks never extend owner inactivity limits.
#' @param refresh_check_interval_ms Positive polling interval in milliseconds, at
#'   least 100. Safely retryable automatic refresh failures wait at least 30 seconds
#'   across all connections sharing the same refresh credential and registration;
#'   an uncertain refresh requires reconnecting.
#' @return A server-side list with:
#'   * `connect(client_name)`: request a new authorization without discarding others.
#'     EHR-only clients report `fresh_ehr_launch_required` and return `FALSE`;
#'     use their registered [smart_launch_route()] to start authorization.
#'   * `connections()`: reactive list of redacted connection summaries.
#'   * `connection(connection_id = NULL)`: an [OAuthConnection] for requests, refresh,
#'     scope checks and server-side `$access_token()` retrieval for external SDKs.
#'   * `reauthorize(connection_id)`: end this local authorization and start its
#'     replacement with the retained scope limit, without upstream revocation.
#'     Local state preparation is checked first; rejection preserves current access.
#'     The replacement summary includes `replaces_connection_id`. Failed/cancelled
#'     replacement leaves the old reference invalid. Unrelated authorizations
#'     remain usable; shared-credential protections still apply. EHR-only clients
#'     require a fresh EHR launch instead.
#'   * `touch()`: record explicit user activity after checking the current owner;
#'     returns `TRUE` invisibly.
#'   * `disconnect(connection_id, revoke = TRUE)`: remove local usability first,
#'     then return separate `local` and `remote` revocation results.
#'     For token targets, `remote$access` summarizes all acquired API tokens;
#'     incomplete or failed cleanup takes priority over successful cleanup.
#'   * `disconnect_all(revoke = TRUE)`: cancel pending authorizations and disconnect
#'     this owner's stored connections; return a list of results.
#'   * `logout(revoke = TRUE, reload = TRUE)`: end the local owner session,
#'     disconnect its connections, and normally reload the UI.
#'     This does not log the user out of the external OAuth provider or the app's
#'     own account authentication system.
#'   * `errors()`: reactive list of per-client module error codes, with no raw
#'     provider text. An ended owner is reported as `owner_unavailable`.
#' @details
#' Use `auth$connections()` to populate a selection control, then
#' `connection <- auth$connection(selected_id)` for the chosen account.
#' `connection$request()` calls a configured API; `connection$access_token()`
#' supplies a current token for another R package. See
#' `vignette("multiple-authorizations", package = "shinyOAuth")`
#' ([online guide](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.html))
#' for a complete app and `vignette("external-integrations", package = "shinyOAuth")`
#' ([online guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html))
#' for API client and database examples.
#'
#' @section Advanced lifetime and refresh behavior:
#' Each Shiny session needs its own connection references, even when the manager
#' retains the saved authorizations. A new session obtains these after owner
#' verification. The manager coordinates refresh across its connections without
#' changing the original authentication time or retention expiry.
#' Reactive connection reads also recheck expiry at `refresh_check_interval_ms`,
#' including references used without `connections()` or `errors()`. These checks
#' notify reactive expressions when connection status changes; unchanged polling
#' does not rerun application requests or extend owner inactivity limits.
#' Notifications to application code reflect only this owner's record changes.
#' Without an ID, `connection()` returns NULL when no authorization remains,
#' selects the sole retained authorization, or raises `shinyOAuth_access_error`
#' with reason `selection_required` when several remain. Expired, limited and
#' uncertain authorizations count toward ambiguity; disconnected rows do not.
#'
#' Reactive expressions that read `connection()`, `$access_token()` or
#' `$has_scopes()` do not rerun on token refresh alone if the login and permissions
#' stay the same. Token acquisition never extends owner idle limits or replays
#' application requests. See
#' `vignette("external-integrations", package = "shinyOAuth")`
#' ([online guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html)).
#' Resource requests and status reads do not reset owner inactivity, including
#' reactive reads after automatic refresh. `touch()` explicitly records activity,
#' for example from an input event handler. Connecting, explicitly refreshing and
#' disconnecting also count as activity.
#'
#' Remote revocation is best effort: at most ten seconds per disconnect/logout
#' batch, at most two seconds and one HTTP attempt per credential. Results are
#' `accepted`, `unsupported`, `missing`, `failed` or `not_attempted` for access and
#' refresh credentials. `accepted` describes the endpoint response, not proof of
#' prior token validity. Local disconnect remains effective if revocation fails.
#' A provider may revoke an entire authorization grant or related credentials
#' (RFC 7009 section 2.1). Separate connection IDs do not establish independent
#' provider grants, even after repeated consent or account selection. Consequently,
#' default `revoke = TRUE` may also end access for sibling connections or other
#' applications covered by the provider's revocation policy. With `revoke = FALSE`,
#' disconnect removes local access without requesting remote revocation. This also
#' applies to credentials returned by work already in flight. Removed credentials
#' remain valid remotely until the provider expires or revokes them. Local summaries
#' and `is_usable()` reflect local state, independently of remote provider changes.
#'
#' The API checks its owning session's reactive context. Session setup requires
#' a matching HTTP Origin on the Shiny request. Raw HTTP routes cannot
#' import credentials or select an owner. The manager supports one R process.
#' @example inst/examples/oauth_connections.R
#' @export
oauth_connections_server <- function(
  id,
  manager,
  async = FALSE,
  refresh_proactively = FALSE,
  refresh_lead_seconds = 60,
  refresh_check_interval_ms = 10000
) {
  connection_manager_bind(manager, id)
  if (!isTRUE(manager[["state"]][["ui_bound"]])) {
    err_config("Configure oauth_connections_ui() before starting its server")
  }
  connection_manager_flag(async, "async")
  connection_manager_flag(refresh_proactively, "refresh_proactively")
  if (
    !is.numeric(refresh_lead_seconds) ||
      length(refresh_lead_seconds) != 1L ||
      !is.finite(refresh_lead_seconds) ||
      refresh_lead_seconds < 0 ||
      !is.numeric(refresh_check_interval_ms) ||
      length(refresh_check_interval_ms) != 1L ||
      !is.finite(refresh_check_interval_ms) ||
      refresh_check_interval_ms < 100
  ) {
    err_config("Invalid connection refresh timing")
  }
  shiny::moduleServer(id, function(input, output, session) {
    controller <- connection_manager_controller(
      manager,
      session,
      refresh_lead_seconds
    )
    modules <- lapply(names(manager[["clients"]]), function(client_name) {
      oauth_module_server_impl(
        client_name,
        manager[["clients"]][[client_name]],
        auto_redirect = FALSE,
        async = async,
        request_uri_base_url = manager[["state"]][["app_base"]],
        .managed = controller[["hooks"]](client_name)
      )
    })
    names(modules) <- names(manager[["clients"]])
    lifecycle <- shiny::reactiveVal(NULL)
    authorization <- shiny::reactiveVal(NULL)
    references <- new.env(parent = emptyenv())
    launch_error <- shiny::reactiveVal(NULL)
    shiny::observeEvent(
      input[["smart_launch"]],
      {
        tryCatch(
          {
            client_name <- controller[["resume_launch"]](input[[
              "smart_launch"
            ]])
            launch_error(NULL)
            modules[[client_name]][["request_login"]]()
          },
          error = function(...) launch_error("fresh_ehr_launch_required")
        )
      },
      ignoreInit = FALSE
    )
    connection <- function(connection_id = NULL) {
      authorization()
      if (is.null(connection_id)) {
        rows <- shiny::isolate(controller[["records"]]())
        rows <- Filter(
          function(record) !identical(record[["status"]], "disconnected"),
          rows
        )
        if (!length(rows)) {
          return(NULL)
        }
        if (length(rows) != 1L) {
          connection_access_error("selection_required")
        }
        connection_id <- rows[[1L]][["stored"]][["id"]]
      }
      record <- shiny::isolate(controller[["read"]](connection_id))
      if (!is.null(references[[connection_id]])) {
        return(references[[connection_id]][["reference"]])
      }
      current <- shiny::reactiveVal(
        !identical(record[["status"]], "disconnected")
      )
      reference <- OAuthConnection[["new"]](
        connection_id,
        record[["client"]],
        is_current = current,
        resolve = function() {
          controller[["changed"]]()
          lifecycle()
          controller[["read"]](connection_id)
        },
        refresh = function(scopes = NULL, target = NULL) {
          controller[["refresh"]](
            connection_id,
            async = async,
            scopes = scopes,
            target = target
          )
        },
        acquire = function(
          async = FALSE,
          target = NULL,
          wait_only = FALSE,
          reuse_cached = NULL
        ) {
          controller[["acquire"]](
            connection_id,
            async = async,
            target = target,
            wait_only = wait_only,
            reuse_cached = reuse_cached
          )
        }
      )
      if (shiny::isolate(current())) {
        references[[connection_id]] <- list(
          reference = reference,
          current = current
        )
      }
      reference
    }
    connections <- shiny::reactive({
      controller[["changed"]]()
      lifecycle()
      tryCatch(
        lapply(controller[["records"]](), function(record) {
          connection_record_summary(record, record[["stored"]][["id"]])
        }),
        error = function(...) list()
      )
    })
    errors <- shiny::reactive({
      controller[["changed"]]()
      lifecycle()
      available <- tryCatch(
        {
          controller[["guard"]]()
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
          lapply(modules, function(module) module[["error"]]),
          list(smart_launch = launch_error())
        )
      )
    })
    shiny::observe({
      controller[["changed"]]()
      shiny::invalidateLater(refresh_check_interval_ms, session)
      rows <- tryCatch(controller[["poll"]](), error = function(...) NULL)
      if (!is.null(rows)) {
        retained <- vapply(
          Filter(
            function(record) !identical(record[["status"]], "disconnected"),
            rows
          ),
          function(record) record[["stored"]][["id"]],
          character(1)
        )
        for (id in setdiff(ls(references, all.names = TRUE), retained)) {
          references[[id]][["current"]](FALSE)
          rm(list = id, envir = references)
        }
      }
      authorization(list(
        available = !is.null(rows),
        records = lapply(rows, function(record) {
          list(
            id = record[["stored"]][["id"]],
            available = record[["status"]] %in% c("active", "refreshing")
          )
        })
      ))
      # Only lifecycle transitions invalidate reference consumers on a poll.
      # Explicit store changes notify this owner's consumers through changed().
      lifecycle(list(
        available = !is.null(rows),
        records = lapply(rows, function(record) {
          list(
            id = record[["stored"]][["id"]],
            status = record[["lifecycle_status"]]
          )
        })
      ))
      for (record in rows) {
        now <- as.numeric(Sys.time())
        lead <- if (refresh_proactively) refresh_lead_seconds else 0
        if (
          identical(record[["status"]], "active") &&
            isTRUE(record[["refreshable"]]) &&
            !is.na(record[["refresh_at"]]) &&
            record[["refresh_at"]] <= now + lead
        ) {
          result <- tryCatch(
            controller[["refresh"]](
              record[["stored"]][["id"]],
              async = async,
              touch = FALSE
            ),
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
        controller[["guard"]](touch = TRUE)
        if (!is_valid_string(client_name) || !client_name %in% names(modules)) {
          err_input("Unknown connection client")
        }
        if (
          identical(
            manager[["clients"]][[client_name]]@smart[["launch"]],
            "ehr"
          )
        ) {
          launch_error("fresh_ehr_launch_required")
          return(invisible(FALSE))
        }
        modules[[client_name]][["request_login"]]()
      },
      connections = connections,
      connection = connection,
      reauthorize = function(connection_id) {
        client_name <- controller[["reauthorize"]](connection_id)
        modules[[client_name]][[".reauthorize"]]()
      },
      touch = function() {
        controller[["guard"]](touch = TRUE)
        invisible(TRUE)
      },
      errors = errors,
      disconnect = controller[["disconnect"]],
      disconnect_all = controller[["disconnect_all"]],
      logout = function(revoke = TRUE, reload = TRUE) {
        connection_manager_flag(reload, "reload")
        result <- controller[["logout"]](revoke)
        for (module in modules) {
          module[["logout"]]()
        }
        if (reload) {
          session[["reload"]]()
        }
        result
      }
    )
  })
}
