#' Configure several independently managed OAuth connections
#'
#' Create one manager outside `server()` for a named set of client/API
#' configurations from [oauth_target()]. Use [oauth_connections_ui()] to handle
#' callbacks and [oauth_connections_server()] for each Shiny session. Each
#' successful authorization creates a separate connection, including repeated
#' authorizations at the same target.
#'
#' @param targets Non-empty named list of [OAuthTarget] objects, at most 64.
#'   Names are local target IDs: a letter followed by letters, digits, `_` or `-`,
#'   with a maximum of 64 characters.
#' @param app_origin Public application origin, including a non-default port.
#'   HTTPS is required for retained owners, except an explicit browser-owner
#'   HTTP loopback exception. Session-only development also permits loopback HTTP.
#' @param callback_policy `"distinct_routes"` (default) gives each target its own
#'   registered callback route. With several targets, configure every client with
#'   `authorization_server_mode = "multi_redirect_uri"` and the complete set of
#'   routes in `authorization_server_redirect_uris`.
#'   `"issuer"` allows shared routes for distinct authorization-server issuers.
#'   `"shared_routes"` additionally supports several targets or registrations at
#'   one issuer through a protected pending-state index. Both opt-in policies
#'   require explicit `authorization_server_mode = "multi_issuer"` clients, with
#'   RFC 9207 issuer responses or JARM. Same-issuer encrypted JARM still requires
#'   distinct routes. Routing never substitutes for callback authentication.
#' @param retention `"shiny"` (default) discards connections at Shiny session end.
#'   `"browser"` restores the browser owner's connections after navigation;
#'   `"account"` uses a trusted local application login. Retention does not request
#'   refresh tokens or extend provider authorization.
#' @param store A store from [oauth_connection_store_memory()]. Required for
#'   retained modes; session-only mode creates a memory store by default. This
#'   initial manager supports one R process and rejects external adapter claims.
#' @param owner [oauth_browser_owner()] or [oauth_account_owner()] matching the
#'   retained mode. Must be `NULL` for session-only retention.
#' @param keys Named list with `credentials` and `owner`, each a deployment-held
#'   raw vector of 32 bytes. Required for retained modes. Session-only mode creates
#'   ephemeral keys if omitted. Keep these keys outside credential storage.
#' @param retention_seconds Maximum lifetime of each stored grant, in seconds.
#'   Positive and finite, no larger than the store's `max_age`. Refresh never
#'   resets it. Browser retention is also capped by the owner's absolute expiry.
#' @return An `OAuthConnections` server-side configuration object. Printing shows
#'   only the retention mode and target count. It contains client configuration
#'   and deployment keys and must never be sent to the browser.
#' @details
#' A manager is bound to one UI/server module ID and one public origin. Create
#' another manager for another namespace. The memory store and owner registries
#' survive Shiny sessions, not R restarts; copies in another R process fail closed.
#'
#' In session-only mode, a pending authorization survives navigation through the
#' existing single-use OAuth state and browser binding, while existing grants are
#' discarded with the old Shiny session. Browser/account mode additionally binds
#' authorization to the initiating local owner and its session generation.
#'
#' These are optional package interfaces, not SMART protocol objects. This manager
#' supports generic OAuth targets and the SMART discovery, scope and launch
#' policies configured by [smart_target()].
#' @seealso [oauth_connections_ui()], [oauth_connections_server()]
#' @export
oauth_connections <- function(
  targets,
  app_origin,
  callback_policy = "distinct_routes",
  retention = c("shiny", "browser", "account"),
  store = NULL,
  owner = NULL,
  keys = NULL,
  retention_seconds = 28800
) {
  retention <- match.arg(retention)
  if (!is_valid_string(callback_policy) ||
      !callback_policy %in% c("distinct_routes", "issuer", "shared_routes")) {
    err_config(
      "callback_policy must be distinct_routes, issuer or shared_routes"
    )
  }
  if (
    !is.list(targets) ||
      !length(targets) ||
      length(targets) > 64L ||
      is.null(names(targets)) ||
      anyNA(names(targets)) ||
      anyDuplicated(names(targets)) ||
      !all(grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", names(targets))) ||
      !all(vapply(targets, inherits, logical(1), "OAuthTarget"))
  ) {
    err_config("targets must be a named list of approved OAuth targets")
  }
  if (retention == "shiny") {
    if (!is.null(owner)) {
      err_config("Session-only retention does not use an owner policy")
    }
    origin_policy <- list(allow_http_loopback = TRUE)
    store <- store %||% oauth_connection_store_memory()
    keys <- keys %||%
      list(
        credentials = openssl::rand_bytes(32L),
        owner = openssl::rand_bytes(32L)
      )
  } else {
    if (
      !inherits(owner, "OAuthOwnerPolicy") || !identical(owner$mode, retention)
    ) {
      err_config("Retained connections require the matching local owner policy")
    }
    origin_policy <- owner
  }
  app_origin <- connection_owner_origin(app_origin, origin_policy)
  if (
    !inherits(store, "OAuthConnectionStore") ||
      !identical(store$scope, "process") ||
      !identical(store$version, 1L)
  ) {
    err_config("A process-local connection store is required")
  }
  connection_owner_timeouts(retention_seconds, retention_seconds)
  if (retention_seconds > store$max_age) {
    err_config("Retention exceeds the store's maximum age")
  }
  if (
    !is.list(keys) ||
      !setequal(names(keys), c("credentials", "owner")) ||
      anyDuplicated(names(keys)) ||
      !all(vapply(
        keys,
        function(key) {
          is.raw(key) && length(key) == 32L
        },
        logical(1)
      ))
  ) {
    err_config(
      "Connection keys must contain 32-byte credentials and owner keys"
    )
  }
  routes <- lapply(targets, function(target) {
    connection_current_target_fingerprint(target)
    client <- target$client
    if (
      identical(callback_policy, "distinct_routes") && length(targets) > 1L &&
        !identical(client@authorization_server_mode, "multi_redirect_uri")
    ) {
      err_config("Multiple targets require multi_redirect_uri clients")
    }
    if (callback_policy != "distinct_routes" &&
        !identical(client@authorization_server_mode, "multi_issuer")) {
      err_config("Issuer-based callback policies require explicit multi_issuer clients")
    }
    if (!connection_manager_same_origin(client@redirect_uri, app_origin)) {
      err_config("Every callback must use the configured application origin")
    }
    oauth_callback_route(client@redirect_uri)
  })
  if (
    identical(callback_policy, "distinct_routes") && anyDuplicated(vapply(
      routes,
      function(route) {
        as.character(jsonlite::toJSON(route, auto_unbox = TRUE))
      },
      character(1)
    ))
  ) {
    err_config("Each target requires a distinct callback route")
  }
  if (callback_policy != "distinct_routes") {
    oauth_callback_registry(lapply(targets, function(target) target$client),
      allow_shared_issuer = identical(callback_policy, "shared_routes"), mark_ui = FALSE)
  }
  state <- new.env(parent = emptyenv())
  state$id <- NULL
  state$ui_bound <- FALSE
  state$owners <- NULL
  state$pending <- new.env(parent = emptyenv())
  state$routes <- new.env(parent = emptyenv())
  state$launches <- new.env(parent = emptyenv())
  state$next_refresh <- new.env(parent = emptyenv())
  state$signal <- shiny::reactiveVal(0)
  manager <- new.env(parent = emptyenv())
  for (name in c(
    "targets",
    "app_origin",
    "callback_policy",
    "retention",
    "store",
    "owner",
    "keys",
    "retention_seconds"
  )) {
    manager[[name]] <- get(name)
  }
  manager$process <- Sys.getpid()
  manager$state <- state
  class(manager) <- "OAuthConnections"
  lockEnvironment(manager, bindings = TRUE)
  manager
}

#' @rdname oauth_connections
#' @param x A connection manager to print.
#' @param ... Unused print arguments.
#' @export
print.OAuthConnections <- function(x, ...) {
  cat(
    "<OAuthConnections: ",
    length(x$targets),
    " target(s); ",
    x$retention,
    " retention; credentials redacted>\n",
    sep = ""
  )
  invisible(x)
}

connection_manager_check <- function(manager) {
  if (
    !inherits(manager, "OAuthConnections") ||
      !is.environment(manager) ||
      !identical(manager$process, Sys.getpid())
  ) {
    err_config(
      "The connection manager is available only in its original R process"
    )
  }
  invisible(NULL)
}

connection_manager_same_origin <- function(uri, origin) {
  tryCatch(
    identical(
      resource_binding_components(uri)[c("scheme", "host", "port")],
      resource_binding_components(origin)[c("scheme", "host", "port")]
    ),
    error = function(...) FALSE
  )
}

connection_manager_bind <- function(manager, id) {
  connection_manager_check(manager)
  connection_owner_namespace(id)
  state <- manager$state
  if (!is.null(state$id)) {
    if (!identical(state$id, id)) {
      err_config("A manager can use only one module namespace")
    }
    return(invisible(NULL))
  }
  owners <- switch(
    manager$retention,
    browser = connection_browser_sessions(
      manager$owner,
      manager$app_origin,
      id,
      manager$keys$owner
    ),
    account = connection_account_sessions(
      manager$owner,
      manager$app_origin,
      id,
      manager$keys$owner
    ),
    shiny = NULL
  )
  state$id <- id
  state$owners <- owners
  invisible(NULL)
}

connection_manager_signal <- function(manager) {
  signal <- manager$state$signal
  signal(shiny::isolate(signal()) + 1)
  invisible(NULL)
}

# At most ten seconds for a batch, with a single attempt per credential. Report
# remote acceptance separately: a successful revocation response does not prove
# that the provider previously recognized the token (RFC 7009 section 2.2).
connection_manager_revoke <- function(manager, target, token, deadline) {
  if (is.null(token)) {
    return(list(refresh = "not_attempted", access = "not_attempted"))
  }
  unchanged <- tryCatch(
    {
      connection_current_target_fingerprint(target)
      TRUE
    },
    error = function(...) FALSE
  )
  if (!unchanged) {
    return(list(refresh = "not_attempted", access = "not_attempted"))
  }
  result <- lapply(c("refresh", "access"), function(which) {
    remaining <- deadline - as.numeric(Sys.time())
    if (remaining <= 0) {
      return("not_attempted")
    }
    settings <- capture_async_options()
    settings$shinyOAuth.timeout <- min(2, remaining)
    settings$shinyOAuth.retry_max_tries <- 1L
    tryCatch(
      with_async_options(
        settings,
        {
          response <- revoke_token(target$client, token, which = which)
          if (isTRUE(response$revoked)) {
            "accepted"
          } else if (identical(response$supported, FALSE)) {
            "unsupported"
          } else if (identical(response$status, "missing_token")) {
            "missing"
          } else {
            "failed"
          }
        }
      ),
      error = function(...) "failed"
    )
  })
  stats::setNames(result, c("refresh", "access"))
}

connection_manager_controller <- function(manager, session) {
  connection_manager_check(manager)
  root <- connection_session_root(session)
  if (
    is.null(root) ||
      isTRUE(root$isClosed()) ||
      !identical(
        root,
        connection_session_root(shiny::getDefaultReactiveDomain())
      )
  ) {
    err_config("Create managed connections inside their owning Shiny session")
  }
  origin <- root$request[["HTTP_ORIGIN"]]
  if (
    !is_valid_string(origin) ||
      !connection_manager_same_origin(origin, manager$app_origin) ||
      !identical(resource_binding_components(origin)$path, "/") ||
      grepl("[?#]", origin)
  ) {
    err_config("Connection sessions require the configured application Origin")
  }
  state <- manager$state
  if (is.null(state$id)) {
    err_config("Bind the manager's UI and server namespace first")
  }
  at <- as.numeric(Sys.time())
  owner <- switch(
    manager$retention,
    browser = state$owners$resolve(connection_owner_cookie_read(
      root$request,
      state$owners$cookie_name
    )),
    account = state$owners$establish(root),
    shiny = list(
      id = random_urlsafe(32L),
      generation = random_urlsafe(32L),
      created_at = at,
      expires_at = at + manager$retention_seconds
    )
  )
  if (is.null(owner)) {
    err_config("No active local owner; return through the connection UI")
  }
  active <- TRUE
  store <- manager$store
  next_refresh <- state$next_refresh
  signal <- function() connection_manager_signal(manager)
  verify_owner <- function(require_session = TRUE, touch = FALSE) {
    connection_manager_check(manager)
    if (
      require_session &&
        (!active ||
          isTRUE(root$isClosed()) ||
          !identical(
            root,
            connection_session_root(shiny::getDefaultReactiveDomain())
          ))
    ) {
      return(NULL)
    }
    switch(
      manager$retention,
      browser = state$owners$validate(owner, touch),
      account = state$owners$validate(owner, root, touch),
      shiny = if (
        active &&
          !isTRUE(root$isClosed()) &&
          as.numeric(Sys.time()) < owner$expires_at
      ) {
        owner
      } else {
        NULL
      }
    )
  }
  guard <- function(touch = FALSE) {
    verified <- verify_owner(touch = touch)
    if (is.null(verified)) {
      err_token("Connection owner is unavailable")
    }
    verified
  }
  target_for <- function(id) {
    if (!is_valid_string(id) || !id %in% names(manager$targets)) {
      err_input("Unknown connection target")
    }
    manager$targets[[id]]
  }
  prune_pending <- function() {
    now <- as.numeric(Sys.time())
    for (id in ls(state$pending, all.names = TRUE)) {
      if (state$pending[[id]]$context$expires_at <= now) {
        connection_router_cancel(manager, id)
      }
    }
  }
  launch_queue <- new.env(parent = emptyenv())
  resume_launch <- function(id) {
    verified <- guard(touch = TRUE)
    if (!is_valid_string(id) || !grepl("^[A-Za-z0-9_-]{32}$", id)) {
      err_input("Invalid SMART continuation")
    }
    smart_launch_prune(manager)
    entry <- state$launches[[id]]
    if (is.null(entry)) err_token("SMART launch is unavailable")
    launch <- smart_launch_open(manager, entry, verified, id)
    if (!is.null(launch_queue[[launch$target]])) err_token("A SMART launch is already pending")
    # Atomic process-local take after owner and target checks. Another browser
    # or failed lookup cannot consume a valid launch belonging to its owner.
    rm(list = id, envir = state$launches)
    launch_queue[[launch$target]] <- entry
    launch$target
  }
  prepare <- function(target_id) {
    verified <- guard(touch = TRUE)
    target <- target_for(target_id)
    prune_pending()
    if (length(state$pending) >= 1000L) {
      err_token("Pending connection capacity reached")
    }
    context <- list(
      version = 1L,
      manager = state$id,
      transaction = random_urlsafe(32L),
      target = target_id,
      fingerprint = connection_current_target_fingerprint(target),
      retention = manager$retention,
      owner = if (manager$retention == "shiny") "shiny" else verified$id,
      generation = if (manager$retention == "shiny") {
        "shiny"
      } else {
        verified$generation
      },
      expires_at = min(
        verified$expires_at,
        as.numeric(Sys.time()) + target$client@state_payload_max_age
      )
    )
    launch_entry <- NULL
    if (identical(target$smart$launch, "ehr")) {
      launch_entry <- launch_queue[[target_id]]
      if (is.null(launch_entry)) err_token("Start a fresh EHR launch to reconnect")
      launch <- smart_launch_open(manager, launch_entry, verified)
      rm(list = target_id, envir = launch_queue)
      context$smart <- list(launch_id = launch$id, fhir_base = launch$fhir_base,
        launch_digest = state_policy_value_digest(launch$launch))
      context$expires_at <- min(context$expires_at, launch$expires_at)
    }
    state$pending[[context$transaction]] <- list(
      context = context,
      initiating_owner = owner$id,
      launch_entry = launch_entry
    )
    context
  }
  validate <- function(context) {
    if (
      is.null(verify_owner()) ||
        !is.list(context) ||
        !is_valid_string(context$transaction)
    ) {
      return(FALSE)
    }
    pending <- state$pending[[context$transaction]]
    if (
      is.null(pending) ||
        !identical(
          authorization_context_json(context),
          authorization_context_json(pending$context)
        ) ||
        context$expires_at <= as.numeric(Sys.time())
    ) {
      return(FALSE)
    }
    if (
      manager$retention != "shiny" &&
        (!identical(context$owner, owner$id) ||
          !identical(context$generation, owner$generation))
    ) {
      return(FALSE)
    }
    identical(
      context$fingerprint,
      connection_current_target_fingerprint(target_for(context$target))
    )
  }
  cancel <- function(context) {
    if (
      is.list(context) &&
        is_valid_string(context$transaction) &&
        exists(context$transaction, state$pending, inherits = FALSE)
    ) {
      connection_router_cancel(manager, context$transaction)
    }
    invisible(NULL)
  }
  accept <- function(token, context, authenticated_at) {
    if (!validate(context)) {
      err_token("Managed authorization owner is unavailable")
    }
    target <- target_for(context$target)
    id <- random_urlsafe(32L)
    sealed <- connection_credentials_seal(
      token,
      owner$id,
      id,
      target,
      manager$keys$credentials,
      authenticated_at
    )
    if (!validate(context)) {
      err_token("Managed authorization owner is unavailable")
    }
    expiry <- as.numeric(Sys.time()) + manager$retention_seconds
    if (manager$retention != "account") {
      expiry <- min(expiry, owner$expires_at)
    }
    # The store mutation does not yield. Cancel the ticket before attempting the
    # commit so a failed/uncertain backend result cannot be blindly imported again.
    cancel(context)
    record <- store$create(
      owner$id,
      id,
      context$transaction,
      context$target,
      context$fingerprint,
      sealed,
      expiry
    )
    if (is.null(record)) {
      err_token("Connection credentials could not be committed")
    }
    signal()
    invisible(TRUE)
  }
  decode <- function(record) {
    target <- target_for(record$target)
    result <- list(
      target = target,
      token = NULL,
      status = record$status,
      stored = record
    )
    if (!identical(record$status, "active")) {
      return(result)
    }
    value <- tryCatch(
      connection_credentials_open(
        record$sealed,
        owner$id,
        record$id,
        target,
        manager$keys$credentials
      ),
      error = function(...) NULL
    )
    if (is.null(value)) {
      result$status <- "unavailable"
    } else {
      result$token <- value$token
      result$authenticated_at <- value$authenticated_at
      result$refresh_scope_narrowed <- value$refresh_scope_narrowed
    }
    result
  }
  read <- function(id, touch = FALSE) {
    guard(touch)
    record <- store$read(owner$id, id)
    if (is.null(record)) {
      err_token("Connection is unavailable")
    }
    decode(record)
  }
  records <- function() {
    guard()
    lapply(store$list(owner$id), function(row) read(row$id))
  }
  discard <- function(target_id, token) {
    connection_manager_revoke(
      manager,
      target_for(target_id),
      token,
      as.numeric(Sys.time()) + 10
    )
    invisible(NULL)
  }
  refresh <- function(id, async = FALSE, touch = TRUE, scopes = NULL) {
    for (key in ls(next_refresh, all.names = TRUE)) {
      if (next_refresh[[key]] <= as.numeric(Sys.time())) {
        rm(list = key, envir = next_refresh)
      }
    }
    record <- read(id, touch)
    if (!identical(record$status, "active") || is.null(record$token)) {
      err_token("Connection cannot be refreshed in its current state")
    }
    if (!is_valid_string(record$token@refresh_token)) {
      err_token("Connection has no refresh credential")
    }
    # Validate before taking the refresh claim or sending any credentials.
    # After explicit narrowing, automatic calls retain the accepted grant.
    if (is.null(scopes) && isTRUE(record$refresh_scope_narrowed)) scopes <- record$token@granted_scopes
    scope_request <- if (!is.null(scopes)) {
      refresh_scope_request(record$target$client, record$token, scopes, record$target$required_scopes)
    } else NULL
    claim <- store$begin_refresh(owner$id, id, record$stored$revision)
    if (is.null(claim)) {
      err_token("Connection refresh is already in progress or unavailable")
    }
    next_refresh[[id]] <- as.numeric(Sys.time()) + 30
    signal()
    fail <- function(error) {
      next_refresh[[id]] <- as.numeric(Sys.time()) + 30
      outcome <- error[["refresh_credential_outcome"]] %||% "possibly_consumed"
      if (!outcome %in% c("not_consumed", "possibly_consumed", "consumed")) {
        outcome <- "possibly_consumed"
      }
      try(
        store$fail_refresh(
          owner$id,
          id,
          claim$operation,
          claim$revision,
          outcome
        ),
        silent = TRUE
      )
      signal()
      err_token("Connection refresh failed; inspect its status before retrying")
    }
    succeed <- function(token) {
      committed <- FALSE
      on.exit(if (!committed) discard(claim$target, token), add = TRUE)
      tryCatch(
        {
          validate_token_acceptance_deadline(token)
          validate_refresh_scope_grant(record$target$client, token@granted_scopes, scope_request)
          if (is.null(verify_owner(require_session = FALSE))) {
            err_token("Connection owner is unavailable")
          }
          sealed <- connection_credentials_seal(
            token,
            owner$id,
            id,
            record$target,
            manager$keys$credentials,
            record$authenticated_at,
            refresh_scope_narrowed = !is.null(scope_request)
          )
          if (is.null(verify_owner(require_session = FALSE))) {
            err_token("Connection owner is unavailable")
          }
          installed <- store$commit_refresh(
            owner$id,
            id,
            claim$operation,
            claim$revision,
            sealed
          )
          if (is.null(installed)) {
            err_token("Connection refresh could not be committed")
          }
          committed <- TRUE
          signal()
          TRUE
        },
        error = function(e) fail(refresh_outcome_error(e, "consumed"))
      )
    }
    result <- tryCatch(
      if (is.null(scope_request)) {
        refresh_token(record$target$client, record$token, async = async)
      } else {
        refresh_token_dispatch(record$target$client, record$token, async = async, scope_request = scope_request)
      },
      error = fail
    )
    if (inherits(result, "promise")) {
      promises::then(result, onFulfilled = succeed, onRejected = fail)
    } else {
      succeed(result)
    }
  }
  cleanup_records <- function(previous, revoke) {
    deadline <- as.numeric(Sys.time()) + 10
    lapply(previous, function(record) {
      remote <- "not_requested"
      if (revoke && !is.null(record)) {
        opened <- tryCatch(
          connection_credentials_open(
            record$sealed,
            owner$id,
            record$id,
            target_for(record$target),
            manager$keys$credentials
          ),
          error = function(...) NULL
        )
        remote <- connection_manager_revoke(
          manager,
          target_for(record$target),
          opened$token,
          deadline
        )
      }
      list(local = "disconnected", remote = remote)
    })
  }
  disconnect <- function(id, revoke = TRUE) {
    connection_manager_flag(revoke, "revoke")
    record <- read(id, touch = TRUE)$stored
    changed <- store$disconnect(owner$id, id, record$revision)
    if (is.null(changed)) {
      err_token("Connection changed before disconnect")
    }
    signal()
    cleanup_records(list(changed$previous), revoke)[[1L]]
  }
  cancel_owner_pending <- function() {
    for (id in ls(state$launches, all.names = TRUE)) {
      if (identical(state$launches[[id]]$owner, owner$id)) {
        rm(list = id, envir = state$launches)
      }
    }
    rm(list = ls(launch_queue, all.names = TRUE), envir = launch_queue)
    for (id in ls(state$pending, all.names = TRUE)) {
      pending <- state$pending[[id]]
      if (identical(pending$initiating_owner, owner$id)) {
        connection_router_cancel(manager, id)
      }
    }
  }
  disconnect_all <- function(revoke = TRUE) {
    connection_manager_flag(revoke, "revoke")
    guard(touch = TRUE)
    cancel_owner_pending()
    previous <- store$disconnect_owner(owner$id)
    signal()
    cleanup_records(previous, revoke)
  }
  logout <- function(revoke = TRUE) {
    connection_manager_flag(revoke, "revoke")
    guard()
    active <<- FALSE
    if (manager$retention != "shiny") {
      state$owners$revoke(owner)
    }
    cancel_owner_pending()
    previous <- store$disconnect_owner(owner$id)
    signal()
    cleanup_records(previous, revoke)
  }
  end <- function() {
    active <<- FALSE
    rm(list = ls(launch_queue, all.names = TRUE), envir = launch_queue)
    if (manager$retention == "shiny") {
      store$disconnect_owner(owner$id)
      signal()
    }
    invisible(NULL)
  }
  hooks <- function(target_id) {
    target_for(target_id)
    list(
      prepare = function() prepare(target_id),
      prepared = if (identical(manager$callback_policy, "shared_routes")) {
        function(prepared, context) {
          if (!validate(context) || !identical(context$target, target_id)) {
            err_token("Managed authorization owner is unavailable")
          }
          connection_router_register(manager, target_id, context, prepared)
        }
      } else NULL,
      parameters = function(context) {
        if (!identical(target_for(target_id)$smart$launch, "ehr")) return(list())
        if (!validate(context)) err_token("SMART launch owner is unavailable")
        pending <- state$pending[[context$transaction]]
        if (is.null(pending$launch_entry)) err_token("Start a fresh EHR launch to reconnect")
        launch <- smart_launch_open(manager, pending$launch_entry, guard(), context$smart$launch_id)
        pending$launch_entry <- NULL
        state$pending[[context$transaction]] <- pending
        list(launch = launch$launch)
      },
      validate = function(context) {
        is.list(context) &&
          identical(context$target, target_id) &&
          validate(context)
      },
      accept = accept,
      cancel = cancel,
      discard = function(token) discard(target_id, token)
    )
  }
  list(
    guard = guard,
    read = read,
    records = records,
    hooks = hooks,
    resume_launch = resume_launch,
    refresh = refresh,
    disconnect = disconnect,
    disconnect_all = disconnect_all,
    logout = logout,
    end = end,
    next_refresh = next_refresh
  )
}

connection_manager_flag <- function(value, name) {
  if (!is.logical(value) || length(value) != 1L || is.na(value)) {
    err_input(paste0(name, " must be TRUE or FALSE"))
  }
}
