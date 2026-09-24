connection_access_error <- function(reason) {
  message <- switch(
    reason,
    authorization_unavailable = "The authorization is no longer available; obtain a current connection.",
    unknown_target = "The token target is not declared on this client.",
    unsupported_target = "This client does not support token target selection.",
    selection_required = "Several authorizations are available; select a connection ID.",
    insufficient_scope = "The authorization does not cover this operation.",
    refresh_pending = "Credential refresh is in progress; await it asynchronously or retry later.",
    refresh_unavailable = "Credentials cannot be refreshed now; retry later or authorize again.",
    interaction_required = "A new authorization is required.",
    lifetime_unavailable = "The access token does not meet the requested remaining lifetime.",
    unsupported_token_binding = "Exporting this token requires its sender-bound transport; use request() instead.",
    unsupported_scope_narrowing = "Microsoft tokens include previously consented API permissions and cannot be narrowed by a refresh scope request.",
    "Access-token acquisition failed."
  )
  err_abort(
    message,
    class = c("shinyOAuth_access_error", "shinyOAuth_token_error"),
    context = list(reason = reason)
  )
}

connection_scope_arguments <- function(scopes) {
  validate_scopes(scopes)
  normalize_scope_tokens(scopes)
}

connection_scope_covered <- function(
  client,
  required,
  granted,
  verified = TRUE
) {
  (!client_uses_smart_scopes(client) || isTRUE(verified)) &&
    identical(
      client_scope_coverage(client, required, granted)[["status"]],
      "covered"
    )
}

# These notifications describe authorization and permission changes, never
# access-token bytes or expiry. A refresh claim temporarily hides stored tokens.
connection_integration_signal <- function(resolve, is_current = NULL) {
  observer <- NULL
  ended <- FALSE
  snapshot <- function(previous = NULL) {
    if (!is.null(is_current) && !isTRUE(is_current())) {
      ended <<- TRUE
      if (!is.null(observer)) {
        observer[["destroy"]]()
      }
      return(NULL)
    }
    record <- tryCatch(resolve(), error = function(...) NULL)
    if (identical(record[["status"]], "refreshing")) {
      return(previous)
    }
    token <- record[["token"]]
    available <- !is.null(token) &&
      (is.null(record[["status"]]) || identical(record[["status"]], "active"))
    if (available && token_targets_configured(record[["client"]])) {
      evidence <- function(target) {
        token <- tokens[[target]]
        if (is.null(token)) {
          NULL
        } else {
          list(
            scopes = sort(token_target_operation_scopes(
              record[["client"]],
              target,
              token@granted_scopes,
              record[["targets"]][["limits"]][[target]]
            )),
            verified = token@granted_scopes_verified
          )
        }
      }
      tokens <- record[["targets"]][["tokens"]]
      tokens[[record[["client"]]@default_token_target]] <- token
      targets <- sort(names(tokens))
      list(targets = stats::setNames(lapply(targets, evidence), targets))
    } else if (available) {
      list(
        scopes = sort(token@granted_scopes),
        verified = token@granted_scopes_verified
      )
    } else {
      NULL
    }
  }
  state <- shiny::reactiveVal(shiny::isolate(snapshot()))
  if (!ended) {
    observer <- shiny::observe(
      {
        state(snapshot(shiny::isolate(state())))
      },
      priority = 100
    )
  }
  state
}

connection_record_has_scopes <- function(record, scopes, previous = NULL) {
  client <- record[["client"]]
  token <- record[["token"]]
  if (identical(record[["status"]], "refreshing")) {
    evidence <- previous
  } else if (
    !is.null(token) &&
      (is.null(record[["status"]]) || identical(record[["status"]], "active"))
  ) {
    evidence <- list(
      scopes = token@granted_scopes,
      verified = token@granted_scopes_verified
    )
  } else {
    return(FALSE)
  }
  !is.null(evidence) &&
    connection_record_configured_scopes(record, scopes) &&
    connection_record_scope_limit_allows(record, scopes) &&
    connection_scope_covered(
      client,
      scopes,
      evidence[["scopes"]],
      evidence[["verified"]]
    )
}

connection_export_token <- function(
  resolve,
  acquire,
  required_scopes,
  min_valid_for,
  force_refresh,
  async,
  export_bearer = TRUE
) {
  required_scopes <- connection_scope_arguments(required_scopes)
  connection_manager_flag(force_refresh, "force_refresh")
  connection_manager_flag(async, "async")
  if (
    !is.numeric(min_valid_for) ||
      length(min_valid_for) != 1L ||
      !is.finite(min_valid_for) ||
      min_valid_for < 0
  ) {
    err_input("min_valid_for must be a finite, non-negative number of seconds")
  }
  if (!is.function(acquire)) {
    err_config(
      "Obtain this connection from the module's connection() method to manage access tokens"
    )
  }
  if (async && !requireNamespace("promises", quietly = TRUE)) {
    err_config("Install promises to acquire access tokens asynchronously")
  }
  read <- function() {
    tryCatch(resolve(), error = function(error) {
      if (inherits(error, "shinyOAuth_access_error")) {
        stop(error)
      }
      connection_access_error("authorization_unavailable")
    })
  }
  check <- function(record) {
    client <- record[["client"]]
    if (!connection_record_configured_scopes(record, required_scopes)) {
      err_input(
        "Operation scopes must be included in the client's requested scopes"
      )
    }
    status <- record[["status"]] %||% "active"
    if (status %in% c("uncertain", "unavailable")) {
      connection_access_error("interaction_required")
    }
    if (!status %in% c("active", "refreshing")) {
      connection_access_error("authorization_unavailable")
    }
    if (identical(status, "refreshing")) {
      return(FALSE)
    }
    if (
      !is.null(record[["target"]]) &&
        !token_target_scopes_allowed(
          client,
          record[["target"]],
          required_scopes,
          record[["target_scopes"]]
        )
    ) {
      connection_access_error("insufficient_scope")
    }
    token <- record[["token"]]
    if (is.null(token) && !is.null(record[["target"]])) {
      return(FALSE)
    }
    if (is.null(token)) {
      connection_access_error("authorization_unavailable")
    }
    if (
      export_bearer &&
        (!identical(tolower(token@token_type), "bearer") ||
          length(token@cnf) ||
          isTRUE(client@mtls_certificate_bound_access_tokens) ||
          isTRUE(client@dpop_require_access_token))
    ) {
      connection_access_error("unsupported_token_binding")
    }
    if (
      !connection_record_has_scopes(
        record,
        union(connection_record_required_scopes(record), required_scopes)
      )
    ) {
      connection_access_error("insufficient_scope")
    }
    !is.na(token@expires_at) &&
      token@expires_at > as.numeric(Sys.time()) + min_valid_for
  }
  deliver <- function(...) {
    record <- read()
    if (!check(record)) {
      if (async && identical(record[["status"]], "refreshing")) {
        # A queued target may have claimed the credential before every consumer
        # of the previous operation ran. Await that claim without acquiring again.
        pending <- tryCatch(
          shiny::isolate(acquire(async = TRUE, wait_only = TRUE)),
          error = failed
        )
        return(promises::then(pending, deliver, deliver))
      }
      connection_access_error("lifetime_unavailable")
    }
    if (export_bearer) record[["token"]]@access_token else record
  }
  failed <- function(error) {
    if (inherits(error, "shinyOAuth_access_error")) {
      stop(error)
    }
    record <- read()
    check(record)
    connection_access_error("refresh_unavailable")
  }
  perform <- function() {
    record <- read()
    fresh <- check(record)
    if (fresh && !force_refresh) {
      return(if (export_bearer) record[["token"]]@access_token else record)
    }
    if (identical(record[["status"]], "refreshing")) {
      if (!async) connection_access_error("refresh_pending")
    } else if (
      !is_valid_string(
        record[["refresh_token"]] %||% record[["token"]]@refresh_token
      )
    ) {
      connection_access_error("interaction_required")
    }
    result <- tryCatch(shiny::isolate(acquire(async = async)), error = failed)
    if (inherits(result, "promise")) {
      return(promises::then(result, deliver, failed))
    }
    if (!isTRUE(result)) {
      connection_access_error("refresh_unavailable")
    }
    deliver()
  }
  if (async) {
    tryCatch(promises::promise_resolve(perform()), error = function(e) {
      promises::promise_reject(e)
    })
  } else {
    perform()
  }
}
