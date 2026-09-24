module_authorization_expired <- function(
  values,
  indefinite_session,
  reauth_after_seconds
) {
  started <- values[["auth_started_at"]]
  !indefinite_session &&
    !is.null(reauth_after_seconds) &&
    length(started) == 1L &&
    is.finite(started) &&
    as.numeric(Sys.time()) >= started + reauth_after_seconds
}

module_connection_factory <- function(
  client,
  values,
  session,
  operations,
  epoch,
  refresh,
  async,
  indefinite_session,
  reauth_after_seconds
) {
  root <- connection_session_root(session)
  present <- shiny::reactiveVal(shiny::isolate(!is.null(values[["token"]])))
  shiny::observe(
    {
      present(!is.null(values[["token"]]))
    },
    priority = 100
  )
  reference <- NULL
  reference_epoch <- NULL
  function() {
    epoch()
    present()
    if (
      !isTRUE(operations[["session_active"]]) ||
        isTRUE(root[["isClosed"]]()) ||
        !identical(
          root,
          connection_session_root(shiny::getDefaultReactiveDomain())
        )
    ) {
      connection_access_error("authorization_unavailable")
    }
    if (is.null(shiny::isolate(values[["token"]]))) {
      return(NULL)
    }
    generation <- operations[["epoch"]]
    if (!is.null(reference) && identical(reference_epoch, generation)) {
      return(reference)
    }
    id <- random_urlsafe(32L)
    resolve <- function() {
      epoch()
      if (
        !isTRUE(operations[["session_active"]]) ||
          !identical(operations[["epoch"]], generation) ||
          isTRUE(root[["isClosed"]]()) ||
          !identical(
            root,
            connection_session_root(shiny::getDefaultReactiveDomain())
          )
      ) {
        connection_access_error("authorization_unavailable")
      }
      if (
        module_authorization_expired(
          values,
          indefinite_session,
          reauth_after_seconds
        )
      ) {
        connection_access_error("interaction_required")
      }
      list(
        client = client,
        token = values[["token"]],
        targets = values[["targets"]],
        status = if (isTRUE(values[["refresh_in_progress"]])) {
          "refreshing"
        } else {
          "active"
        }
      )
    }
    new_reference <- OAuthConnection[["new"]](
      id,
      client,
      resolve,
      refresh = function(scopes = NULL, target = NULL) {
        record <- resolve()
        if (!is.null(scopes) && !token_targets_configured(client)) {
          refresh_scope_request(client, record[["token"]], scopes)
        }
        redact <- function(error) {
          if (inherits(error, "shinyOAuth_access_error")) {
            stop(error)
          }
          connection_access_error("refresh_unavailable")
        }
        result <- tryCatch(
          refresh(async = async, scopes = scopes, target = target),
          error = redact
        )
        if (inherits(result, "promise")) {
          promises::catch(result, redact)
        } else {
          result
        }
      },
      acquire = function(async = FALSE, target = NULL, wait_only = FALSE) {
        resolve()
        refresh(
          async = async,
          respect_pacing = TRUE,
          target = target,
          wait_only = wait_only
        )
      }
    )
    reference_epoch <<- generation
    reference <<- new_reference
    new_reference
  }
}

# The proactive observer and connection methods share this owner/commit path.
# HTTP executes once; only the originating Shiny session can install its result.
module_refresh_controller <- function(
  client,
  values,
  operations,
  hooks,
  indefinite_session,
  auto_redirect,
  refresh_lead_seconds,
  reauth_after_seconds = NULL
) {
  pending <- NULL
  pending_target <- NULL
  pending_scopes <- NULL
  narrowed <- FALSE
  narrowed_epoch <- NULL
  refresh <- function(
    async = FALSE,
    scopes = NULL,
    automatic = FALSE,
    respect_pacing = automatic,
    target = NULL,
    wait_only = FALSE
  ) {
    target <- token_target_name(client, target)
    if (
      module_authorization_expired(
        values,
        indefinite_session,
        reauth_after_seconds
      )
    ) {
      connection_access_error("interaction_required")
    }
    generation <- operations[["epoch"]]
    primary <- values[["token"]]
    bundle <- values[["targets"]]
    token <- primary
    if (isTRUE(values[["refresh_in_progress"]])) {
      if (isTRUE(async) && inherits(pending, "promise")) {
        if (
          wait_only ||
            (identical(target, pending_target) &&
              (is.null(scopes) || identical(scopes, pending_scopes)))
        ) {
          return(pending)
        }
        if (!is.null(target)) {
          resume <- function(...) {
            if (!identical(operations[["epoch"]], generation)) {
              connection_access_error("authorization_unavailable")
            }
            refresh(async, scopes, automatic, respect_pacing, target)
          }
          return(promises::then(pending, resume, resume))
        }
      }
      connection_access_error("refresh_pending")
    }
    if (!isTRUE(operations[["session_active"]]) || is.null(token)) {
      connection_access_error("authorization_unavailable")
    }
    if (wait_only) {
      return(promises::promise_resolve(TRUE))
    }
    if (!is.null(operations[["active_login_id"]])) {
      connection_access_error("interaction_required")
    }
    if (!is_valid_string(token@refresh_token)) {
      connection_access_error("interaction_required")
    }
    next_attempt <- if (is.null(target)) {
      values[["refresh_next_attempt_at"]]
    } else {
      operations[["target_next_attempt"]][[target]] %||% 0
    }
    # A server-directed delay applies to the shared refresh credential, including
    # sibling targets and explicit refreshes. Cached access tokens remain usable.
    if (
      as.numeric(Sys.time()) < (operations[["refresh_retry_after_at"]] %||% 0)
    ) {
      connection_access_error("refresh_unavailable")
    }
    if (
      respect_pacing &&
        as.numeric(Sys.time()) < next_attempt
    ) {
      return(invisible(FALSE))
    }
    if (!identical(narrowed_epoch, operations[["epoch"]])) {
      narrowed <<- isTRUE(operations[["refresh_scope_narrowed"]])
    }
    explicit_scopes <- scopes
    if (is.null(target) && is.null(scopes) && narrowed) {
      scopes <- token@granted_scopes
    }
    target_request <- if (!is.null(target)) {
      token_target_refresh_request(client, target, bundle[["limits"]], scopes)
    } else {
      NULL
    }
    if (!is.null(target_request)) {
      token <- token_target_refresh_source(
        list(client = client, token = primary, targets = bundle),
        target_request
      )
    }
    scope_request <- if (is.null(target) && !is.null(scopes)) {
      refresh_scope_request(client, token, scopes)
    } else {
      NULL
    }
    pending <<- NULL
    pending_target <<- target
    pending_scopes <<- scopes
    operation <- hooks[["begin"]]("refresh", source_token = primary)
    if (is.null(target)) {
      operations[["last_authorized_scopes"]] <- authorization_retained_scopes(
        client,
        token,
        operations[["last_authorized_scopes"]] %||% token@granted_scopes
      )
    }
    retained_scopes <- explicit_scopes %||%
      operations[["last_authorized_scopes"]]
    values[["refresh_last_attempt_at"]] <- as.numeric(Sys.time())
    captured <- if (async) {
      capture_shiny_session_context(is_async = TRUE)
    } else {
      NULL
    }
    fail <- function(error) {
      if (!isTRUE(hooks[["can_apply"]](operation, "refresh"))) {
        hooks[["finish"]](operation, "refresh")
        connection_access_error("authorization_unavailable")
      }
      values[["refresh_failure_count"]] <- values[["refresh_failure_count"]] +
        1L
      now <- as.numeric(Sys.time())
      retry_after <- refresh_condition_retry_after(error)
      if (is.finite(retry_after)) {
        operations[["refresh_retry_after_at"]] <- max(
          operations[["refresh_retry_after_at"]] %||% 0,
          now + retry_after
        )
      }
      values[["refresh_next_attempt_at"]] <- now +
        proactive_refresh_failure_delay(
          values[["refresh_failure_count"]],
          retry_after
        )
      if (!refresh_credential_retryable(error)) {
        retained <- values[["token"]]
        retained@refresh_token <- NA_character_
        operations[["retired_refresh_snapshot"]] <- retained
        values[["token"]] <- retained
      }
      keep_targets <- !is.null(target) && refresh_credential_retryable(error)
      if (!indefinite_session && !keep_targets) {
        values[["token"]] <- NULL
        values[["targets"]] <- NULL
      }
      if (!is.null(target)) {
        operations[["target_next_attempt"]][[target]] <- values[[
          "refresh_next_attempt_at"
        ]]
      }
      if (!keep_targets) {
        values[["token_stale"]] <- indefinite_session
        phase <- if (async) "async_token_refresh" else "sync_token_refresh"
        hooks[["set_error"]]("token_refresh_error", error, phase = phase)
      }
      hooks[["finish"]](operation, "refresh")
      try(
        audit_event(
          if (indefinite_session || keep_targets) {
            "refresh_failed_but_kept_session"
          } else {
            "session_cleared"
          },
          context = list(
            provider = client@provider@name,
            issuer = client@provider@issuer,
            client_id_digest = string_digest(client@client_id),
            reason = if (async) {
              "refresh_failed_async"
            } else {
              "refresh_failed_sync"
            },
            kept_token = indefinite_session || keep_targets,
            error_class = paste(class(error), collapse = ", ")
          ),
          shiny_session = captured
        ),
        silent = TRUE
      )
      if (
        automatic &&
          !keep_targets &&
          !indefinite_session &&
          auto_redirect &&
          !isTRUE(values[["reauth_triggered"]])
      ) {
        values[["reauth_triggered"]] <- TRUE
        try(values[["request_login"]]())
      }
      stop(error)
    }
    succeed <- function(raw) {
      fresh <- tryCatch(replay_async_conditions(raw), error = fail)
      expired <- module_authorization_expired(
        values,
        indefinite_session,
        reauth_after_seconds
      )
      if (!isTRUE(hooks[["can_apply"]](operation, "refresh")) || expired) {
        hooks[["finish"]](operation, "refresh")
        hooks[["discard"]](
          fresh,
          shiny_session = captured,
          operation_epoch = operation[["epoch"]]
        )
        connection_access_error(
          if (expired) "interaction_required" else "authorization_unavailable"
        )
      }
      tryCatch(
        {
          validate_refresh_delivery(fresh, token)
          validate_refresh_scope_grant(
            client,
            fresh@granted_scopes,
            scope_request
          )
          validate_token_target_grant(
            client,
            fresh@granted_scopes,
            target_request
          )
        },
        error = fail
      )
      if (!is.null(target_request)) {
        committed <- tryCatch(
          token_target_commit(client, primary, bundle, fresh, target_request),
          error = fail
        )
        values[["targets"]] <- committed[["targets"]]
        values[["token"]] <- committed[["token"]]
        operations[["target_limits"]] <- committed[["targets"]][["limits"]]
        operations[[
          "last_authorized_scopes"
        ]] <- token_target_authorization_scopes(
          client,
          operations[["target_limits"]]
        )
      } else {
        values[["token"]] <- fresh
        operations[["last_authorized_scopes"]] <- authorization_retained_scopes(
          client,
          fresh,
          retained_scopes
        )
      }
      values[["error"]] <- NULL
      values[["error_description"]] <- NULL
      values[["error_uri"]] <- NULL
      # A successful secondary acquisition does not renew the primary token
      # exposed through the module's compatibility interface.
      primary_expiry <- values[["token"]]@expires_at
      values[["token_stale"]] <- !is.null(target) &&
        is.finite(primary_expiry) &&
        primary_expiry <= as.numeric(Sys.time())
      values[["reauth_triggered"]] <- FALSE
      values[["refresh_failure_count"]] <- 0L
      now <- as.numeric(Sys.time())
      values[["refresh_last_success_at"]] <- now
      values[["refresh_success_generation"]] <- values[[
        "refresh_success_generation"
      ]] +
        1L
      values[["refresh_next_attempt_at"]] <- now +
        proactive_refresh_success_delay(fresh, now, refresh_lead_seconds)
      if (!is.null(target)) {
        # Use the same lifetime-aware pacing as the proactive observer so a
        # short-lived target can be renewed before its replacement expires.
        operations[["target_next_attempt"]][[target]] <- values[[
          "refresh_next_attempt_at"
        ]]
      }
      narrowed <<- !is.null(scope_request)
      narrowed_epoch <<- operation[["epoch"]]
      hooks[["finish"]](operation, "refresh")
      TRUE
    }
    result <- tryCatch(
      {
        if (!is.null(target_request)) {
          refresh_token_dispatch(
            client,
            token,
            async = async,
            introspect = isTRUE(client@introspect),
            shiny_session = captured,
            target_request = target_request
          )
        } else if (is.null(scope_request)) {
          refresh_token(
            client,
            token,
            async = async,
            introspect = isTRUE(client@introspect),
            shiny_session = captured
          )
        } else {
          refresh_token_dispatch(
            client,
            token,
            async = async,
            introspect = isTRUE(client@introspect),
            shiny_session = captured,
            scope_request = scope_request
          )
        }
      },
      error = fail
    )
    if (async) {
      pending <<- promises::then(result, succeed, fail)
      return(pending)
    }
    succeed(result)
  }
  refresh
}

module_proactive_refresh <- function(
  values,
  session,
  refresh,
  operations,
  async,
  lead,
  interval
) {
  shiny::observe({
    token <- values[["token"]]
    wake <- interval
    if (
      !is.null(token) &&
        is_valid_string(token@refresh_token) &&
        is.finite(token@expires_at)
    ) {
      now <- as.numeric(Sys.time())
      remaining <- token@expires_at - now - lead
      if (remaining > 0) {
        wake <- shiny_timer_delay_ms(
          remaining,
          buffer_seconds = stats::runif(1, 0, 1)
        )
      } else {
        next_attempt <- values[["refresh_next_attempt_at"]]
        wake <- if (next_attempt > now) {
          shiny_timer_delay_ms(next_attempt - now)
        } else {
          250L
        }
        if (
          !isTRUE(values[["refresh_in_progress"]]) &&
            is.null(operations[["active_login_id"]]) &&
            next_attempt <= now
        ) {
          result <- tryCatch(
            refresh(async = async, automatic = TRUE),
            error = function(...) NULL
          )
          if (inherits(result, "promise")) {
            promises::catch(result, function(...) NULL)
          }
        }
      }
    }
    shiny::invalidateLater(wake, session)
  })
}
