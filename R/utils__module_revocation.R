# One bounded cleanup batch per authorization. Prioritize the shared refresh
# credential; each HTTP attempt consumes the same overall wall-clock budget.
module_revoke_targets <- function(
  client,
  token,
  secondary,
  deadline = as.numeric(Sys.time()) + 10,
  async = FALSE,
  shiny_session = NULL
) {
  if (isTRUE(async)) {
    pending <- dispatch_token_async(
      function_name = "module_revoke_targets",
      call_args = list(
        client = client,
        token = token,
        secondary = secondary,
        deadline = deadline
      ),
      client = client,
      shiny_session = shiny_session,
      trace_id = resolve_trace_id(),
      span_name = "shinyOAuth.targets.revoke",
      phase = "targets.revoke",
      worker_span_name = "shinyOAuth.targets.revoke.worker",
      worker_phase = "targets.revoke.worker"
    )
    # Logout has already removed local access. Worker failure cannot undo that
    # decision and must not leave an unhandled fire-and-forget rejection.
    return(invisible(promises::catch(pending, function(...) NULL)))
  }
  entries <- c(list(token, token), unname(secondary))
  kinds <- c("refresh", rep("access", length(entries) - 1L))
  attempted <- list(refresh = character(), access = character())
  for (i in seq_along(entries)) {
    remaining <- deadline - as.numeric(Sys.time())
    # Smaller values trigger the HTTP helper's invalid-timeout fallback.
    if (remaining < 0.001) {
      break
    }
    if (is.null(entries[[i]])) {
      next
    }
    kind <- kinds[[i]]
    value <- if (kind == "refresh") {
      entries[[i]]@refresh_token
    } else {
      entries[[i]]@access_token
    }
    if (value %in% attempted[[kind]]) {
      next
    }
    # A failed attempt also consumes this credential's turn in the batch.
    attempted[[kind]] <- c(attempted[[kind]], value)
    settings <- capture_async_options()
    settings[["shinyOAuth.timeout"]] <- min(2, remaining)
    settings[["shinyOAuth.retry_max_tries"]] <- 1L
    tryCatch(
      with_async_options(settings, {
        revoke_token(
          client,
          entries[[i]],
          token_kind = kinds[[i]],
          async = FALSE,
          shiny_session = shiny_session
        )
      }),
      error = function(...) NULL
    )
  }
  invisible(NULL)
}
