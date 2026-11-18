interop_resource_limits <- function() {
  c(
    "single_resource_basic_auth_query",
    "oidc_without_userinfo",
    "fixture_resource_server_public_model_api",
    "resource_and_introspection_in_main_process",
    "no_sender_constraint_or_multi_resource_selection",
    "no_navigation_retention"
  )
}

interop_resource_true <- function(value, fields) {
  all(vapply(fields, function(field) isTRUE(value[[field]]), logical(1)))
}

interop_resource_app_matches <- function(row, context) {
  positive <- identical(row[["outcome"]], "authenticated")
  initial <- row[["initial"]]
  before <- row[["before_refresh"]]
  after <- row[["app"]]
  for (app in list(initial, before, after)) {
    if (
      !identical(app[["run_id"]], row[["case_id"]]) ||
        !identical(app[["package_version"]], context[["package_version"]]) ||
        !isTRUE(app[["ready"]]) ||
        !identical(app[["userinfo_present"]], FALSE) ||
        !identical(app[["operations"]][["audit_userinfo"]], 0L)
    ) {
      return(FALSE)
    }
  }
  if (
    !identical(initial[["authenticated"]], FALSE) ||
      !identical(initial[["has_token"]], FALSE) ||
      !identical(
        before[["session_number"]],
        initial[["session_number"]] + 1L
      ) ||
      !identical(after[["session_number"]], before[["session_number"]])
  ) {
    return(FALSE)
  }
  for (name in c("app_instance", "cache_instance")) {
    if (
      !openid_string(initial[[name]]) ||
        !identical(initial[[name]], before[[name]]) ||
        !identical(initial[[name]], after[[name]])
    ) {
      return(FALSE)
    }
  }
  if (!positive) {
    return(
      identical(before, after) &&
        identical(after[["error_code"]], "invalid_target") &&
        all(vapply(
          c(
            "authenticated",
            "has_token",
            "id_token_present",
            "id_token_validated",
            "has_refresh_token"
          ),
          function(field) identical(after[[field]], FALSE),
          logical(1)
        )) &&
        all(vapply(
          c(
            "audit_token_exchange",
            "audit_login_success",
            "audit_token_refresh"
          ),
          function(field) identical(after[["operations"]][[field]], 0L),
          logical(1)
        ))
    )
  }
  for (app in list(before, after)) {
    if (
      !interop_resource_true(
        app,
        c(
          "authenticated",
          "has_token",
          "id_token_present",
          "id_token_validated",
          "has_refresh_token"
        )
      ) ||
        !is.null(app[["error_code"]]) ||
        length(app[["error_classes"]])
    ) {
      return(FALSE)
    }
  }
  for (field in c(
    "audit_token_exchange",
    "audit_login_success",
    "audit_callback_validation_success"
  )) {
    if (
      !identical(initial[["operations"]][[field]], 0L) ||
        !identical(before[["operations"]][[field]], 1L) ||
        !identical(after[["operations"]][[field]], 1L)
    ) {
      return(FALSE)
    }
  }
  if (
    !identical(before[["operations"]][["audit_token_refresh"]], 0L) ||
      !identical(after[["operations"]][["audit_token_refresh"]], 1L) ||
      !is.null(before[["refresh"]])
  ) {
    return(FALSE)
  }
  refresh <- after[["refresh"]]
  interop_resource_true(
    refresh,
    c(
      "done",
      "connection_same",
      "connection_present",
      "old_connection_usable",
      "access_changed",
      "original_id_token_retained",
      "issuer_unchanged",
      "subject_unchanged",
      "exported_current"
    )
  ) &&
    identical(refresh[["attempts"]], 1L) &&
    identical(refresh[["result"]], "succeeded") &&
    identical(refresh[["export_blocked"]], FALSE) &&
    identical(refresh[["refresh_error_is_access_error"]], FALSE)
}

interop_resource_provider_matches <- function(row, lock) {
  provider <- row[["provider"]]
  if (
    !identical(provider[["run_id"]], row[["case_id"]]) ||
      !identical(provider[["provider_version"]], lock[["provider_version"]]) ||
      !identical(provider[["node_version"]], lock[["node_version"]]) ||
      !identical(provider[["client_auth_type"]], "client_secret_basic") ||
      !identical(
        provider[["resource_indicators"]],
        list(target = row[["target"]])
      ) ||
      !identical(
        provider[["features"]],
        list(
          dev_interactions = FALSE,
          userinfo = FALSE,
          pkce_required = TRUE,
          refresh_rotation = TRUE
        )
      )
  ) {
    return(FALSE)
  }
  events <- provider[["events"]]
  positive <- identical(row[["outcome"]], "authenticated")
  types <- if (positive) {
    c(
      "interaction",
      "interaction",
      "authorization.accepted",
      "authorization.success",
      "grant.success",
      "resource",
      "introspection",
      "grant.success",
      "resource",
      "introspection",
      "resource",
      "resource",
      "resource"
    )
  } else {
    "authorization.error"
  }
  if (
    !identical(
      vapply(events, function(event) event[["type"]], character(1)),
      types
    ) ||
      !identical(
        vapply(events, function(event) event[["sequence"]], integer(1)),
        seq_along(types)
      )
  ) {
    return(FALSE)
  }
  if (!positive) {
    return(
      identical(events[[1L]][["error"]], "invalid_target") &&
        isTRUE(events[[1L]][["client_matches"]]) &&
        isTRUE(events[[1L]][["requested_resource_matches"]]) &&
        identical(events[[1L]][["resource_known"]], FALSE)
    )
  }
  if (
    !identical(events[[1L]][["prompt"]], "login") ||
      !identical(events[[2L]][["prompt"]], "consent") ||
      !interop_resource_true(
        events[[3L]],
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present",
          "requested_resource_matches",
          "resource_known"
        )
      ) ||
      !identical(events[[3L]][["response_mode"]], "query") ||
      !isTRUE(events[[4L]][["code_issued"]])
  ) {
    return(FALSE)
  }
  for (i in c(5L, 8L)) {
    event <- events[[i]]
    if (
      !identical(
        event[["grant_type"]],
        if (i == 5L) "authorization_code" else "refresh_token"
      ) ||
        !interop_resource_true(
          event,
          c(
            "client_matches",
            "authentication_valid",
            "access_token_present",
            "refresh_token_present",
            "requested_resource_matches",
            "resource_known",
            "audience_matches",
            "scope_matches"
          )
        ) ||
        !identical(event[["id_token_present"]], i == 5L)
    ) {
      return(FALSE)
    }
  }
  if (
    !interop_resource_true(events[[5L]], c("pkce_verified", "code_matches")) ||
      !is.null(events[[5L]][["refresh_token_rotated"]]) ||
      !isTRUE(events[[8L]][["refresh_token_rotated"]]) ||
      !is.null(events[[8L]][["pkce_verified"]]) ||
      !is.null(events[[8L]][["code_matches"]])
  ) {
    return(FALSE)
  }
  for (i in c(6L, 9L)) {
    event <- events[[i]]
    if (
      !identical(event[["status"]], 200L) ||
        !identical(event[["target"]], row[["target"]]) ||
        !is.null(event[["probe"]]) ||
        !interop_resource_true(
          event,
          c(
            "token_present",
            "token_valid",
            "audience_matches",
            "scope_matches",
            "current_token_used"
          )
        )
    ) {
      return(FALSE)
    }
  }
  for (i in c(7L, 10L)) {
    if (
      !identical(events[[i]][["status"]], 200L) ||
        !interop_resource_true(
          events[[i]],
          c(
            "active",
            "client_matches",
            "audience_matches",
            "scope_matches",
            "current_token_used"
          )
        )
    ) {
      return(FALSE)
    }
  }
  for (i in 11:13) {
    event <- events[[i]]
    wrong <- i == 11L
    if (
      !identical(event[["status"]], 401L) ||
        !identical(
          event[["probe"]],
          c("wrong_audience", "missing", "invalid")[[i - 10L]]
        ) ||
        !identical(
          event[["target"]],
          if (wrong) {
            if (row[["target"]] == "a") "b" else "a"
          } else {
            row[["target"]]
          }
        ) ||
        !identical(event[["token_present"]], i != 12L) ||
        !identical(event[["token_valid"]], wrong) ||
        !identical(event[["audience_matches"]], FALSE) ||
        !identical(event[["scope_matches"]], wrong) ||
        !identical(event[["current_token_used"]], wrong)
    ) {
      return(FALSE)
    }
  }
  TRUE
}

interop_resource_row_matches <- function(row, context, selection, lock) {
  for (name in c("id", "target", "outcome")) {
    if (!identical(row[[name]], selection[[name]])) return(FALSE)
  }
  request <- row[["authorization_request"]]
  if (
    !identical(request[["method"]], "GET") ||
      !interop_resource_true(
        request,
        c("resource_matches", "direct", "pkce_s256")
      )
  ) {
    return(FALSE)
  }
  if (
    !identical(row[["run_id"]], context[["run_id"]]) ||
      !identical(row[["checkout_revision"]], context[["checkout_revision"]]) ||
      !interop_resource_true(
        row,
        c("cleanup_verified", "worker_cleanup_verified", "callback_cleaned")
      ) ||
      !openid_string(row[["browser_version"]]) ||
      !grepl("^https://localhost:[0-9]+$", row[["provider_origin"]]) ||
      !grepl("^https://localhost:[0-9]+$", row[["app_origin"]]) ||
      identical(row[["provider_origin"]], row[["app_origin"]]) ||
      !identical(
        row[["resource_uri"]],
        paste0(row[["provider_origin"]], "/resource/", row[["target"]])
      ) ||
      !interop_resource_provider_matches(row, lock) ||
      !interop_resource_app_matches(row, context)
  ) {
    return(FALSE)
  }
  endpoints <- c(
    issuer = "",
    authorization_endpoint = "/authorize",
    token_endpoint = "/token",
    jwks_uri = "/jwks",
    introspection_endpoint = "/token/introspection"
  )
  for (name in names(endpoints)) {
    if (
      !identical(
        row[["discovery"]][[name]],
        paste0(row[["provider_origin"]], endpoints[[name]])
      )
    ) {
      return(FALSE)
    }
  }
  if (!is.null(row[["discovery"]][["userinfo_endpoint"]])) {
    return(FALSE)
  }
  positive <- identical(selection[["outcome"]], "authenticated")
  # The transport checker already has the exact no-UserInfo worker accounting
  # used by OAuth-only flows; identity validation is required separately above.
  expected <- list(
    outcome = if (positive) "authorized" else "callback_rejected"
  )
  if (!openid_transport_matches(row, expected, context)) {
    return(FALSE)
  }
  if (!positive) {
    return(is.null(row[["reads"]]) && is.null(row[["probes"]]))
  }
  if (length(row[["reads"]]) != 2L) {
    return(FALSE)
  }
  for (read in row[["reads"]]) {
    if (
      !identical(read[["status"]], 200L) ||
        !identical(read[["api"]], "connection") ||
        !interop_resource_true(
          read,
          c(
            "done",
            "subject_matches",
            "audience_matches",
            "introspection_active",
            "introspection_audience_matches",
            "introspection_scope_matches",
            "connection_usable"
          )
        )
    ) {
      return(FALSE)
    }
  }
  probe <- row[["probes"]]
  if (
    !interop_resource_true(probe, c("done", "escape_blocked")) ||
      !all(vapply(
        c("wrong_audience", "missing", "invalid"),
        function(name) identical(probe[[name]], 401L),
        logical(1)
      ))
  ) {
    return(FALSE)
  }
  all(vapply(
    c(row[["reads"]], list(probe)),
    function(value) {
      !isTRUE(value[["failed"]]) &&
        identical(value[["transport"]], "main_process") &&
        identical(value[["pid"]], row[["app"]][["transport"]][["app_pid"]])
    },
    logical(1)
  ))
}

interop_resource_matches <- function(report, context, lock, cases) {
  tryCatch(
    {
      if (
        !identical(report[["schema_version"]], 1L) ||
          !identical(report[["scope"]], "oidc_provider_resource_indicators") ||
          !identical(report[["coverage_complete"]], FALSE) ||
          !identical(
            unlist(report[["coverage_limitations"]]),
            interop_resource_limits()
          ) ||
          !interop_resource_true(
            report,
            c("cleanup_verified", "driver_failure_control_passed")
          ) ||
          !interop_sanitized(report) ||
          !identical(report[["provider_lock"]], lock) ||
          !identical(report[["image_id"]], context[["image_id"]]) ||
          !grepl("^sha256:[a-f0-9]{64}$", report[["image_id"]]) ||
          !identical(report[["source_hashes"]], context[["source_hashes"]])
      ) {
        return(FALSE)
      }
      for (name in c(
        "run_id",
        "checkout_revision",
        "transport",
        "package_version"
      )) {
        if (
          !openid_string(context[[name]]) ||
            !identical(report[[name]], context[[name]])
        ) {
          return(FALSE)
        }
      }
      if (!context[["transport"]] %in% c("sync", "mirai")) {
        return(FALSE)
      }
      rows <- report[["results"]]
      if (!length(cases) || !length(rows)) {
        return(FALSE)
      }
      ids <- vapply(rows, function(row) row[["id"]], character(1))
      instances <- vapply(rows, function(row) row[["case_id"]], character(1))
      expected <- vapply(cases, function(row) row[["id"]], character(1))
      if (
        length(rows) != length(cases) ||
          anyDuplicated(ids) ||
          anyDuplicated(instances) ||
          !all(grepl("^[a-f0-9]{32}$", instances)) ||
          !setequal(ids, expected)
      ) {
        return(FALSE)
      }
      all(vapply(
        rows,
        function(row) {
          interop_resource_row_matches(
            row,
            context,
            cases[[match(row[["id"]], expected)]],
            lock
          )
        },
        logical(1)
      ))
    },
    error = function(...) FALSE
  )
}

interop_resource_mutations <- function(report) {
  paths <- list(
    list("coverage_limitations"),
    list("cleanup_verified"),
    list("driver_failure_control_passed"),
    list("image_id")
  )
  for (i in seq_along(report[["results"]])) {
    row <- report[["results"]][[i]]
    base <- list("results", i)
    paths <- c(paths, list(base))
    for (field in c(
      "provider",
      "discovery",
      "worker_cleanup_verified",
      "callback_cleaned",
      "resource_uri",
      "authorization_request"
    )) {
      paths <- c(paths, list(c(base, field)))
    }
    if (row[["outcome"]] == "authenticated") {
      for (path in list(
        list("app", "id_token_validated"),
        list("app", "refresh"),
        list("reads", 1L),
        list("reads", 2L),
        list("probes", "escape_blocked"),
        list("probes", "wrong_audience")
      )) {
        paths <- c(paths, list(c(base, path)))
      }
    } else {
      paths <- c(paths, list(c(base, list("app", "error_code"))))
    }
    for (j in seq_along(row[["provider"]][["events"]])) {
      event <- row[["provider"]][["events"]][[j]]
      path <- c(base, list("provider", "events", j))
      paths <- c(paths, list(path))
      # Optional null fields have exact per-grant meanings. Required flags,
      # statuses, targets and rejection categories must survive serialization.
      for (field in setdiff(
        names(event),
        c("sequence", "type", "pkce_missing")
      )) {
        if (!is.null(event[[field]])) paths <- c(paths, list(c(path, field)))
      }
    }
  }
  setNames(
    paths,
    vapply(
      paths,
      function(path) paste(unlist(path), collapse = "_"),
      character(1)
    )
  )
}

interop_resource_rejections <- function(report, context, lock, cases) {
  if (!interop_resource_matches(report, context, lock, cases)) {
    stop("Actual resource report failed before rejection controls")
  }
  controls <- lapply(interop_resource_mutations(report), function(path) {
    !interop_resource_matches(
      replace_nested(report, path, NULL),
      context,
      lock,
      cases
    )
  })
  failed <- names(controls)[!vapply(controls, isTRUE, logical(1))]
  if (length(failed)) {
    stop(
      "Resource rejection controls unexpectedly passed: ",
      paste(failed, collapse = ", ")
    )
  }
  controls
}

interop_resource_check_report <- function(report, context, lock, cases) {
  controls <- report[["rejection_controls"]]
  interop_resource_matches(report, context, lock, cases) &&
    is.list(controls) &&
    !anyDuplicated(names(controls)) &&
    setequal(names(controls), names(interop_resource_mutations(report))) &&
    all(vapply(controls, isTRUE, logical(1)))
}
