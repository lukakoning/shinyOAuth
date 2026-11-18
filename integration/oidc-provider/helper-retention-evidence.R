interop_retention_limits <- function() {
  c(
    "one_client_basic_auth",
    "query_and_form_post",
    "browser_owner_memory_store_single_process",
    "localhost_origins_only",
    "local_logout_without_remote_revocation",
    "resource_reads_in_main_process"
  )
}

interop_retention_true <- function(value, fields) {
  all(vapply(fields, function(name) isTRUE(value[[name]]), logical(1)))
}

interop_retention_provider_matches <- function(row, lock) {
  value <- row[["provider"]]
  if (
    !identical(value[["run_id"]], row[["case_id"]]) ||
      !identical(value[["provider_version"]], lock[["provider_version"]]) ||
      !identical(value[["node_version"]], lock[["node_version"]]) ||
      !identical(value[["client_auth_type"]], "client_secret_basic") ||
      !identical(
        value[["features"]],
        list(
          dev_interactions = FALSE,
          userinfo = TRUE,
          pkce_required = TRUE,
          refresh_rotation = TRUE
        )
      )
  ) {
    return(FALSE)
  }
  events <- value[["events"]]
  types <- c(
    "authorization.error",
    "interaction",
    "interaction",
    "authorization.accepted",
    "authorization.success",
    "grant.success",
    "userinfo",
    "userinfo",
    "userinfo",
    "grant.success",
    "userinfo",
    "userinfo",
    "userinfo"
  )
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
  if (
    !identical(events[[1L]][["error"]], "invalid_request") ||
      !interop_retention_true(
        events[[1L]],
        c("client_matches", "pkce_missing")
      ) ||
      !identical(events[[2L]][["prompt"]], "login") ||
      !identical(events[[3L]][["prompt"]], "consent") ||
      !identical(events[[4L]][["response_mode"]], row[["response_mode"]]) ||
      !interop_retention_true(
        events[[4L]],
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ) ||
      !isTRUE(events[[5L]][["code_issued"]])
  ) {
    return(FALSE)
  }
  for (i in c(6L, 10L)) {
    event <- events[[i]]
    if (
      !identical(
        event[["grant_type"]],
        if (i == 6L) "authorization_code" else "refresh_token"
      ) ||
        !interop_retention_true(
          event,
          c(
            "client_matches",
            "authentication_valid",
            "access_token_present",
            "id_token_present",
            "refresh_token_present"
          )
        )
    ) {
      return(FALSE)
    }
  }
  if (
    !interop_retention_true(events[[6L]], c("pkce_verified", "code_matches")) ||
      !is.null(events[[6L]][["refresh_token_rotated"]]) ||
      !isTRUE(events[[10L]][["refresh_token_rotated"]]) ||
      !is.null(events[[10L]][["pkce_verified"]]) ||
      !is.null(events[[10L]][["code_matches"]])
  ) {
    return(FALSE)
  }
  all(vapply(
    events[c(7L, 8L, 9L, 11L, 12L, 13L)],
    function(event) {
      identical(event[["status"]], 200L) &&
        interop_retention_true(
          event,
          c("issued_token_used", "current_token_used", "subject_present")
        )
    },
    logical(1)
  ))
}

interop_retention_row_matches <- function(row, context, selection, lock) {
  for (name in c("id", "response_mode")) {
    if (!identical(row[[name]], selection[[name]])) return(FALSE)
  }
  if (
    !identical(row[["run_id"]], context[["run_id"]]) ||
      !identical(row[["checkout_revision"]], context[["checkout_revision"]]) ||
      !interop_retention_true(
        row,
        c("cleanup_verified", "worker_cleanup_verified", "callback_cleaned")
      ) ||
      !openid_string(row[["browser_version"]]) ||
      !grepl("^https://localhost:[0-9]+$", row[["provider_origin"]]) ||
      !grepl("^https://localhost:[0-9]+$", row[["app_origin"]]) ||
      identical(row[["provider_origin"]], row[["app_origin"]]) ||
      !interop_retention_provider_matches(row, lock)
  ) {
    return(FALSE)
  }
  paths <- c(
    issuer = "",
    authorization_endpoint = "/authorize",
    token_endpoint = "/token",
    userinfo_endpoint = "/userinfo",
    jwks_uri = "/jwks"
  )
  for (name in names(paths)) {
    if (
      !identical(
        row[["discovery"]][[name]],
        paste0(row[["provider_origin"]], paths[[name]])
      )
    ) {
      return(FALSE)
    }
  }
  snapshots <- row[["snapshots"]]
  expected_names <- c(
    "connected",
    "initial_read",
    "page_two",
    "restored_read",
    "refreshed",
    "refreshed_read",
    "page_one",
    "returned_read",
    "foreign",
    "foreign_probe",
    "logged_out",
    "new_owner",
    "old_id_probe"
  )
  if (
    !identical(names(snapshots), expected_names) ||
      !identical(row[["app"]], snapshots[["returned_read"]])
  ) {
    return(FALSE)
  }
  initial <- row[["initial"]]
  for (snapshot in c(list(initial), snapshots)) {
    if (
      !identical(snapshot[["run_id"]], row[["case_id"]]) ||
        !identical(
          snapshot[["package_version"]],
          context[["package_version"]]
        ) ||
        !isTRUE(snapshot[["ready"]]) ||
        !identical(snapshot[["app_instance"]], initial[["app_instance"]]) ||
        !identical(snapshot[["app_pid"]], initial[["app_pid"]]) ||
        !openid_count(snapshot[["session_number"]], 1L) ||
        !openid_count(snapshot[["result_revision"]]) ||
        !isTRUE(snapshot[["transport"]][["events_verified"]])
    ) {
      return(FALSE)
    }
  }
  if (
    !grepl("^[a-f0-9]{32}$", initial[["app_instance"]]) ||
      !openid_count(initial[["app_pid"]], 1L)
  ) {
    return(FALSE)
  }
  connected <- snapshots[["connected"]]
  for (name in expected_names[1:8]) {
    snapshot <- snapshots[[name]]
    if (
      !identical(snapshot[["connection_count"]], 1L) ||
        !isTRUE(snapshot[["identity_verified"]]) ||
        !openid_string(snapshot[["connection_id"]]) ||
        !identical(snapshot[["connection_id"]], connected[["connection_id"]]) ||
        !identical(
          snapshot[["identity_digest"]],
          connected[["identity_digest"]]
        ) ||
        !grepl("^[a-f0-9]{64}$", snapshot[["identity_digest"]]) ||
        length(snapshot[["errors"]])
    ) {
      return(FALSE)
    }
  }
  for (snapshot in c(list(initial), snapshots[expected_names[9:13]])) {
    if (
      !identical(snapshot[["connection_count"]], 0L) ||
        !identical(snapshot[["identity_verified"]], FALSE) ||
        !is.null(snapshot[["identity_digest"]]) ||
        !is.null(snapshot[["connection_id"]])
    ) {
      return(FALSE)
    }
  }
  if (
    connected[["session_number"]] <= initial[["session_number"]] ||
      snapshots[["page_two"]][["session_number"]] <=
        connected[["session_number"]] ||
      snapshots[["page_one"]][["session_number"]] <=
        snapshots[["page_two"]][["session_number"]] ||
      snapshots[["foreign"]][["session_number"]] <=
        snapshots[["page_one"]][["session_number"]] ||
      snapshots[["new_owner"]][["session_number"]] <=
        snapshots[["foreign"]][["session_number"]]
  ) {
    return(FALSE)
  }
  groups <- list(
    c("connected", "initial_read"),
    c("page_two", "restored_read", "refreshed", "refreshed_read"),
    c("page_one", "returned_read", "logged_out"),
    c("foreign", "foreign_probe"),
    c("new_owner", "old_id_probe")
  )
  for (group in groups) {
    if (
      length(unique(vapply(
        snapshots[group],
        function(snapshot) snapshot[["session_number"]],
        integer(1)
      ))) !=
        1L
    ) {
      return(FALSE)
    }
  }
  for (name in c("page_two", "page_one", "foreign", "new_owner")) {
    if (
      !identical(snapshots[[name]][["result_revision"]], 0L) ||
        !is.null(snapshots[[name]][["result"]])
    ) {
      return(FALSE)
    }
  }
  for (name in c(
    "initial_read",
    "restored_read",
    "refreshed_read",
    "returned_read"
  )) {
    result <- snapshots[[name]][["result"]]
    if (
      !identical(result[["action"]], "read") ||
        !identical(result[["status"]], 200L) ||
        !identical(result[["api"]], "connection") ||
        !identical(result[["transport"]], "main_process") ||
        !identical(result[["pid"]], initial[["app_pid"]]) ||
        !interop_retention_true(
          result,
          c("done", "subject_matches", "identity_usable")
        ) ||
        isTRUE(result[["failed"]])
    ) {
      return(FALSE)
    }
  }
  refresh <- snapshots[["refreshed"]][["result"]]
  if (
    !identical(refresh[["action"]], "refresh") ||
      !interop_retention_true(
        refresh,
        c(
          "done",
          "succeeded",
          "connection_same",
          "access_changed",
          "identity_unchanged",
          "connection_usable"
        )
      ) ||
      isTRUE(refresh[["failed"]])
  ) {
    return(FALSE)
  }
  for (name in c("foreign_probe", "old_id_probe")) {
    if (
      !identical(snapshots[[name]][["result"]][["action"]], "probe") ||
        !interop_retention_true(
          snapshots[[name]][["result"]],
          c("done", "denied")
        )
    ) {
      return(FALSE)
    }
  }
  logout <- snapshots[["logged_out"]][["result"]]
  for (name in c("foreign", "foreign_probe", "new_owner", "old_id_probe")) {
    if (length(snapshots[[name]][["errors"]])) return(FALSE)
  }
  if (
    !identical(
      snapshots[["logged_out"]][["errors"]],
      list(owner = "owner_unavailable")
    )
  ) {
    return(FALSE)
  }
  if (
    !identical(logout[["action"]], "logout") ||
      !interop_retention_true(
        logout,
        c("done", "stale_unusable", "export_blocked")
      ) ||
      !identical(logout[["remote_revocation_requested"]], FALSE)
  ) {
    return(FALSE)
  }
  cookie <- row[["owner_cookie"]]
  if (
    !identical(cookie[["count"]], 1L) ||
      !interop_retention_true(
        cookie,
        c("secure", "http_only", "hidden_from_javascript")
      ) ||
      !identical(cookie[["same_site"]], "Lax") ||
      !identical(cookie[["path"]], "/")
  ) {
    return(FALSE)
  }
  for (snapshot in c(list(initial), snapshots[1:8])) {
    operations <- snapshot[["operations"]]
    authenticated <- snapshot[["connection_count"]] == 1L
    refreshed <- snapshot[["session_number"]] >=
      snapshots[["refreshed"]][["session_number"]] &&
      !identical(snapshot, snapshots[["page_two"]]) &&
      !identical(snapshot, snapshots[["restored_read"]])
    for (name in c(
      "audit_token_exchange",
      "audit_login_success",
      "audit_callback_validation_success"
    )) {
      if (!identical(operations[[name]], as.integer(authenticated))) {
        return(FALSE)
      }
    }
    if (
      !identical(
        operations[["audit_userinfo"]],
        if (!authenticated) {
          0L
        } else if (refreshed) {
          2L
        } else {
          1L
        }
      ) ||
        !identical(
          operations[["audit_token_refresh"]],
          as.integer(refreshed)
        ) ||
        !identical(operations[["audit_login_failed"]], 0L) ||
        !identical(operations[["audit_session_cleared"]], 0L)
    ) {
      return(FALSE)
    }
  }
  if (!openid_transport_matches(row, list(outcome = "refreshed"), context)) {
    return(FALSE)
  }
  if (row[["response_mode"]] == "form_post") {
    value <- row[["form_post"]]
    return(
      identical(value[["authorization_method"]], "GET") &&
        identical(value[["callback_method"]], "POST") &&
        isTRUE(value[["bridge_redirect_303"]]) &&
        identical(value[["provider_origin"]], row[["provider_origin"]]) &&
        identical(value[["app_origin"]], row[["app_origin"]])
    )
  }
  is.null(row[["form_post"]])
}

interop_retention_matches <- function(report, context, lock, cases) {
  tryCatch(
    {
      if (
        !identical(report[["schema_version"]], 1L) ||
          !identical(report[["scope"]], "oidc_provider_browser_retention") ||
          !identical(report[["coverage_complete"]], FALSE) ||
          !identical(
            unlist(report[["coverage_limitations"]]),
            interop_retention_limits()
          ) ||
          !interop_retention_true(
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
      if (!length(cases) || length(rows) != length(cases)) {
        return(FALSE)
      }
      ids <- vapply(rows, function(row) row[["id"]], character(1))
      instances <- vapply(rows, function(row) row[["case_id"]], character(1))
      expected <- vapply(cases, function(value) value[["id"]], character(1))
      if (
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
          interop_retention_row_matches(
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

interop_retention_mutations <- function(report) {
  paths <- list(
    list("coverage_limitations"),
    list("cleanup_verified"),
    list("driver_failure_control_passed")
  )
  for (i in seq_along(report[["results"]])) {
    row <- report[["results"]][[i]]
    base <- list("results", i)
    paths <- c(paths, list(base))
    for (field in c(
      "provider",
      "owner_cookie",
      "discovery",
      "callback_cleaned",
      "worker_cleanup_verified",
      "app"
    )) {
      paths <- c(paths, list(c(base, field)))
    }
    for (name in names(row[["snapshots"]])) {
      path <- c(base, list("snapshots", name))
      paths <- c(paths, list(path), list(c(path, "session_number")))
      for (field in c(
        "connection_count",
        "connection_id",
        "identity_verified",
        "identity_digest",
        "app_instance"
      )) {
        if (!is.null(row[["snapshots"]][[name]][[field]])) {
          paths <- c(paths, list(c(path, field)))
        }
      }
      if (!is.null(row[["snapshots"]][[name]][["result"]])) {
        paths <- c(paths, list(c(path, "result")))
      }
    }
    for (j in seq_along(row[["provider"]][["events"]])) {
      path <- c(base, list("provider", "events", j))
      paths <- c(paths, list(path))
      event <- row[["provider"]][["events"]][[j]]
      for (field in setdiff(names(event), c("sequence", "type"))) {
        if (!is.null(event[[field]])) paths <- c(paths, list(c(path, field)))
      }
    }
    if (row[["response_mode"]] == "form_post") {
      paths <- c(paths, list(c(base, "form_post")))
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

interop_retention_rejections <- function(report, context, lock, cases) {
  if (!interop_retention_matches(report, context, lock, cases)) {
    stop("Actual retention report failed before rejection controls")
  }
  controls <- lapply(interop_retention_mutations(report), function(path) {
    !interop_retention_matches(
      replace_nested(report, path, NULL),
      context,
      lock,
      cases
    )
  })
  failed <- names(controls)[!vapply(controls, isTRUE, logical(1))]
  if (length(failed)) {
    stop(
      "Retention rejection controls unexpectedly passed: ",
      paste(failed, collapse = ", ")
    )
  }
  controls
}

interop_retention_check_report <- function(report, context, lock, cases) {
  controls <- report[["rejection_controls"]]
  interop_retention_matches(report, context, lock, cases) &&
    is.list(controls) &&
    !anyDuplicated(names(controls)) &&
    setequal(names(controls), names(interop_retention_mutations(report))) &&
    all(vapply(controls, isTRUE, logical(1)))
}
