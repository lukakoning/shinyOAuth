interop_sanitized <- function(value) {
  forbidden <- c(
    "code",
    "state",
    "nonce",
    "client_secret",
    "client_assertion",
    "access_token",
    "refresh_token",
    "id_token",
    "private_key",
    "control_key",
    "error_description"
  )
  if (is.list(value)) {
    return(
      !any(names(value) %in% forbidden) &&
        all(vapply(value, interop_sanitized, logical(1)))
    )
  }
  if (is.character(value)) {
    return(
      !any(grepl(
        "PRIVATE KEY|[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}",
        value
      ))
    )
  }
  TRUE
}

interop_event_flags <- function(event, fields) {
  all(vapply(fields, function(name) isTRUE(event[[name]]), logical(1)))
}

interop_userinfo_matches <- function(event) {
  identical(event[["status"]], 200L) &&
    interop_event_flags(
      event,
      c("issued_token_used", "current_token_used", "subject_present")
    )
}

interop_login_events_match <- function(events, app, response_mode, max_age) {
  login <- events[[1L]]
  consent <- events[[2L]]
  accepted <- events[[3L]]
  code <- events[[4L]]
  grant <- events[[5L]]
  if (
    !identical(login[["prompt"]], "login") ||
      !identical(consent[["prompt"]], "consent") ||
      !identical(accepted[["response_mode"]], response_mode) ||
      !interop_event_flags(
        accepted,
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ) ||
      !isTRUE(code[["code_issued"]]) ||
      !identical(grant[["grant_type"]], "authorization_code") ||
      !interop_event_flags(
        grant,
        c(
          "client_matches",
          "authentication_valid",
          "access_token_present",
          "id_token_present",
          "refresh_token_present",
          "pkce_verified",
          "code_matches"
        )
      ) ||
      !is.null(grant[["refresh_token_rotated"]]) ||
      !interop_userinfo_matches(events[[6L]])
  ) {
    return(FALSE)
  }
  if (is.null(max_age)) {
    return(TRUE)
  }
  request <- accepted[["pushed_age_request"]]
  observed <- grant[["auth_time"]]
  validated <- app[["validated_auth_time"]]
  login_started <- login[["login_started_at"]]
  code_issued <- code[["code_issued_at"]]
  identical(request[["max_age"]], as.character(max_age)) &&
    interop_event_flags(request, c("client_matches", "challenge_matches")) &&
    all(vapply(
      list(observed, validated, login_started, code_issued),
      function(value) {
        is.numeric(value) && length(value) == 1L && is.finite(value)
      },
      logical(1)
    )) &&
    observed == validated &&
    login_started <= observed &&
    observed <= code_issued
}

interop_provider_matches <- function(provider, row, lock, selection) {
  if (
    !identical(provider[["run_id"]], row[["case_id"]]) ||
      !identical(provider[["provider_version"]], lock[["provider_version"]]) ||
      !identical(provider[["node_version"]], lock[["node_version"]]) ||
      !identical(provider[["client_auth_type"]], row[["client_auth_type"]]) ||
      !identical(
        provider[["features"]],
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
  events <- provider[["events"]]
  login_types <- c(
    "interaction",
    "interaction",
    "authorization.accepted",
    "authorization.success",
    "grant.success",
    "userinfo"
  )
  reauthenticate <- isTRUE(selection[["reauthenticate"]])
  types <- c(
    "authorization.error",
    login_types,
    "grant.success",
    "userinfo",
    if (reauthenticate) login_types
  )
  if (
    length(events) != length(types) ||
      !identical(
        vapply(events, function(e) e[["type"]], character(1)),
        types
      ) ||
      !identical(
        vapply(events, function(e) e[["sequence"]], integer(1)),
        seq_along(types)
      )
  ) {
    return(FALSE)
  }
  response_mode <- row[["response_mode"]]
  max_age <- selection[["max_age"]]
  refresh <- events[[8L]]
  if (
    !identical(events[[1L]][["error"]], "invalid_request") ||
      !interop_event_flags(events[[1L]], c("client_matches", "pkce_missing")) ||
      !interop_login_events_match(
        events[2:7],
        row[["before_refresh"]],
        response_mode,
        max_age
      ) ||
      !identical(refresh[["grant_type"]], "refresh_token") ||
      !interop_event_flags(
        refresh,
        c(
          "client_matches",
          "authentication_valid",
          "access_token_present",
          "id_token_present",
          "refresh_token_present",
          "refresh_token_rotated"
        )
      ) ||
      !is.null(refresh[["pkce_verified"]]) ||
      !is.null(refresh[["code_matches"]]) ||
      !interop_userinfo_matches(events[[9L]])
  ) {
    return(FALSE)
  }
  if (!reauthenticate) {
    return(TRUE)
  }
  old_time <- events[[6L]][["auth_time"]]
  interop_login_events_match(
    events[10:15],
    row[["reauthentication"]][["app"]],
    response_mode,
    max_age
  ) &&
    is.null(events[[2L]][["prior_session_auth_time"]]) &&
    identical(events[[10L]][["prior_session_auth_time"]], old_time) &&
    isTRUE(events[[10L]][["login_prompt_requested"]]) &&
    identical(
      events[[12L]][["pushed_age_request"]][["login_prompt_sent"]],
      FALSE
    ) &&
    events[[14L]][["auth_time"]] > old_time
}

interop_reauthentication_matches <- function(row, context) {
  evidence <- row[["reauthentication"]]
  logged_out <- evidence[["logged_out"]]
  after <- evidence[["app"]]
  before <- row[["app"]]
  expectation <- list(outcome = "authenticated")
  identical(logged_out[["authenticated"]], FALSE) &&
    identical(logged_out[["has_token"]], FALSE) &&
    identical(logged_out[["error_code"]], "logged_out") &&
    identical(logged_out[["session_number"]], before[["session_number"]]) &&
    identical(after[["session_number"]], before[["session_number"]] + 1L) &&
    identical(logged_out[["app_instance"]], before[["app_instance"]]) &&
    identical(after[["app_instance"]], before[["app_instance"]]) &&
    isTRUE(evidence[["callback_cleaned"]]) &&
    openid_app_matches(
      after,
      expectation,
      row[["case_id"]],
      context[["package_version"]]
    ) &&
    openid_transport_matches(
      list(
        app = after,
        initial = row[["initial"]],
        worker_cleanup_verified = row[["worker_cleanup_verified"]]
      ),
      expectation,
      context
    )
}

interop_report_source_matches <- function(report, context) {
  version <- report[["schema_version"]]
  expected <- context[["schema_version"]]
  if (identical(version, 1L)) {
    return(is.null(expected) || identical(expected, 1L))
  }
  identical(version, 2L) &&
    identical(version, expected) &&
    identical(report[["checkout_dirty"]], context[["checkout_dirty"]]) &&
    isTRUE(openid_check_source(report, context))
}

interop_report_matches <- function(report, context, lock, cases) {
  tryCatch(
    {
      if (
        !interop_report_source_matches(report, context) ||
          !identical(report[["scope"]], "oidc_provider_interoperability") ||
          !identical(report[["coverage_complete"]], FALSE) ||
          !isTRUE(report[["driver_failure_control_passed"]]) ||
          !isTRUE(report[["cleanup_verified"]]) ||
          !interop_sanitized(report)
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
      if (
        !report[["transport"]] %in% c("sync", "mirai") ||
          !identical(report[["provider_lock"]], lock) ||
          !identical(report[["source_hashes"]], context[["source_hashes"]]) ||
          !identical(report[["image_id"]], context[["image_id"]]) ||
          !grepl("^sha256:[a-f0-9]{64}$", report[["image_id"]])
      ) {
        return(FALSE)
      }
      results <- report[["results"]]
      if (length(results) != length(cases) || !length(cases)) {
        return(FALSE)
      }
      ids <- vapply(results, function(row) row[["id"]], character(1))
      instance_ids <- vapply(
        results,
        function(row) row[["case_id"]],
        character(1)
      )
      if (
        anyDuplicated(ids) ||
          anyDuplicated(instance_ids) ||
          !all(grepl("^[a-f0-9]{32}$", instance_ids)) ||
          !setequal(
            ids,
            vapply(cases, function(case) case[["id"]], character(1))
          )
      ) {
        return(FALSE)
      }
      for (row in results) {
        selection <- cases[[match(
          row[["id"]],
          vapply(cases, function(case) case[["id"]], character(1))
        )]]
        for (name in c("client_auth_type", "response_mode")) {
          if (!identical(row[[name]], selection[[name]])) return(FALSE)
        }
        if (
          !identical(row[["run_id"]], context[["run_id"]]) ||
            !identical(
              row[["checkout_revision"]],
              context[["checkout_revision"]]
            ) ||
            !isTRUE(row[["cleanup_verified"]]) ||
            !isTRUE(row[["worker_cleanup_verified"]]) ||
            !isTRUE(row[["callback_cleaned"]]) ||
            !isTRUE(row[["pkce_control_passed"]]) ||
            !openid_string(row[["browser_version"]]) ||
            !interop_provider_matches(
              row[["provider"]],
              row,
              lock,
              selection
            ) ||
            !openid_refresh_matches(
              row,
              list(outcome = "refreshed", action = "refresh"),
              row[["case_id"]],
              context[["package_version"]]
            ) ||
            !openid_transport_matches(
              row,
              list(outcome = "refreshed", action = "refresh"),
              context
            )
        ) {
          return(FALSE)
        }
        if (
          isTRUE(selection[["reauthenticate"]]) &&
            !interop_reauthentication_matches(row, context)
        ) {
          return(FALSE)
        }
        discovery <- row[["discovery"]]
        if (
          !identical(discovery[["issuer"]], row[["provider_origin"]]) ||
            !identical(
              unlist(discovery[["code_challenge_methods_supported"]]),
              "S256"
            ) ||
            !all(
              c("query", "form_post") %in%
                unlist(discovery[["response_modes_supported"]])
            ) ||
            !all(
              c("authorization_code", "refresh_token") %in%
                unlist(discovery[["grant_types_supported"]])
            ) ||
            !all(
              c("none", "client_secret_basic") %in%
                unlist(discovery[["token_endpoint_auth_methods_supported"]])
            ) ||
            !"RS256" %in%
              unlist(discovery[["id_token_signing_alg_values_supported"]])
        ) {
          return(FALSE)
        }
        for (name in c(
          "authorization_endpoint",
          "token_endpoint",
          "userinfo_endpoint",
          "jwks_uri"
        )) {
          if (
            !openid_string(discovery[[name]]) ||
              !startsWith(
                discovery[[name]],
                paste0(row[["provider_origin"]], "/")
              )
          ) {
            return(FALSE)
          }
        }
        if (
          !grepl("^https://localhost:[0-9]+$", row[["provider_origin"]]) ||
            !grepl("^https://localhost:[0-9]+$", row[["app_origin"]]) ||
            identical(row[["provider_origin"]], row[["app_origin"]])
        ) {
          return(FALSE)
        }
        if (
          identical(selection[["response_mode"]], "form_post") &&
            !openid_form_post_matches(row, row)
        ) {
          return(FALSE)
        }
      }
      TRUE
    },
    error = function(...) FALSE
  )
}

interop_source_rejection_overrides <- function(report) {
  if (!identical(report[["schema_version"]], 2L)) {
    return(list())
  }
  list(
    schema_version = 1L,
    source_verified = FALSE,
    checkout_source_after = FALSE,
    installation_after = FALSE
  )
}

interop_source_rejections <- function(report, matches) {
  overrides <- interop_source_rejection_overrides(report)
  fields <- names(overrides)
  controls <- lapply(fields, function(name) {
    altered <- report
    altered[[name]] <- overrides[[name]]
    !matches(altered)
  })
  setNames(controls, fields)
}

interop_rejection_controls <- function(report, context, lock, cases) {
  matches <- function(value) interop_report_matches(value, context, lock, cases)
  if (!matches(report)) {
    stop("The actual provider report must pass before rejection controls")
  }
  controls <- list()
  for (i in seq_along(report[["results"]])) {
    control <- report
    control[["results"]] <- control[["results"]][-i]
    controls[[paste0(i, "_missing_case")]] <- !matches(control)
    paths <- list(
      c("provider", "run_id"),
      c("provider", "events"),
      c("app", "id_token_validated"),
      c("app", "has_refresh_token"),
      c("app", "refresh", "access_changed"),
      c("app", "refresh", "subject_unchanged"),
      c("app", "transport", "events_verified"),
      c("worker_cleanup_verified"),
      c("callback_cleaned")
    )
    for (path in paths) {
      control <- report
      control[["results"]][[i]] <- replace_nested(
        control[["results"]][[i]],
        path,
        NULL
      )
      controls[[paste(c(i, path), collapse = "_")]] <- !matches(control)
    }
    for (field in c("pkce_verified", "code_matches", "authentication_valid")) {
      control <- report
      control[["results"]][[i]][["provider"]][["events"]][[6L]][[
        field
      ]] <- FALSE
      controls[[paste0(i, "_", field)]] <- !matches(control)
    }
    control <- report
    control[["results"]][[i]][["provider"]][["events"]][[9L]][[
      "current_token_used"
    ]] <- FALSE
    controls[[paste0(i, "_stale_userinfo_token")]] <- !matches(control)
    control <- report
    control[["results"]][[i]][["provider"]][["events"]][[8L]][[
      "refresh_token_rotated"
    ]] <- FALSE
    controls[[paste0(i, "_unrotated_refresh")]] <- !matches(control)
    if (identical(report[["results"]][[i]][["response_mode"]], "form_post")) {
      control <- report
      control[["results"]][[i]][["form_post"]] <- NULL
      controls[[paste0(i, "_missing_post_bridge")]] <- !matches(control)
    }
  }
  for (name in c("cleanup_verified", "driver_failure_control_passed")) {
    control <- report
    control[[name]] <- FALSE
    controls[[name]] <- !matches(control)
  }
  controls <- c(controls, interop_source_rejections(report, matches))
  if (!all(vapply(controls, isTRUE, logical(1)))) {
    stop("A provider evidence rejection control unexpectedly passed")
  }
  controls
}

interop_check_report <- function(report, context, lock, cases) {
  controls <- report[["rejection_controls"]]
  paths <- list(
    c("provider", "run_id"),
    c("provider", "events"),
    c("app", "id_token_validated"),
    c("app", "has_refresh_token"),
    c("app", "refresh", "access_changed"),
    c("app", "refresh", "subject_unchanged"),
    c("app", "transport", "events_verified"),
    c("worker_cleanup_verified"),
    c("callback_cleaned")
  )
  names_expected <- c(
    unlist(lapply(seq_along(cases), function(i) {
      c(
        paste0(i, "_missing_case"),
        vapply(
          paths,
          function(path) paste(c(i, path), collapse = "_"),
          character(1)
        ),
        paste0(
          i,
          c(
            "_pkce_verified",
            "_code_matches",
            "_authentication_valid",
            "_stale_userinfo_token",
            "_unrotated_refresh"
          )
        ),
        if (identical(cases[[i]][["response_mode"]], "form_post")) {
          paste0(i, "_missing_post_bridge")
        }
      )
    })),
    "cleanup_verified",
    "driver_failure_control_passed",
    names(interop_source_rejection_overrides(report))
  )
  interop_report_matches(report, context, lock, cases) &&
    is.list(controls) &&
    !anyDuplicated(names(controls)) &&
    setequal(names(controls), names_expected) &&
    all(vapply(controls, isTRUE, logical(1)))
}

replace_nested <- function(value, path, replacement) {
  if (length(path) == 1L) {
    value[[path[[1L]]]] <- replacement
  } else {
    value[[path[[1L]]]] <- replace_nested(
      value[[path[[1L]]]],
      path[-1L],
      replacement
    )
  }
  value
}
