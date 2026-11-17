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

interop_provider_matches <- function(provider, row, lock) {
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
  types <- c(
    "authorization.error",
    "interaction",
    "interaction",
    "authorization.accepted",
    "authorization.success",
    "grant.success",
    "userinfo",
    "grant.success",
    "userinfo"
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
  required <- function(event, fields) {
    all(vapply(fields, function(name) isTRUE(event[[name]]), logical(1)))
  }
  if (
    !identical(events[[1L]][["error"]], "invalid_request") ||
      !required(events[[1L]], c("client_matches", "pkce_missing")) ||
      !identical(events[[2L]][["prompt"]], "login") ||
      !identical(events[[3L]][["prompt"]], "consent") ||
      !identical(events[[4L]][["response_mode"]], row[["response_mode"]]) ||
      !required(
        events[[4L]],
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ) ||
      !required(events[[5L]], "code_issued")
  ) {
    return(FALSE)
  }
  for (i in c(6L, 8L)) {
    event <- events[[i]]
    if (
      !identical(
        event[["grant_type"]],
        if (i == 6L) "authorization_code" else "refresh_token"
      ) ||
        !required(
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
    if (
      i == 6L &&
        (!required(event, c("pkce_verified", "code_matches")) ||
          !is.null(event[["refresh_token_rotated"]]))
    ) {
      return(FALSE)
    }
    if (
      i == 8L &&
        (!isTRUE(event[["refresh_token_rotated"]]) ||
          !is.null(event[["pkce_verified"]]) ||
          !is.null(event[["code_matches"]]))
    ) {
      return(FALSE)
    }
  }
  all(vapply(
    events[c(7L, 9L)],
    function(event) {
      identical(event[["status"]], 200L) &&
        required(
          event,
          c("issued_token_used", "current_token_used", "subject_present")
        )
    },
    logical(1)
  ))
}

interop_report_matches <- function(report, context, lock, cases) {
  tryCatch(
    {
      if (
        !identical(report[["schema_version"]], 1L) ||
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
            !interop_provider_matches(row[["provider"]], row, lock) ||
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
    "driver_failure_control_passed"
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
