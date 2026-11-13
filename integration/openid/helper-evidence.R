openid_count <- function(value, minimum = 0L) {
  is.numeric(value) &&
    length(value) == 1L &&
    is.finite(value) &&
    value == floor(value) &&
    value >= minimum
}

openid_app_matches <- function(app, expectation, case_id, package_version) {
  if (
    !is.list(app) ||
      !identical(app[["run_id"]], case_id) ||
      !identical(app[["package_version"]], package_version)
  ) {
    return(FALSE)
  }
  if (expectation[["outcome"]] %in% c("discovered", "discovery_rejected")) {
    rejected <- identical(expectation[["outcome"]], "discovery_rejected")
    no_identity <- all(vapply(
      app[c(
        "authenticated",
        "has_token",
        "id_token_validated",
        "userinfo_present"
      )],
      identical,
      logical(1),
      FALSE
    )) &&
      all(
        c(
          "authenticated",
          "has_token",
          "id_token_validated",
          "userinfo_present"
        ) %in%
          names(app)
      )
    no_exchanges <- all(vapply(
      c("audit_token_exchange", "audit_userinfo", "audit_login_success"),
      function(name) {
        count <- app[["operations"]][[name]]
        openid_count(count) && count == 0L
      },
      logical(1)
    ))
    if (rejected) {
      return(
        no_identity &&
          no_exchanges &&
          identical(app[["ready"]], FALSE) &&
          identical(app[["discovery_issuer_exact"]], FALSE) &&
          identical(app[["error_code"]], "discovery_setup_error") &&
          "shinyOAuth_config_error" %in% unlist(app[["error_classes"]]) &&
          "iss" %in% unlist(app[["claims"]]) &&
          "discovery_issuer_mismatch" %in% unlist(app[["reasons"]])
      )
    }
    return(
      no_identity &&
        no_exchanges &&
        isTRUE(app[["ready"]]) &&
        isTRUE(app[["discovery_issuer_exact"]]) &&
        is.null(app[["error_code"]]) &&
        !length(app[["error_classes"]]) &&
        (!isTRUE(expectation[["preload_jwks"]]) ||
          isTRUE(app[["prefetch_completed"]]))
    )
  }
  if (!isTRUE(app[["ready"]])) {
    return(FALSE)
  }
  if (identical(expectation[["outcome"]], "authenticated")) {
    return(
      isTRUE(app[["authenticated"]]) &&
        isTRUE(app[["has_token"]]) &&
        isTRUE(app[["id_token_validated"]]) &&
        isTRUE(app[["userinfo_present"]]) &&
        all(
          unlist(expectation[["userinfo_claims"]]) %in%
            unlist(app[["userinfo_claims"]])
        ) &&
        is.null(app[["error_code"]]) &&
        !length(app[["error_classes"]]) &&
        openid_count(app[["operations"]][["audit_token_exchange"]], 1L) &&
        openid_count(app[["operations"]][["audit_userinfo"]], 1L)
    )
  }
  expected_class <- expectation[["error_class"]]
  if (is.null(expected_class)) {
    expected_class <- "shinyOAuth_id_token_error"
  }
  category <- if (!is.null(expectation[["claim"]])) {
    expectation[["claim"]] %in% unlist(app[["claims"]])
  } else if (!is.null(expectation[["reason"]])) {
    expectation[["reason"]] %in% unlist(app[["reasons"]])
  } else {
    identical(expected_class, "shinyOAuth_userinfo_mismatch")
  }
  userinfo_count <- app[["operations"]][["audit_userinfo"]]
  operations_match <- if (
    identical(expected_class, "shinyOAuth_userinfo_mismatch")
  ) {
    # Subject validation can fail before the UserInfo completion audit. Its
    # typed error and the suite verdict establish that exchange; token
    # exchange completion establishes the preceding validated ID token.
    openid_count(app[["operations"]][["audit_token_exchange"]], 1L)
  } else {
    openid_count(userinfo_count) && userinfo_count == 0L
  }
  identical(expectation[["outcome"]], "rejected") &&
    identical(app[["authenticated"]], FALSE) &&
    identical(app[["has_token"]], FALSE) &&
    identical(app[["id_token_validated"]], FALSE) &&
    identical(app[["userinfo_present"]], FALSE) &&
    identical(app[["error_code"]], "token_exchange_error") &&
    expected_class %in% unlist(app[["error_classes"]]) &&
    isTRUE(category) &&
    isTRUE(operations_match) &&
    openid_count(app[["operations"]][["audit_login_success"]]) &&
    app[["operations"]][["audit_login_success"]] == 0L
}

openid_refresh_matches <- function(
  result,
  expectation,
  case_id,
  package_version
) {
  before <- result[["before_refresh"]]
  after <- result[["app"]]
  initial <- result[["initial"]]
  positive <- identical(expectation[["outcome"]], "refreshed")
  if (
    !expectation[["outcome"]] %in% c("refreshed", "refresh_rejected") ||
      !openid_app_matches(
        before,
        list(outcome = "authenticated"),
        case_id,
        package_version
      ) ||
      !isTRUE(before[["has_refresh_token"]]) ||
      !is.null(before[["refresh"]]) ||
      !identical(result[["steps"]], list(before)) ||
      length(result[["between_logins"]]) != 0L ||
      !identical(after[["run_id"]], case_id) ||
      !identical(after[["package_version"]], package_version) ||
      !isTRUE(after[["ready"]]) ||
      !identical(after[["session_number"]], before[["session_number"]]) ||
      !openid_count(
        before[["session_number"]],
        initial[["session_number"]] + 1L
      ) ||
      !identical(initial[["authenticated"]], FALSE) ||
      !identical(initial[["has_token"]], FALSE)
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
  count_is <- function(app, name, expected) {
    value <- app[["operations"]][[name]]
    openid_count(value) && value == expected
  }
  for (name in c(
    "audit_token_exchange",
    "audit_userinfo",
    "audit_login_success",
    "audit_callback_validation_success"
  )) {
    if (
      !count_is(initial, name, 0L) ||
        !count_is(before, name, 1L) ||
        !count_is(
          after,
          name,
          if (name == "audit_userinfo" && positive) 2L else 1L
        )
    ) {
      return(FALSE)
    }
  }
  for (name in c("audit_token_refresh", "audit_session_cleared")) {
    if (
      !count_is(initial, name, 0L) ||
        !count_is(before, name, 0L) ||
        !count_is(
          after,
          name,
          if ((name == "audit_token_refresh") == positive) 1L else 0L
        )
    ) {
      return(FALSE)
    }
  }
  refresh <- after[["refresh"]]
  if (
    !openid_count(refresh[["attempts"]]) ||
      refresh[["attempts"]] != 1L ||
      !isTRUE(refresh[["done"]]) ||
      !identical(refresh[["result"]], if (positive) "succeeded" else "rejected")
  ) {
    return(FALSE)
  }
  for (name in c(
    "connection_same",
    "connection_present",
    "old_connection_usable",
    "access_changed",
    "original_id_token_retained",
    "issuer_unchanged",
    "subject_unchanged",
    "exported_current"
  )) {
    if (!identical(refresh[[name]], positive)) return(FALSE)
  }
  for (name in c("export_blocked", "refresh_error_is_access_error")) {
    if (!identical(refresh[[name]], !positive)) return(FALSE)
  }
  if (positive) {
    return(
      isTRUE(after[["has_refresh_token"]]) &&
        openid_app_matches(
          after,
          list(outcome = "authenticated"),
          case_id,
          package_version
        )
    )
  }
  flags <- c(
    "authenticated",
    "has_token",
    "has_refresh_token",
    "id_token_validated",
    "userinfo_present"
  )
  all(vapply(
    flags,
    function(name) identical(after[[name]], FALSE),
    logical(1)
  )) &&
    identical(after[["error_code"]], "token_refresh_error") &&
    "shinyOAuth_id_token_error" %in% unlist(after[["error_classes"]]) &&
    expectation[["claim"]] %in% unlist(after[["claims"]])
}

openid_rotation_matches <- function(
  result,
  expectation,
  case_id,
  package_version
) {
  if (!isTRUE(expectation[["rotation_required"]])) {
    return(TRUE)
  }
  initial <- result[["initial"]]
  if (
    !identical(initial[["run_id"]], case_id) ||
      !identical(initial[["package_version"]], package_version) ||
      !isTRUE(initial[["ready"]]) ||
      !isTRUE(initial[["discovery_issuer_exact"]]) ||
      !identical(initial[["authenticated"]], FALSE) ||
      !identical(initial[["has_token"]], FALSE)
  ) {
    return(FALSE)
  }
  steps <- result[["steps"]]
  logins <- expectation[["logins"]]
  if (is.null(logins)) {
    logins <- 1L
  }
  if (length(steps) != logins || !identical(result[["app"]], steps[[logins]])) {
    return(FALSE)
  }
  for (name in c("app_instance", "cache_instance")) {
    if (
      !openid_string(initial[[name]]) ||
        !all(vapply(
          steps,
          function(step) identical(step[[name]], initial[[name]]),
          logical(1)
        ))
    ) {
      return(FALSE)
    }
  }
  for (i in seq_along(steps)) {
    step <- steps[[i]]
    if (
      !openid_app_matches(step, expectation, case_id, package_version) ||
        !isTRUE(step[["discovery_issuer_exact"]]) ||
        !openid_count(step[["operations"]][["audit_token_exchange"]], i) ||
        !openid_count(step[["operations"]][["audit_userinfo"]], i) ||
        !openid_count(step[["session_number"]], initial[["session_number"]] + i)
    ) {
      return(FALSE)
    }
  }
  after <- steps[[logins]]
  if (!openid_string(after[["token_key_id_digest"]])) {
    return(FALSE)
  }
  if (isTRUE(expectation[["preload_jwks"]])) {
    ids <- unlist(initial[["prefetched_key_ids"]])
    if (
      !isTRUE(initial[["prefetch_completed"]]) ||
        !length(ids) ||
        !all(vapply(as.list(ids), openid_string, logical(1))) ||
        after[["token_key_id_digest"]] %in% ids
    ) {
      return(FALSE)
    }
  } else {
    before <- steps[[1L]]
    if (
      !openid_string(before[["token_key_id_digest"]]) ||
        identical(
          before[["token_key_id_digest"]],
          after[["token_key_id_digest"]]
        )
    ) {
      return(FALSE)
    }
  }
  between <- result[["between_logins"]]
  if (length(between) != logins - 1L) {
    return(FALSE)
  }
  for (state in between) {
    if (
      !identical(state[["app_instance"]], initial[["app_instance"]]) ||
        !identical(state[["cache_instance"]], initial[["cache_instance"]]) ||
        !identical(state[["authenticated"]], FALSE) ||
        !identical(state[["has_token"]], FALSE) ||
        !identical(state[["error_code"]], "logged_out")
    ) {
      return(FALSE)
    }
  }
  # The pinned suite forbids JWKS storage. Keep the actual cache object, honor
  # that policy and explicitly leave cached-key refresh coverage incomplete.
  for (state in c(list(initial), steps, between)) {
    for (name in c("cache_updates", "cache_hits")) {
      if (!openid_count(state[[name]]) || state[[name]] != 0L) return(FALSE)
    }
  }
  TRUE
}

openid_form_post_matches <- function(result, context) {
  navigation <- result[["form_post"]]
  callback <- result[["app"]][["form_post"]]
  cookie <- navigation[["cookie"]]
  if (
    !all(vapply(
      context[c("provider_origin", "app_origin")],
      openid_string,
      logical(1)
    )) ||
      !all(c("provider_origin", "app_origin") %in% names(context))
  ) {
    return(FALSE)
  }
  origins <- c(context[["provider_origin"]], context[["app_origin"]])
  if (
    !all(grepl("^https://localhost:[0-9]+$", origins)) ||
      identical(origins[[1L]], origins[[2L]])
  ) {
    return(FALSE)
  }
  identical(navigation[["provider_origin"]], context[["provider_origin"]]) &&
    identical(navigation[["app_origin"]], context[["app_origin"]]) &&
    identical(navigation[["authorization_method"]], "GET") &&
    identical(navigation[["callback_method"]], "POST") &&
    isTRUE(navigation[["bridge_redirect_303"]]) &&
    isTRUE(navigation[["secure_context"]]) &&
    identical(navigation[["cross_origin"]], TRUE) &&
    identical(callback[["method"]], "POST") &&
    isTRUE(callback[["origin_matched"]]) &&
    isTRUE(callback[["form_urlencoded"]]) &&
    openid_string(callback[["sec_fetch_site"]]) &&
    callback[["sec_fetch_site"]] %in% c("same-site", "cross-site") &&
    identical(
      navigation[["cross_site"]],
      identical(callback[["sec_fetch_site"]], "cross-site")
    ) &&
    openid_count(cookie[["binding_cookie_count"]], 1L) &&
    isTRUE(cookie[["secure"]]) &&
    identical(cookie[["same_site"]], "Strict") &&
    openid_count(
      result[["app"]][["operations"]][["audit_callback_validation_success"]],
      1L
    )
}

openid_transport_matches <- function(result, expectation, context) {
  transport <- context[["transport"]]
  if (
    !transport %in% c("sync", "mirai", "future") ||
      (identical(transport, "future") &&
        !context[["profile"]] %in% c("smoke", "refresh"))
  ) {
    return(FALSE)
  }
  evidence <- result[["app"]][["transport"]]
  initial <- result[["initial"]][["transport"]]
  async <- !identical(transport, "sync")
  if (
    !identical(evidence[["backend"]], transport) ||
      !isTRUE(evidence[["backend_verified"]]) ||
      !isTRUE(evidence[["events_verified"]]) ||
      !isTRUE(result[["worker_cleanup_verified"]]) ||
      !openid_count(evidence[["app_pid"]], 1L) ||
      !identical(evidence[["app_pid"]], initial[["app_pid"]]) ||
      !identical(evidence[["probes"]], initial[["probes"]]) ||
      !identical(
        evidence[["cache_scope"]],
        if (async) "serialized_per_dispatch" else "main_process"
      )
  ) {
    return(FALSE)
  }
  for (name in c(
    "audit_token_exchange",
    "audit_userinfo",
    "audit_login_success",
    "audit_login_failed",
    "audit_callback_validation_success",
    "audit_token_refresh",
    "audit_session_cleared"
  )) {
    main <- evidence[["main_operations"]][[name]]
    worker <- evidence[["worker_operations"]][[name]]
    total <- result[["app"]][["operations"]][[name]]
    if (
      !openid_count(main) ||
        !openid_count(worker) ||
        !openid_count(total) ||
        main + worker != total
    ) {
      return(FALSE)
    }
    if (
      (!async && worker != 0L) ||
        (async &&
          name %in%
            c(
              "audit_token_exchange",
              "audit_userinfo",
              "audit_token_refresh"
            ) &&
          main != 0L)
    ) {
      return(FALSE)
    }
  }
  pids <- unlist(evidence[["worker_pids"]])
  probes <- evidence[["probes"]]
  if (!async) {
    return(length(pids) == 0L && length(probes) == 0L)
  }
  if (
    length(probes) != 2L ||
      !all(vapply(
        probes,
        function(probe) {
          openid_count(probe[["pid"]], 1L) &&
            probe[["pid"]] != evidence[["app_pid"]] &&
            identical(
              probe[["package_version"]],
              context[["package_version"]]
            ) &&
            all(vapply(
              c(
                "package_matches",
                "ca_matches",
                "tls_verified",
                "hostname_rejected"
              ),
              function(name) isTRUE(probe[[name]]),
              logical(1)
            ))
        },
        logical(1)
      ))
  ) {
    return(FALSE)
  }
  probe_pids <- vapply(probes, function(probe) probe[["pid"]], numeric(1))
  if (
    anyDuplicated(probe_pids) ||
      anyDuplicated(pids) ||
      !all(pids %in% probe_pids)
  ) {
    return(FALSE)
  }
  if (identical(expectation[["action"]], "discovery")) {
    return(length(pids) == 0L)
  }
  if (!length(pids)) {
    return(FALSE)
  }
  if (expectation[["outcome"]] %in% c("rejected", "refresh_rejected")) {
    return(openid_count(evidence[["worker_validation_errors"]], 1L))
  }
  openid_count(evidence[["worker_operations"]][["audit_token_exchange"]], 1L) &&
    openid_count(evidence[["worker_operations"]][["audit_userinfo"]], 1L)
}

openid_check_report <- function(report, context, manifest) {
  tryCatch(
    {
      if (!identical(report[["schema_version"]], 3L)) {
        stop("Unsupported evidence schema")
      }
      for (name in c(
        "run_id",
        "attempt_id",
        "checkout_revision",
        "source_revision",
        "profile",
        "transport",
        "package_version",
        "plan_id"
      )) {
        if (
          !openid_string(context[[name]]) ||
            !identical(report[[name]], context[[name]])
        ) {
          stop("Evidence does not belong to this run and checkout")
        }
      }
      if (
        !identical(context[["source_revision"]], manifest[["source_revision"]])
      ) {
        stop("Unexpected suite revision")
      }
      profile <- manifest[["profiles"]][[context[["profile"]]]]
      if (is.null(profile)) {
        stop("Unknown evidence profile")
      }
      spec <- openid_plan_spec(manifest, context[["profile"]])
      if (identical(context[["profile"]], "form-post")) {
        for (name in c("provider_origin", "app_origin")) {
          if (
            !openid_string(context[[name]]) ||
              !identical(report[[name]], context[[name]])
          ) {
            stop("Form Post origins do not belong to this run")
          }
        }
      }
      expected <- profile[["modules"]]
      names_expected <- vapply(
        expected,
        function(x) x[["module"]],
        character(1)
      )
      if (
        (isTRUE(profile[["complete_profile"]]) ||
          isTRUE(profile[["all_modules_required"]])) &&
          !setequal(names_expected, unlist(spec[["available_modules"]]))
      ) {
        stop("Complete profile does not select every pinned module")
      }
      if (
        identical(context[["profile"]], "config") &&
          (!isTRUE(report[["jwks_cache_policy"]][["no_store"]]) ||
            !identical(
              report[["jwks_cache_policy"]][["source_revision"]],
              context[["source_revision"]]
            ) ||
            !openid_string(report[["jwks_cache_policy"]][["suite_id"]]))
      ) {
        stop("Missing pinned-suite JWKS cache-policy evidence")
      }
      results <- report[["results"]]
      if (!length(expected) || length(results) != length(expected)) {
        stop("Incomplete module selection")
      }
      names_actual <- vapply(results, function(x) x[["module"]], character(1))
      if (
        anyDuplicated(names_actual) || !setequal(names_actual, names_expected)
      ) {
        stop("Missing, duplicated or unrelated module results")
      }
      ids <- vapply(results, function(x) x[["suite_id"]], character(1))
      if (
        anyDuplicated(ids) ||
          !all(vapply(as.list(ids), openid_string, logical(1)))
      ) {
        stop("Missing or reused suite instance")
      }
      variant <- utils::modifyList(
        spec[["plan_variant"]],
        as.list(spec[["module_variant"]])
      )
      for (result in results) {
        expectation <- expected[[match(result[["module"]], names_expected)]]
        if (
          !identical(result[["run_id"]], context[["run_id"]]) ||
            !identical(result[["attempt_id"]], context[["attempt_id"]]) ||
            !identical(
              result[["checkout_revision"]],
              context[["checkout_revision"]]
            ) ||
            !identical(
              result[["source_revision"]],
              context[["source_revision"]]
            ) ||
            !identical(result[["plan_id"]], context[["plan_id"]]) ||
            !identical(
              openid_variant_key(result[["variant"]]),
              openid_variant_key(variant)
            )
        ) {
          stop("Stale or mismatched module evidence")
        }
        expected_verdict <- "PASSED"
        if (
          identical(
            expectation[["optional_policy"]],
            "reject_unsigned_id_token"
          ) &&
            identical(
              result[["module"]],
              "oidcc-client-test-idtoken-sig-none"
            ) &&
            identical(expectation[["outcome"]], "rejected") &&
            identical(expectation[["reason"]], "disallowed_algorithm") &&
            identical(expectation[["suite_result"]], "SKIPPED")
        ) {
          expected_verdict <- "SKIPPED"
        }
        if (
          !identical(result[["suite_status"]], "FINISHED") ||
            !identical(result[["suite_result"]], expected_verdict) ||
            !is.null(result[["exception"]])
        ) {
          stop("Module did not finish with the expected suite verdict")
        }
        discovery <- identical(expectation[["action"]], "discovery")
        refreshing <- identical(expectation[["action"]], "refresh")
        if (
          !identical(
            result[["action"]],
            if (discovery) {
              "discovery"
            } else if (refreshing) {
              "refresh"
            } else {
              "login"
            }
          ) ||
            !isTRUE(result[[
              if (discovery) "no_callback" else "callback_cleaned"
            ]]) ||
            !openid_string(result[["browser_version"]])
        ) {
          stop("Missing browser navigation evidence")
        }
        if (
          identical(context[["profile"]], "form-post") &&
            !openid_form_post_matches(result, context)
        ) {
          stop("Missing real-browser Form Post, bridge or binding evidence")
        }
        if (!openid_transport_matches(result, expectation, context)) {
          stop(
            "Missing verified transport, worker execution or cleanup evidence"
          )
        }
        if (
          if (refreshing) {
            !openid_refresh_matches(
              result,
              expectation,
              paste0(context[["run_id"]], "-", result[["suite_id"]]),
              context[["package_version"]]
            )
          } else {
            !openid_app_matches(
              result[["app"]],
              expectation,
              paste0(context[["run_id"]], "-", result[["suite_id"]]),
              context[["package_version"]]
            )
          }
        ) {
          stop("Missing or incorrect application evidence")
        }
        if (
          !openid_rotation_matches(
            result,
            expectation,
            paste0(context[["run_id"]], "-", result[["suite_id"]]),
            context[["package_version"]]
          )
        ) {
          stop("Missing retained app/cache or signing-key rotation evidence")
        }
      }
      if (!isTRUE(report[["driver_failure_control_passed"]])) {
        stop("The real app failure control did not pass")
      }
      if (!isTRUE(report[["cleanup_verified"]])) {
        stop("Owned resources were not cleaned up")
      }
      cache_limited <- identical(context[["profile"]], "config") &&
        isTRUE(report[["jwks_cache_policy"]][["no_store"]])
      list(
        gate_passed = TRUE,
        selection_complete = TRUE,
        coverage_complete = isTRUE(profile[["complete_profile"]]) &&
          !cache_limited,
        coverage_limitations = as.list(unique(c(
          unlist(profile[["coverage_limitations"]]),
          if (cache_limited) {
            "suite_jwks_no_store_prevents_cached_key_refresh_test"
          }
        ))),
        cached_key_refresh_tested = if (cache_limited) FALSE else NULL,
        reason = NULL
      )
    },
    error = function(e) {
      list(
        gate_passed = FALSE,
        selection_complete = FALSE,
        coverage_complete = FALSE,
        reason = conditionMessage(e)
      )
    }
  )
}

openid_report_context <- function(root, profile, transport, package_version) {
  git <- function(args) {
    trimws(processx::run("git", args, wd = root)[["stdout"]])
  }
  random <- function() paste(format(openssl::rand_bytes(12)), collapse = "")
  dependencies <- c(
    "httr2",
    "jsonlite",
    "openssl",
    "processx",
    "callr",
    "chromote",
    "ps",
    if (!identical(transport, "sync")) c(transport, "promises", "later")
  )
  list(
    schema_version = 3L,
    status = "failed",
    run_id = random(),
    attempt_id = random(),
    checkout_revision = git(c("rev-parse", "HEAD")),
    checkout_dirty = nzchar(git(c("status", "--porcelain"))),
    source_revision = openid_lock(root)[["source_revision"]],
    profile = profile,
    transport = transport,
    package_version = package_version,
    r_version = as.character(getRversion()),
    dependency_versions = setNames(
      lapply(
        dependencies,
        function(package) as.character(utils::packageVersion(package))
      ),
      dependencies
    ),
    results = list(),
    cleanup_verified = FALSE,
    gate_passed = FALSE,
    selection_complete = FALSE,
    coverage_complete = FALSE
  )
}
