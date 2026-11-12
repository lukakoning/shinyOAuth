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

openid_check_report <- function(report, context, manifest) {
  tryCatch(
    {
      if (!identical(report[["schema_version"]], 2L)) {
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
        spec[["module_variant"]]
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
        if (
          !identical(
            result[["action"]],
            if (discovery) "discovery" else "login"
          ) ||
            !isTRUE(result[[
              if (discovery) "no_callback" else "callback_cleaned"
            ]]) ||
            !openid_string(result[["browser_version"]])
        ) {
          stop("Missing browser navigation evidence")
        }
        if (
          !openid_app_matches(
            result[["app"]],
            expectation,
            paste0(context[["run_id"]], "-", result[["suite_id"]]),
            context[["package_version"]]
          )
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
  list(
    schema_version = 2L,
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
        c("httr2", "jsonlite", "openssl", "processx", "callr", "chromote"),
        function(package) as.character(utils::packageVersion(package))
      ),
      c("httr2", "jsonlite", "openssl", "processx", "callr", "chromote")
    ),
    results = list(),
    cleanup_verified = FALSE,
    gate_passed = FALSE,
    selection_complete = FALSE,
    coverage_complete = FALSE
  )
}
