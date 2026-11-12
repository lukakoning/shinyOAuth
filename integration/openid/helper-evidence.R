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
      !identical(app[["package_version"]], package_version) ||
      !isTRUE(app[["ready"]])
  ) {
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

openid_check_report <- function(report, context, manifest) {
  tryCatch(
    {
      if (!identical(report[["schema_version"]], 1L)) {
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
      expected <- profile[["modules"]]
      names_expected <- vapply(
        expected,
        function(x) x[["module"]],
        character(1)
      )
      if (
        isTRUE(profile[["complete_profile"]]) &&
          !setequal(names_expected, unlist(manifest[["available_modules"]]))
      ) {
        stop("Complete profile does not select every pinned module")
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
        manifest[["plan_variant"]],
        manifest[["module_variant"]]
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
        if (
          !isTRUE(result[["callback_cleaned"]]) ||
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
      }
      if (!isTRUE(report[["driver_failure_control_passed"]])) {
        stop("The real app failure control did not pass")
      }
      if (!isTRUE(report[["cleanup_verified"]])) {
        stop("Owned resources were not cleaned up")
      }
      list(
        gate_passed = TRUE,
        selection_complete = TRUE,
        coverage_complete = isTRUE(profile[["complete_profile"]]),
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
    schema_version = 1L,
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
