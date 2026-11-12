evidence_fixture <- function(profile = "smoke") {
  manifest <- openid_profiles("../..")
  context <- list(
    schema_version = 1L,
    run_id = "run",
    attempt_id = "attempt",
    checkout_revision = paste(rep("a", 40), collapse = ""),
    source_revision = manifest[["source_revision"]],
    profile = profile,
    transport = "sync",
    package_version = "0.7.0.9000",
    plan_id = "plan"
  )
  results <- lapply(
    seq_along(manifest[["profiles"]][[profile]][["modules"]]),
    function(i) {
      expected <- manifest[["profiles"]][[profile]][["modules"]][[i]]
      positive <- identical(expected[["outcome"]], "authenticated")
      row <- context[c(
        "run_id",
        "attempt_id",
        "checkout_revision",
        "source_revision",
        "plan_id"
      )]
      row[["module"]] <- expected[["module"]]
      row[["suite_id"]] <- paste0("instance", i)
      row[["variant"]] <- utils::modifyList(
        manifest[["plan_variant"]],
        manifest[["module_variant"]]
      )
      row[["suite_status"]] <- "FINISHED"
      row[["suite_result"]] <- if (is.null(expected[["suite_result"]])) {
        "PASSED"
      } else {
        expected[["suite_result"]]
      }
      row[["callback_cleaned"]] <- TRUE
      row[["browser_version"]] <- "Chrome/test"
      row[["app"]] <- list(
        run_id = paste0("run-instance", i),
        ready = TRUE,
        package_version = context[["package_version"]],
        authenticated = positive,
        has_token = positive,
        id_token_validated = positive,
        userinfo_present = positive,
        userinfo_claims = if (positive) list("sub", "email") else list(),
        error_code = if (!positive) "token_exchange_error" else NULL,
        error_classes = if (!positive) {
          if (is.null(expected[["error_class"]])) {
            list("shinyOAuth_id_token_error")
          } else {
            list(expected[["error_class"]])
          }
        } else {
          list()
        },
        claims = if (!positive) list(expected[["claim"]]) else list(),
        reasons = if (!positive) list(expected[["reason"]]) else list(),
        operations = list(
          audit_token_exchange = 1L,
          audit_userinfo = if (positive) 1L else 0L,
          audit_login_success = if (positive) 1L else 0L
        )
      )
      row
    }
  )
  report <- c(
    context,
    list(
      results = results,
      cleanup_verified = TRUE,
      driver_failure_control_passed = TRUE
    )
  )
  list(manifest = manifest, context = context, report = report)
}

testthat::test_that("a passing smoke selection remains partial profile coverage", {
  f <- evidence_fixture()
  check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_true(check[["selection_complete"]])
  testthat::expect_false(check[["coverage_complete"]])
})

testthat::test_that("Basic coverage requires all pinned modules with their expected app outcomes", {
  f <- evidence_fixture("basic")
  check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_true(check[["coverage_complete"]])
  for (i in seq_along(f[["report"]][["results"]])) {
    report <- f[["report"]]
    report[["results"]] <- report[["results"]][-i]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
    report <- f[["report"]]
    report[["results"]][[i]][["app"]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  f[["manifest"]][["profiles"]][["smoke"]][["complete_profile"]] <- TRUE
  smoke <- evidence_fixture()
  testthat::expect_false(openid_check_report(
    smoke[["report"]],
    smoke[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("only the unsigned-token rejection policy permits the documented skip", {
  f <- evidence_fixture("basic")
  results <- f[["report"]][["results"]]
  unsigned <- which(vapply(
    results,
    function(row) {
      identical(row[["module"]], "oidcc-client-test-idtoken-sig-none")
    },
    logical(1)
  ))
  for (verdict in c("PASSED", "WARNING", "REVIEW", "FAILED")) {
    report <- f[["report"]]
    report[["results"]][[unsigned]][["suite_result"]] <- verdict
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (i in setdiff(seq_along(results), unsigned)) {
    report <- f[["report"]]
    report[["results"]][[i]][["suite_result"]] <- "SKIPPED"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (reason in list(NULL, "invalid_signature")) {
    report <- f[["report"]]
    report[["results"]][[unsigned]][["app"]][["reasons"]] <- reason
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[unsigned]][["app"]][["operations"]][[
    "audit_userinfo"
  ]] <- 1L
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("Basic rejection categories and scoped UserInfo evidence cannot be substituted", {
  f <- evidence_fixture("basic")
  for (i in seq_along(f[["report"]][["results"]])) {
    expected <- f[["manifest"]][["profiles"]][["basic"]][["modules"]][[i]]
    field <- if (!is.null(expected[["claim"]])) {
      "claims"
    } else if (!is.null(expected[["reason"]])) {
      "reasons"
    } else if (!is.null(expected[["error_class"]])) {
      "error_classes"
    } else if (!is.null(expected[["userinfo_claims"]])) {
      "userinfo_claims"
    } else {
      NULL
    }
    if (is.null(field)) {
      next
    }
    report <- f[["report"]]
    report[["results"]][[i]][["app"]][[field]] <- list("unrelated")
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  mismatch <- which(vapply(
    report[["results"]],
    function(row) {
      identical(row[["module"]], "oidcc-client-test-userinfo-invalid-sub")
    },
    logical(1)
  ))
  report[["results"]][[mismatch]][["app"]][["operations"]][[
    "audit_token_exchange"
  ]] <- 0L
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("partial, duplicate and unrelated results cannot pass", {
  f <- evidence_fixture()
  for (indices in list(
    integer(),
    1L,
    c(1L, 2L),
    c(1L, 1L, 3L),
    c(1L, 2L, 3L, 3L)
  )) {
    report <- f[["report"]]
    report[["results"]] <- report[["results"]][indices]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[1L]][["module"]] <- "unrelated"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("run, checkout, suite, plan and variants stay bound to the attempt", {
  f <- evidence_fixture()
  for (name in c(
    "run_id",
    "attempt_id",
    "checkout_revision",
    "source_revision",
    "plan_id"
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][[name]] <- "stale"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
    report <- f[["report"]]
    report[[name]] <- "stale"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[2L]][["suite_id"]] <- report[["results"]][[1L]][[
    "suite_id"
  ]]
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  report <- f[["report"]]
  report[["results"]][[1L]][["variant"]][["response_type"]] <- "id_token"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("lifecycle completion and a passing verdict are both required", {
  f <- evidence_fixture()
  for (status in c("WAITING", "CREATED", "INTERRUPTED", "unknown")) {
    report <- f[["report"]]
    report[["results"]][[1L]][["suite_status"]] <- status
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (verdict in list(
    NULL,
    list(),
    "FAILED",
    "WARNING",
    "REVIEW",
    "SKIPPED"
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][["suite_result"]] <- verdict
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[1L]][["exception"]] <- "unexpected exception"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("a timeout or unrelated app failure cannot satisfy a negative case", {
  f <- evidence_fixture()
  for (name in c("app", "suite_id")) {
    report <- f[["report"]]
    report[["results"]][[2L]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c(
    "run_id",
    "package_version",
    "error_code",
    "error_classes",
    "claims"
  )) {
    report <- f[["report"]]
    report[["results"]][[2L]][["app"]][[name]] <- "unrelated"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c(
    "authenticated",
    "has_token",
    "id_token_validated",
    "userinfo_present"
  )) {
    report <- f[["report"]]
    report[["results"]][[2L]][["app"]][[name]] <- TRUE
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["cleanup_verified"]] <- FALSE
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  report <- f[["report"]]
  report[["results"]][[1L]][["app"]][["operations"]][["audit_userinfo"]] <- "1"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("the real app failure control cannot be omitted", {
  f <- evidence_fixture()
  f[["report"]][["driver_failure_control_passed"]] <- FALSE
  testthat::expect_false(openid_check_report(
    f[["report"]],
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("browser navigation evidence cannot be omitted", {
  f <- evidence_fixture()
  for (name in c("callback_cleaned", "browser_version")) {
    report <- f[["report"]]
    report[["results"]][[1L]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("module polling rejects stale records, interruptions and request failures", {
  manifest <- openid_profiles("../..")
  module <- list(
    id = "instance",
    name = "oidcc-client-test",
    plan_id = "plan",
    variant = utils::modifyList(
      manifest[["plan_variant"]],
      manifest[["module_variant"]]
    )
  )
  info <- list(
    testId = module[["id"]],
    testName = module[["name"]],
    planId = "plan",
    variant = module[["variant"]],
    status = "WAITING"
  )
  request <- function(...) info
  testthat::expect_identical(
    openid_suite_wait(list(), module, "WAITING", .request = request),
    info
  )
  info[["testId"]] <- "old"
  testthat::expect_error(
    openid_suite_wait(list(), module, "WAITING", .request = request),
    "identity"
  )
  info[["testId"]] <- module[["id"]]
  info[["status"]] <- "INTERRUPTED"
  testthat::expect_error(
    openid_suite_wait(list(), module, "WAITING", .request = request),
    "ended before"
  )
  info[["status"]] <- "CREATED"
  testthat::expect_error(
    openid_suite_wait(list(), module, "WAITING", 0, request),
    "Timed out"
  )
  calls <- 0L
  request <- function(...) {
    calls <<- calls + 1L
    stop(structure(
      list(message = "Unauthorized", call = NULL, status = 401L),
      class = c("openid_http_error", "error", "condition")
    ))
  }
  testthat::expect_error(
    openid_suite_wait(list(), module, "WAITING", .request = request),
    class = "openid_http_error"
  )
  testthat::expect_identical(calls, 1L)
})
