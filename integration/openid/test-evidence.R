evidence_fixture <- function(profile = "smoke") {
  manifest <- openid_profiles("../..")
  spec <- openid_plan_spec(manifest, profile)
  context <- list(
    schema_version = 2L,
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
        spec[["plan_variant"]],
        spec[["module_variant"]]
      )
      row[["suite_status"]] <- "FINISHED"
      row[["suite_result"]] <- if (is.null(expected[["suite_result"]])) {
        "PASSED"
      } else {
        expected[["suite_result"]]
      }
      row[["callback_cleaned"]] <- TRUE
      row[["action"]] <- "login"
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

testthat::test_that("fixture key-ID digests serialize as plain JSON strings", {
  fixture <- new.env(parent = baseenv())
  sys.source("fixture-app.R", fixture)
  digest <- fixture[["openid_fixture_digest"]]("public-key-id")
  testthat::expect_type(digest, "character")
  testthat::expect_null(attr(digest, "class"))
  testthat::expect_match(digest, "^[a-f0-9]{64}$")
  encoded <- jsonlite::toJSON(list(key_id = digest), auto_unbox = TRUE)
  testthat::expect_identical(jsonlite::fromJSON(encoded)[["key_id"]], digest)
})

form_post_fixture <- function() {
  f <- evidence_fixture("form-post")
  for (name in c("provider_origin", "app_origin")) {
    value <- if (name == "provider_origin") {
      "https://localhost:41000"
    } else {
      "https://localhost:42000"
    }
    f[["context"]][[name]] <- f[["report"]][[name]] <- value
  }
  for (i in seq_along(f[["report"]][["results"]])) {
    row <- f[["report"]][["results"]][[i]]
    row[["form_post"]] <- list(
      provider_origin = f[["context"]][["provider_origin"]],
      app_origin = f[["context"]][["app_origin"]],
      authorization_method = "GET",
      callback_method = "POST",
      bridge_redirect_303 = TRUE,
      secure_context = TRUE,
      cross_origin = TRUE,
      cross_site = FALSE,
      cookie = list(
        binding_cookie_count = 1L,
        secure = TRUE,
        same_site = "Strict",
        http_only = FALSE
      )
    )
    row[["app"]][["form_post"]] <- list(
      method = "POST",
      origin_matched = TRUE,
      sec_fetch_site = "same-site",
      form_urlencoded = TRUE
    )
    row[["app"]][["operations"]][["audit_callback_validation_success"]] <- 1L
    f[["report"]][["results"]][[i]] <- row
  }
  f
}

testthat::test_that("Form Post coverage requires all pinned modules and the response-mode variant", {
  f <- form_post_fixture()
  spec <- openid_plan_spec(f[["manifest"]], "form-post")
  testthat::expect_identical(
    spec[["plan"]],
    "oidcc-client-formpost-basic-certification-test-plan"
  )
  testthat::expect_identical(
    spec[["module_variant"]][["response_mode"]],
    "form_post"
  )
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
  }
  report <- f[["report"]]
  report[["results"]][[1L]][["variant"]][["response_mode"]] <- "default"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("Form Post cannot pass with GET callbacks, missing bridge evidence or stale origins", {
  f <- form_post_fixture()
  for (change in list(
    list(name = "authorization_method", value = "POST"),
    list(name = "callback_method", value = "GET"),
    list(name = "bridge_redirect_303", value = FALSE),
    list(name = "secure_context", value = FALSE),
    list(name = "cross_origin", value = FALSE),
    list(name = "cross_site", value = TRUE),
    list(name = "provider_origin", value = "https://localhost:43000"),
    list(name = "app_origin", value = "https://localhost:44000")
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][["form_post"]][[change[["name"]]]] <- change[[
      "value"
    ]]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c("provider_origin", "app_origin")) {
    report <- f[["report"]]
    report[[name]] <- "https://localhost:45000"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[2L]][["form_post"]] <- NULL
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("Form Post requires browser site headers, Secure Strict binding cookies and state validation", {
  f <- form_post_fixture()
  for (change in list(
    list(name = "method", value = "GET"),
    list(name = "origin_matched", value = FALSE),
    list(name = "form_urlencoded", value = FALSE),
    list(name = "sec_fetch_site", value = NULL),
    list(name = "sec_fetch_site", value = "none")
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][["app"]][["form_post"]][[change[[
      "name"
    ]]]] <- change[["value"]]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (change in list(
    list(name = "secure", value = FALSE),
    list(name = "same_site", value = "None"),
    list(name = "binding_cookie_count", value = 0L)
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][["form_post"]][["cookie"]][[change[[
      "name"
    ]]]] <- change[["value"]]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[1L]][["app"]][["operations"]][[
    "audit_callback_validation_success"
  ]] <- 0L
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  report <- f[["report"]]
  report[["results"]][[1L]][["app"]][["form_post"]][[
    "sec_fetch_site"
  ]] <- "cross-site"
  report[["results"]][[1L]][["form_post"]][["cross_site"]] <- TRUE
  testthat::expect_true(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

configuration_fixture <- function() {
  f <- evidence_fixture("config")
  f[["report"]][["jwks_cache_policy"]] <- list(
    no_store = TRUE,
    source_revision = f[["context"]][["source_revision"]],
    suite_id = "probe"
  )
  expected <- f[["manifest"]][["profiles"]][["config"]][["modules"]]
  for (i in seq_along(expected)) {
    expectation <- expected[[i]]
    row <- f[["report"]][["results"]][[i]]
    app <- row[["app"]]
    app[["app_instance"]] <- paste0("app", i)
    app[["cache_instance"]] <- paste0("cache", i)
    app[["discovery_issuer_exact"]] <- TRUE
    app[["cache_updates"]] <- 0L
    app[["cache_hits"]] <- 0L
    app[["prefetch_completed"]] <- isTRUE(expectation[["preload_jwks"]])
    app[["prefetched_key_ids"]] <- list("original-key-id-digest")
    app[["token_key_id_digest"]] <- "first-key-id-digest"
    app[["session_number"]] <- 2L
    if (identical(expectation[["action"]], "discovery")) {
      rejected <- identical(expectation[["outcome"]], "discovery_rejected")
      row[["action"]] <- "discovery"
      row[["callback_cleaned"]] <- NULL
      row[["no_callback"]] <- TRUE
      app[["ready"]] <- !rejected
      app[["discovery_issuer_exact"]] <- !rejected
      app[["error_code"]] <- if (rejected) "discovery_setup_error" else NULL
      app[["error_classes"]] <- if (rejected) {
        list("shinyOAuth_config_error")
      } else {
        list()
      }
      app[["claims"]] <- if (rejected) list("iss") else list()
      app[["reasons"]] <- if (rejected) {
        list("discovery_issuer_mismatch")
      } else {
        list()
      }
      app[["operations"]][["audit_token_exchange"]] <- 0L
    }
    if (isTRUE(expectation[["rotation_required"]])) {
      initial <- app
      initial[c(
        "authenticated",
        "has_token",
        "id_token_validated",
        "userinfo_present"
      )] <- rep(list(FALSE), 4L)
      initial[["operations"]] <- list(
        audit_token_exchange = 0L,
        audit_userinfo = 0L,
        audit_login_success = 0L
      )
      row[["initial"]] <- initial
      row[["initial"]][["session_number"]] <- 1L
      if (isTRUE(expectation[["preload_jwks"]])) {
        app[["token_key_id_digest"]] <- "rotated-key-id-digest"
        row[["steps"]] <- list(app)
        row[["between_logins"]] <- list()
      } else {
        first <- app
        app[["operations"]] <- list(
          audit_token_exchange = 2L,
          audit_userinfo = 2L,
          audit_login_success = 2L
        )
        app[["token_key_id_digest"]] <- "rotated-key-id-digest"
        app[["session_number"]] <- 3L
        row[["steps"]] <- list(first, app)
        between <- initial
        between[["operations"]] <- first[["operations"]]
        between[["error_code"]] <- "logged_out"
        row[["between_logins"]] <- list(between)
      }
    }
    row[["app"]] <- app
    f[["report"]][["results"]][[i]] <- row
  }
  f
}

testthat::test_that("Configuration coverage explicitly includes both upstream-ignored rotation modules", {
  f <- configuration_fixture()
  spec <- openid_plan_spec(f[["manifest"]], "config")
  testthat::expect_identical(
    spec[["plan"]],
    "oidcc-client-config-certification-test-plan"
  )
  testthat::expect_length(spec[["available_modules"]], 6L)
  testthat::expect_length(spec[["explicit_modules"]], 2L)
  check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_true(check[["selection_complete"]])
  testthat::expect_false(check[["coverage_complete"]])
  testthat::expect_identical(
    unlist(check[["coverage_limitations"]]),
    "suite_jwks_no_store_prevents_cached_key_refresh_test"
  )
  for (i in seq_along(f[["report"]][["results"]])) {
    report <- f[["report"]]
    report[["results"]] <- report[["results"]][-i]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[1L]][["variant"]][["client_auth_type"]] <- "none"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("discovery-only results require their own outcome and issuer evidence", {
  f <- configuration_fixture()
  for (change in list(
    list(i = 1L, name = "authenticated", value = TRUE),
    list(i = 1L, name = "discovery_issuer_exact", value = FALSE),
    list(i = 2L, name = "prefetch_completed", value = FALSE),
    list(i = 2L, name = "prefetch_completed", value = NULL),
    list(i = 3L, name = "reasons", value = list("unrelated")),
    list(i = 3L, name = "claims", value = list("aud")),
    list(
      i = 3L,
      name = "error_classes",
      value = list("shinyOAuth_parse_error")
    ),
    list(i = 3L, name = "ready", value = TRUE)
  )) {
    report <- f[["report"]]
    report[["results"]][[change[["i"]]]][["app"]][[change[[
      "name"
    ]]]] <- change[["value"]]
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c("action", "no_callback")) {
    report <- f[["report"]]
    report[["results"]][[1L]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("rotation requires retained app/cache, fresh keys and every successful login", {
  f <- configuration_fixture()
  for (i in c(5L, 6L)) {
    for (change in list(
      list(name = "app_instance", value = "restarted-app"),
      list(name = "cache_instance", value = "replacement-cache"),
      list(name = "token_key_id_digest", value = "original-key-id-digest"),
      list(name = "cache_updates", value = 1L),
      list(name = "cache_hits", value = 1L)
    )) {
      report <- f[["report"]]
      row <- report[["results"]][[i]]
      last <- length(row[["steps"]])
      value <- change[["value"]]
      if (i == 6L && change[["name"]] == "token_key_id_digest") {
        value <- row[["steps"]][[1L]][["token_key_id_digest"]]
      }
      row[["steps"]][[last]][[change[["name"]]]] <- value
      row[["app"]] <- row[["steps"]][[last]]
      report[["results"]][[i]] <- row
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    report <- f[["report"]]
    report[["results"]][[i]][["steps"]] <- list()
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c("prefetch_completed", "prefetched_key_ids")) {
    report <- f[["report"]]
    report[["results"]][[5L]][["initial"]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c("between_logins", "initial")) {
    report <- f[["report"]]
    report[["results"]][[6L]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  row <- report[["results"]][[6L]]
  row[["steps"]][[2L]][["operations"]][["audit_token_exchange"]] <- 1L
  row[["app"]] <- row[["steps"]][[2L]]
  report[["results"]][[6L]] <- row
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("Configuration cannot hide the no-store limitation or omit its live policy probe", {
  f <- configuration_fixture()
  manifest <- f[["manifest"]]
  manifest[["profiles"]][["config"]][["complete_profile"]] <- TRUE
  manifest[["profiles"]][["config"]][["coverage_limitations"]] <- NULL
  check <- openid_check_report(f[["report"]], f[["context"]], manifest)
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_false(check[["coverage_complete"]])
  testthat::expect_false(check[["cached_key_refresh_tested"]])
  testthat::expect_identical(
    unlist(check[["coverage_limitations"]]),
    "suite_jwks_no_store_prevents_cached_key_refresh_test"
  )
  for (name in c("jwks_cache_policy")) {
    report <- f[["report"]]
    report[[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (name in c("no_store", "source_revision", "suite_id")) {
    report <- f[["report"]]
    report[["jwks_cache_policy"]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
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
  spec <- openid_plan_spec(manifest, "smoke")
  module <- list(
    id = "instance",
    name = "oidcc-client-test",
    plan_id = "plan",
    variant = utils::modifyList(
      spec[["plan_variant"]],
      spec[["module_variant"]]
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
