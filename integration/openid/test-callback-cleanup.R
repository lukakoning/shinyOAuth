callback_cleanup_upgrade <- function(f) {
  f[["context"]][["callback_rejection_policy"]] <- "opaque_error_v1"
  f[["report"]][["callback_rejection_policy"]] <- "opaque_error_v1"
  for (i in seq_along(f[["report"]][["results"]])) {
    row <- f[["report"]][["results"]][[i]]
    if (is.null(row[["callback_http"]])) {
      next
    }
    row[["callback_cleaned"]] <- TRUE
    row[["callback_http"]] <- c(
      row[["callback_http"]],
      list(
        schema_version = 2L,
        policy = "opaque_error_v1",
        redirect_status = 303L,
        redirect_headers_verified = TRUE,
        redirect_credentials_absent = TRUE,
        redirect_chain_verified = TRUE,
        final_url_verified = TRUE,
        final_request_no_referrer = TRUE,
        pending_state_preserved = TRUE
      )
    )
    f[["report"]][["results"]][[i]] <- row
  }
  f
}

callback_cleanup_fixtures <- function() {
  list(
    oidc = fapi_full_fixture("sync"),
    oauth = fapi_full_fixture("mirai", "fapi-oauth-dpop-reference"),
    mtls = mtls_evidence_fixture("sync", "fapi-mtls-auth"),
    signing = signing_report_fixture("mirai")
  )
}

callback_cleanup_check <- function(
  f,
  report = f[["report"]],
  context = f[["context"]]
) {
  openid_check_report(report, context, f[["manifest"]])
}

callback_cleanup_indices <- function(f) {
  which(vapply(
    f[["report"]][["results"]],
    function(row) {
      !is.null(row[["callback_http"]])
    },
    logical(1)
  ))
}

testthat::test_that("opaque rejection proof replaces only the validated callback limitation", {
  limitation <- "http_callback_rejection_retains_query"
  for (legacy in callback_cleanup_fixtures()) {
    old <- callback_cleanup_check(legacy)
    testthat::expect_true(old[["gate_passed"]], info = old[["reason"]])
    testthat::expect_true(limitation %in% unlist(old[["coverage_limitations"]]))
    testthat::expect_true(
      limitation %in%
        unlist(
          old[["assessment"]][["limitations"]][["client_limitations"]]
        )
    )
    current <- callback_cleanup_upgrade(legacy)
    indices <- callback_cleanup_indices(current)
    testthat::expect_gt(length(indices), 0L)
    validated <- callback_cleanup_check(current)
    testthat::expect_true(
      validated[["gate_passed"]],
      info = validated[["reason"]]
    )
    testthat::expect_false(
      limitation %in% unlist(validated[["coverage_limitations"]])
    )
    testthat::expect_length(
      validated[["assessment"]][["limitations"]][["client_limitations"]],
      0L
    )
    testthat::expect_setequal(
      unlist(validated[["coverage_limitations"]]),
      setdiff(unlist(old[["coverage_limitations"]]), limitation)
    )
    testthat::expect_identical(
      validated[["upstream_plan_complete"]],
      old[["upstream_plan_complete"]]
    )
    testthat::expect_identical(
      validated[["assessment"]][["suite_verdict_counts"]],
      old[["assessment"]][["suite_verdict_counts"]]
    )
    # Each rejected callback needs its own proof, including late modules.
    for (i in indices) {
      report <- current[["report"]]
      report[["results"]][[i]][["callback_http"]][[
        "final_url_verified"
      ]] <- FALSE
      failed <- callback_cleanup_check(current, report)
      testthat::expect_false(
        failed[["gate_passed"]],
        info = paste(i, "per-callback proof")
      )
      testthat::expect_identical(
        failed[["assessment"]][["status"]],
        "unavailable"
      )
    }
  }
})

testthat::test_that("cleanup proof requires every redirect, privacy and pending-state observation", {
  flags <- c(
    "redirect_headers_verified",
    "redirect_credentials_absent",
    "redirect_chain_verified",
    "final_url_verified",
    "final_request_no_referrer",
    "pending_state_preserved",
    "no_store",
    "no_referrer",
    "plain_text",
    "credentials_absent",
    "body_matches",
    "browser_status_400",
    "headers_verified",
    "no_callback_module"
  )
  for (f in lapply(callback_cleanup_fixtures(), callback_cleanup_upgrade)) {
    i <- callback_cleanup_indices(f)[[1L]]
    for (name in flags) {
      for (replacement in list(NULL, FALSE)) {
        report <- f[["report"]]
        report[["results"]][[i]][["callback_http"]][[name]] <- replacement
        failed <- callback_cleanup_check(f, report)
        testthat::expect_false(
          failed[["gate_passed"]],
          info = paste(f[["context"]][["profile"]], name)
        )
        testthat::expect_false(failed[["selection_complete"]])
      }
    }
    for (replacement in list(NULL, FALSE, 1L)) {
      report <- f[["report"]]
      report[["results"]][[i]][["callback_cleaned"]] <- replacement
      testthat::expect_false(callback_cleanup_check(f, report)[["gate_passed"]])
    }
    for (replacement in list(NULL, 302L, 307L, "303")) {
      report <- f[["report"]]
      report[["results"]][[i]][["callback_http"]][[
        "redirect_status"
      ]] <- replacement
      testthat::expect_false(callback_cleanup_check(f, report)[["gate_passed"]])
    }
    for (name in c(
      "token_request_count",
      "userinfo_request_count",
      "resource_request_count"
    )) {
      report <- f[["report"]]
      report[["results"]][[i]][["fapi"]][[name]] <- 1L
      testthat::expect_false(
        callback_cleanup_check(f, report)[["gate_passed"]],
        info = name
      )
    }
    for (name in c(
      "audit_token_exchange",
      "audit_userinfo",
      "audit_login_success"
    )) {
      report <- f[["report"]]
      report[["results"]][[i]][["app"]][["operations"]][[name]] <- 1L
      testthat::expect_false(
        callback_cleanup_check(f, report)[["gate_passed"]],
        info = name
      )
    }
  }
})

testthat::test_that("cleanup policy binds context and report and cannot downgrade to legacy proof", {
  for (legacy in callback_cleanup_fixtures()) {
    f <- callback_cleanup_upgrade(legacy)
    i <- callback_cleanup_indices(f)[[1L]]
    for (name in c("schema_version", "policy")) {
      replacements <- if (name == "schema_version") {
        list(NULL, 1L, 3L, "2")
      } else {
        list(NULL, "legacy", "opaque_error_v2")
      }
      for (replacement in replacements) {
        report <- f[["report"]]
        report[["results"]][[i]][["callback_http"]][[name]] <- replacement
        testthat::expect_false(
          callback_cleanup_check(f, report)[["gate_passed"]],
          info = name
        )
      }
    }
    for (side in c("report", "context")) {
      for (replacement in list(NULL, "legacy", "opaque_error_v2")) {
        changed <- f
        changed[[side]][["callback_rejection_policy"]] <- replacement
        testthat::expect_false(
          callback_cleanup_check(changed)[["gate_passed"]],
          info = side
        )
      }
    }
    changed <- f
    changed[["report"]][["callback_rejection_policy"]] <- "opaque_error_v2"
    changed[["context"]][["callback_rejection_policy"]] <- "opaque_error_v2"
    testthat::expect_false(callback_cleanup_check(changed)[["gate_passed"]])
    # Keeping a clean flag without the redirect evidence cannot earn credit.
    report <- f[["report"]]
    report[["results"]][[i]] <- legacy[["report"]][["results"]][[i]]
    report[["results"]][[i]][["callback_cleaned"]] <- TRUE
    testthat::expect_false(callback_cleanup_check(f, report)[["gate_passed"]])
    report[["results"]][[i]][["callback_cleaned"]] <- FALSE
    testthat::expect_false(callback_cleanup_check(f, report)[["gate_passed"]])
    # A legacy context accepts only legacy proof, irrespective of forged output.
    legacy[["report"]][["assessment"]] <- list(
      status = "validated",
      limitations = list()
    )
    legacy[["report"]][["coverage_limitations"]] <- list()
    old <- callback_cleanup_check(legacy)
    testthat::expect_true(old[["gate_passed"]])
    testthat::expect_true(
      "http_callback_rejection_retains_query" %in%
        unlist(old[["coverage_limitations"]])
    )
    forged <- legacy[["report"]]
    forged[["results"]][[i]][["callback_cleaned"]] <- TRUE
    testthat::expect_false(callback_cleanup_check(legacy, forged)[[
      "gate_passed"
    ]])
    testthat::expect_false(callback_cleanup_check(
      f,
      context = legacy[["context"]]
    )[["gate_passed"]])
    changed <- f
    changed[["context"]][["callback_rejection_policy"]] <- NULL
    changed[["report"]][["callback_rejection_policy"]] <- NULL
    testthat::expect_false(callback_cleanup_check(changed)[["gate_passed"]])
    for (j in callback_cleanup_indices(changed)) {
      changed[["report"]][["results"]][[j]][["callback_cleaned"]] <- FALSE
      changed[["report"]][["results"]][[j]][["callback_http"]][[
        "schema_version"
      ]] <- NULL
      changed[["report"]][["results"]][[j]][["callback_http"]][[
        "policy"
      ]] <- NULL
    }
    downgraded <- callback_cleanup_check(changed)
    testthat::expect_false(downgraded[["gate_passed"]])
    new_names <- setdiff(
      names(f[["report"]][["results"]][[i]][["callback_http"]]),
      names(legacy[["report"]][["results"]][[i]][["callback_http"]])
    )
    for (name in new_names) {
      for (replacement in list(
        NULL,
        f[["report"]][["results"]][[i]][["callback_http"]][[name]]
      )) {
        report <- legacy[["report"]]
        # Keep even explicit null-valued keys, as JSON decoding does.
        report[["results"]][[i]][["callback_http"]][name] <- list(replacement)
        testthat::expect_false(
          callback_cleanup_check(legacy, report)[["gate_passed"]],
          info = name
        )
      }
    }
  }
})

testthat::test_that("shared reports propagate the trusted cleanup policy to every selection", {
  f <- shared_evidence_fixture()
  check <- function(report, context = f[["context"]]) {
    openid_check_shared_report(report, context, f[["manifest"]])[[
      "gate_passed"
    ]]
  }
  testthat::expect_true(check(f[["report"]]))
  f[["context"]][["callback_rejection_policy"]] <- "opaque_error_v1"
  f[["report"]][["callback_rejection_policy"]] <- "opaque_error_v1"
  for (i in seq_along(f[["report"]][["selections"]])) {
    f[["report"]][["selections"]][[i]][[
      "callback_rejection_policy"
    ]] <- "opaque_error_v1"
  }
  testthat::expect_true(check(f[["report"]]))
  for (i in seq_along(f[["report"]][["selections"]])) {
    report <- f[["report"]]
    report[["selections"]][[i]][["callback_rejection_policy"]] <- NULL
    testthat::expect_false(check(report), info = paste("selection", i))
  }
  report <- f[["report"]]
  report[["callback_rejection_policy"]] <- NULL
  testthat::expect_false(check(report))
  context <- f[["context"]]
  context[["callback_rejection_policy"]] <- NULL
  testthat::expect_false(check(f[["report"]], context))
})

testthat::test_that("error continuation URLs contain only an exact origin root and opaque handle", {
  origin <- "https://localhost:44263"
  handle <- paste0("ce1_", strrep("a", 41L), "-_")
  url <- paste0(origin, "/?shinyOAuth_callback_error=", handle)
  for (valid in c(url, paste0(url, "#"))) {
    testthat::expect_true(openid_error_continuation_url(valid, origin))
  }
  invalid <- c(
    sub("https:", "http:", url, fixed = TRUE),
    sub("localhost", "LOCALHOST", url, fixed = TRUE),
    sub("44263", "44264", url, fixed = TRUE),
    sub("localhost", "localhost.attacker.example", url, fixed = TRUE),
    sub("localhost", "attacker.example@localhost", url, fixed = TRUE),
    sub("localhost", "localhost@attacker.example", url, fixed = TRUE),
    sub("/?", "/callback?", url, fixed = TRUE),
    sub("/?", "/./?", url, fixed = TRUE),
    sub("/?", "//?", url, fixed = TRUE),
    sub("/?", "?", url, fixed = TRUE),
    sub(
      "shinyOAuth_callback_error",
      "ShinyOAuth_callback_error",
      url,
      fixed = TRUE
    ),
    sub(
      "shinyOAuth_callback_error",
      "shinyOAuth%5fcallback_error",
      url,
      fixed = TRUE
    ),
    paste0(url, "&state=secret"),
    paste0(url, "&"),
    paste0(url, ";code=secret"),
    paste0(url, "&shinyOAuth_callback_error=", handle),
    paste0(url, "#secret"),
    paste0(url, "##"),
    paste0(url, "%23"),
    paste0(url, "/"),
    paste0(url, " "),
    paste0(url, "\n"),
    sub("ce1_", "ce2_", url, fixed = TRUE),
    sub("ce1_", "ce1_%61", url, fixed = TRUE),
    substring(url, 1L, nchar(url) - 1L),
    paste0(url, "a"),
    sub("-_", "+/", url, fixed = TRUE),
    "",
    NA_character_
  )
  for (value in invalid) {
    testthat::expect_false(
      openid_error_continuation_url(value, origin),
      info = value
    )
  }
  testthat::expect_false(openid_error_continuation_url(NULL, origin))
})

testthat::test_that("CDP callback observations exclude subframes and unrelated origins", {
  callbacks <- new.env(parent = emptyenv())
  enabled <- 0L
  tab <- list(
    Page = list(getFrameTree = function() {
      list(frameTree = list(frame = list(id = "main")))
    }),
    Network = list(
      enable = function() {
        enabled <<- enabled + 1L
      },
      requestWillBeSent = function(callback) {
        callbacks[["request"]] <- callback
      },
      responseReceived = function(callback) {
        callbacks[["response"]] <- callback
      }
    )
  )
  origin <- "https://localhost:44263"
  target <- paste0(origin, "/?shinyOAuth_callback_error=ce1_", strrep("a", 43L))
  observed <- openid_observe_http_callback(tab, origin)
  testthat::expect_identical(enabled, 1L)
  redirect <- list(
    type = "Document",
    frameId = "main",
    requestId = "chain",
    redirectResponse = list(
      url = paste0(origin, "/?state=secret"),
      status = 303,
      headers = list(
        "Cache-Control" = "no-store",
        "Referrer-Policy" = "no-referrer"
      )
    ),
    request = list(url = target, headers = list())
  )
  final <- list(
    type = "Document",
    frameId = "main",
    requestId = "chain",
    response = list(
      url = target,
      status = 400,
      headers = list("Cache-Control" = "no-store")
    )
  )
  for (name in c("type", "frameId")) {
    bad_redirect <- redirect
    bad_final <- final
    bad_redirect[[name]] <- bad_final[[name]] <- if (name == "type") {
      "Fetch"
    } else {
      "subframe"
    }
    callbacks[["request"]](bad_redirect)
    callbacks[["response"]](bad_final)
    testthat::expect_length(as.list(observed), 0L)
  }
  bad_redirect <- redirect
  bad_redirect[["request"]][["url"]] <- paste0(target, "&code=secret")
  callbacks[["request"]](bad_redirect)
  bad_final <- final
  bad_final[["response"]][["url"]] <- "https://attacker.example/"
  callbacks[["response"]](bad_final)
  testthat::expect_length(as.list(observed), 0L)
  callbacks[["request"]](redirect)
  callbacks[["response"]](final)
  testthat::expect_identical(
    observed[["redirect_id"]],
    observed[["request_id"]]
  )
  testthat::expect_identical(observed[["redirect_target"]], observed[["url"]])
  testthat::expect_identical(observed[["redirect_status"]], 303L)
  testthat::expect_identical(observed[["status"]], 400)
  testthat::expect_identical(observed[["redirect_request_headers"]], list())
  # The observer retains both IDs for the collector to reject a different chain.
  final[["requestId"]] <- "unrelated-chain"
  callbacks[["response"]](final)
  testthat::expect_false(identical(
    observed[["redirect_id"]],
    observed[["request_id"]]
  ))
})

testthat::test_that("HTTP rejection collection binds terminal document, redirect chain and rendered body", {
  origin <- "https://localhost:44263"
  target <- paste0(origin, "/?shinyOAuth_callback_error=ce1_", strrep("a", 43L))
  content <- "The OAuth callback was rejected."
  rendered <- content
  href <- target
  directory <- withr::local_tempdir()
  initial <- list(
    session_number = 1L,
    app_instance = "app",
    cache_instance = "cache"
  )
  snapshot <- c(
    list(run_id = "run"),
    initial,
    list(
      http_rejection = list(
        content_digest = paste(
          openssl::sha256(charToRaw(content)),
          collapse = ""
        ),
        redirect_credentials_absent = TRUE,
        final_request_no_referrer = TRUE,
        pending_state_preserved = TRUE
      )
    )
  )
  jsonlite::write_json(
    snapshot,
    file.path(directory, "callback-http.json"),
    auto_unbox = TRUE
  )
  process <- list(is_alive = function() TRUE)
  app <- list(
    origin = origin,
    process = process,
    config = list(run_id = "run", audit_directory = directory)
  )
  browser <- list(get_browser = function() {
    list(get_process = function() process)
  })
  observation <- new.env(parent = emptyenv())
  headers <- list(
    "Cache-Control" = "no-store",
    "Referrer-Policy" = "no-referrer",
    "Content-Type" = "text/plain"
  )
  original <- list(
    request_id = "chain",
    redirect_id = "chain",
    status = 400L,
    redirect_status = 303L,
    headers = headers,
    redirect_headers = headers,
    redirect_request_headers = list(),
    url = target,
    redirect_target = target
  )
  reset <- function() list2env(original, envir = observation)
  reset()
  rlang::local_bindings(
    openid_wait = function(fn, ...) fn(),
    openid_browser_value = function(tab, expression) {
      if (identical(expression, "location.href")) href else rendered
    },
    openid_app_snapshot = function(...) NULL,
    .env = environment(openid_wait_http_callback)
  )
  collect <- function() {
    openid_wait_http_callback(app, browser, list(), initial, observation)
  }
  result <- collect()
  testthat::expect_true(result[["http"]][["redirect_chain_verified"]])
  testthat::expect_true(result[["http"]][["final_url_verified"]])
  testthat::expect_true(result[["http"]][["body_matches"]])
  testthat::expect_true(result[["http"]][["final_request_no_referrer"]])
  href <- paste0(target, "#")
  testthat::expect_true(collect()[["http"]][["final_url_verified"]])
  # A different valid opaque page must not satisfy the observed navigation.
  href <- sub(strrep("a", 43L), strrep("b", 43L), target, fixed = TRUE)
  testthat::expect_null(collect())
  href <- target
  observation[["request_id"]] <- "unrelated-chain"
  testthat::expect_null(collect())
  reset()
  observation[["url"]] <- sub(
    strrep("a", 43L),
    strrep("b", 43L),
    target,
    fixed = TRUE
  )
  testthat::expect_null(collect())
  reset()
  observation[["status"]] <- 200L
  testthat::expect_null(collect())
  reset()
  rendered <- "Loading the redirected document"
  testthat::expect_null(collect())
  rendered <- content
  testthat::expect_true(collect()[["http"]][["body_matches"]])
  observation[["redirect_request_headers"]] <- list(
    Referer = "sensitive-callback"
  )
  testthat::expect_false(collect()[["http"]][["final_request_no_referrer"]])
  reset()
  for (server_value in list(FALSE, NULL)) {
    snapshot[["http_rejection"]][["final_request_no_referrer"]] <- server_value
    jsonlite::write_json(
      snapshot,
      file.path(directory, "callback-http.json"),
      auto_unbox = TRUE
    )
    testthat::expect_false(collect()[["http"]][["final_request_no_referrer"]])
  }
})
