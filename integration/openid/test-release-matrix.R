release_matrix_test_matrix <- function(selections) {
  list(
    schema_version = 1L,
    id = "oidf-client-selections-v1",
    callback_rejection_policy = "opaque_error_v1",
    selections = lapply(selections, function(x) {
      list(profile = x[[1L]], transport = x[[2L]])
    })
  )
}

release_matrix_test_store_check <- function(report, check) {
  for (name in names(check)) {
    report[[name]] <- check[[name]]
  }
  report
}

release_matrix_test_report <- function(f = evidence_fixture(), cleanup = TRUE) {
  if (cleanup) {
    f <- callback_cleanup_upgrade(f)
  }
  f <- source_evidence_fixture(f)
  f[["report"]][["regression_installation_after"]] <- f[["report"]][[
    "installation"
  ]]
  shared <- identical(f[["report"]][["profile"]], "shared-pool")
  if (shared) {
    for (i in seq_along(f[["report"]][["selections"]])) {
      child <- f[["report"]][["selections"]][[i]]
      if (cleanup) {
        child[["callback_rejection_policy"]] <- "opaque_error_v1"
      }
      child[["regression_installation_after"]] <- child[["installation"]]
      check <- openid_check_report(child, child, f[["manifest"]])
      stopifnot(isTRUE(check[["gate_passed"]]))
      f[["report"]][["selections"]][[i]] <- release_matrix_test_store_check(
        child,
        check
      )
    }
    check <- openid_check_shared_report(
      f[["report"]],
      f[["context"]],
      f[["manifest"]]
    )
  } else {
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
  }
  stopifnot(isTRUE(check[["gate_passed"]]))
  release_matrix_test_store_check(f[["report"]], check)
}

release_matrix_test_fixture <- function() {
  f <- evidence_fixture()
  reports <- list(
    release_matrix_test_report(f),
    release_matrix_test_report(evidence_with_transport(
      configuration_fixture(),
      "mirai"
    ))
  )
  list(
    manifest = f[["manifest"]],
    matrix = release_matrix_test_matrix(list(
      c("smoke", "sync"),
      c("config", "mirai")
    )),
    revision = reports[[1L]][["checkout_revision"]],
    tree = reports[[1L]][["checkout_source"]][["tree"]],
    archive = reports[[1L]][["installation"]][["archive_sha256"]],
    reports = reports
  )
}

release_matrix_test_check <- function(
  f,
  reports = f[["reports"]],
  matrix = f[["matrix"]]
) {
  openid_check_release(
    reports,
    matrix,
    f[["manifest"]],
    f[["revision"]],
    f[["tree"]],
    f[["archive"]]
  )
}

release_matrix_test_failed <- function(check, info = NULL) {
  testthat::expect_false(check[["gate_passed"]], info = info)
  testthat::expect_false(check[["matrix_complete"]], info = info)
  testthat::expect_identical(check[["certification_status"]], "not_assessed")
}

testthat::test_that("the declared default matrix covers supported profiles and transports explicitly", {
  manifest <- openid_profiles("../..")
  matrix <- openid_release_matrix("../..")
  testthat::expect_silent(openid_validate_release_matrix(matrix, manifest))
  actual <- vapply(
    matrix[["selections"]],
    function(x) {
      paste(x[["profile"]], x[["transport"]], sep = "/")
    },
    character(1)
  )
  expected <- c(
    unlist(
      lapply(names(manifest[["profiles"]]), function(profile) {
        paste(profile, c("sync", "mirai"), sep = "/")
      }),
      use.names = FALSE
    ),
    "shared-pool/mirai",
    "smoke/future",
    "refresh/future"
  )
  testthat::expect_setequal(actual, expected)
  testthat::expect_length(actual, length(expected))
  testthat::expect_false(anyDuplicated(actual) > 0L)
  testthat::expect_identical(
    matrix[["callback_rejection_policy"]],
    "opaque_error_v1"
  )
})

testthat::test_that("matrix validation rejects ambiguous cells and unsupported transport combinations", {
  f <- release_matrix_test_fixture()
  for (name in c(
    "schema_version",
    "id",
    "callback_rejection_policy",
    "selections"
  )) {
    matrix <- f[["matrix"]]
    matrix[[name]] <- NULL
    testthat::expect_error(
      openid_validate_release_matrix(matrix, f[["manifest"]]),
      info = name
    )
  }
  for (replacement in list(2L, "1", TRUE)) {
    matrix <- f[["matrix"]]
    matrix[["schema_version"]] <- replacement
    testthat::expect_error(openid_validate_release_matrix(
      matrix,
      f[["manifest"]]
    ))
  }
  for (cell in list(
    list(profile = "unknown", transport = "sync"),
    list(profile = "basic", transport = "future"),
    list(profile = "shared-pool", transport = "sync"),
    list(profile = "smoke", transport = "worker"),
    list(profile = "smoke"),
    list(transport = "sync"),
    list(profile = c("smoke", "basic"), transport = "sync")
  )) {
    matrix <- f[["matrix"]]
    matrix[["selections"]][[1L]] <- cell
    testthat::expect_error(openid_validate_release_matrix(
      matrix,
      f[["manifest"]]
    ))
  }
  matrix <- f[["matrix"]]
  matrix[["selections"]][[2L]] <- matrix[["selections"]][[1L]]
  testthat::expect_error(openid_validate_release_matrix(
    matrix,
    f[["manifest"]]
  ))
  matrix <- f[["matrix"]]
  matrix[["selections"]] <- list()
  testthat::expect_error(openid_validate_release_matrix(
    matrix,
    f[["manifest"]]
  ))
  matrix <- f[["matrix"]]
  names(matrix[["selections"]]) <- c("first", "second")
  testthat::expect_error(openid_validate_release_matrix(
    matrix,
    f[["manifest"]]
  ))
  matrix <- c(f[["matrix"]], list(id = "duplicate-id"))
  testthat::expect_error(openid_validate_release_matrix(
    matrix,
    f[["manifest"]]
  ))
  matrix <- f[["matrix"]]
  matrix[["selections"]][[1L]] <- c(
    matrix[["selections"]][[1L]],
    list(profile = "basic")
  )
  testthat::expect_error(openid_validate_release_matrix(
    matrix,
    f[["manifest"]]
  ))
  for (policy in list(
    "legacy",
    "opaque_error_v2",
    c("opaque_error_v1", "legacy")
  )) {
    matrix <- f[["matrix"]]
    matrix[["callback_rejection_policy"]] <- policy
    testthat::expect_error(openid_validate_release_matrix(
      matrix,
      f[["manifest"]]
    ))
  }
})

testthat::test_that("aggregate completeness preserves upstream and fixture limitations", {
  f <- release_matrix_test_fixture()
  before <- serialize(f, NULL)
  check <- release_matrix_test_check(f)
  testthat::expect_true(check[["gate_passed"]], info = check[["reason"]])
  testthat::expect_true(check[["matrix_complete"]])
  testthat::expect_equal(check[["selection_count"]], 2L)
  testthat::expect_equal(check[["required_count"]], 2L)
  testthat::expect_identical(check[["certification_status"]], "not_assessed")
  testthat::expect_false(check[["all_upstream_plans_complete"]])
  testthat::expect_false(check[["all_coverage_complete"]])
  testthat::expect_identical(serialize(f, NULL), before)
  testthat::expect_false(f[["reports"]][[1L]][["upstream_plan_complete"]])
  testthat::expect_false(f[["reports"]][[2L]][["coverage_complete"]])
  testthat::expect_true(f[["reports"]][[2L]][["upstream_plan_complete"]])
  testthat::expect_false(check[["entries"]][[1L]][["upstream_plan_complete"]])
  testthat::expect_true(check[["entries"]][[2L]][["upstream_plan_complete"]])
  testthat::expect_false(check[["entries"]][[2L]][["coverage_complete"]])
  for (name in c(
    "artifact_authentication",
    "platform_coverage",
    "durable_retention"
  )) {
    testthat::expect_identical(check[[name]], "not_assessed")
  }
  text <- as.character(jsonlite::toJSON(
    check,
    auto_unbox = TRUE,
    null = "null"
  ))
  testthat::expect_match(
    text,
    "suite_jwks_no_store_prevents_cached_key_refresh_test",
    fixed = TRUE
  )
})

testthat::test_that("the matrix rejects missing duplicate unrelated and partial substitute reports", {
  f <- release_matrix_test_fixture()
  for (reports in list(
    list(),
    f[["reports"]][-1L],
    c(f[["reports"]], f[["reports"]][1L]),
    list(f[["reports"]][[1L]], f[["reports"]][[1L]]),
    c(
      f[["reports"]],
      list(release_matrix_test_report(evidence_fixture("basic")))
    )
  )) {
    release_matrix_test_failed(release_matrix_test_check(f, reports))
  }
  matrix <- release_matrix_test_matrix(list(c("basic", "sync")))
  release_matrix_test_failed(release_matrix_test_check(
    f,
    f[["reports"]][1L],
    matrix
  ))
  # Changing labels does not turn a three-module smoke report into Basic.
  report <- f[["reports"]][[1L]]
  report[["profile"]] <- "basic"
  release_matrix_test_failed(release_matrix_test_check(f, list(report), matrix))
  reports <- f[["reports"]]
  reports[[1L]][["transport"]] <- "mirai"
  release_matrix_test_failed(release_matrix_test_check(f, reports))
})

testthat::test_that("aggregate source policy rejects dirty mixed legacy and changed installations", {
  f <- release_matrix_test_fixture()
  for (name in c(
    "checkout_revision",
    "checkout_source",
    "checkout_source_after",
    "source_verified",
    "installation",
    "regression_installation_after",
    "installation_after"
  )) {
    reports <- f[["reports"]]
    reports[[1L]][[name]] <- NULL
    release_matrix_test_failed(release_matrix_test_check(f, reports), name)
  }
  mutations <- list(
    schema_version = 3L,
    status = "failed",
    checkout_dirty = TRUE,
    checkout_revision = strrep("9", 40L),
    source_verified = FALSE
  )
  for (name in names(mutations)) {
    reports <- f[["reports"]]
    reports[[1L]][[name]] <- mutations[[name]]
    release_matrix_test_failed(release_matrix_test_check(f, reports), name)
  }
  for (name in c(
    "revision",
    "tree",
    "archive_sha256",
    "source_fingerprint",
    "fingerprint"
  )) {
    reports <- f[["reports"]]
    for (field in c(
      "installation",
      "regression_installation_after",
      "installation_after"
    )) {
      reports[[1L]][[field]][[name]] <- strrep(
        "9",
        if (name %in% c("revision", "tree")) 40L else 64L
      )
    }
    release_matrix_test_failed(release_matrix_test_check(f, reports), name)
  }
  reports <- f[["reports"]]
  reports[[1L]][["checkout_source_after"]][["files"]][["R/client.R"]] <- strrep(
    "9",
    64L
  )
  release_matrix_test_failed(release_matrix_test_check(f, reports))
})

testthat::test_that("separate valid checkout and installation fingerprints can share one canonical source", {
  f <- release_matrix_test_fixture()
  reports <- f[["reports"]]
  source <- reports[[2L]][["checkout_source"]]
  source[["files"]][["R/client.R"]] <- strrep("8", 64L)
  source[["fingerprint"]] <- openid_hash_manifest(source[["files"]])
  reports[[2L]][["checkout_source"]] <- reports[[2L]][[
    "checkout_source_after"
  ]] <- source
  installation <- reports[[2L]][["installation"]]
  installation[["source_fingerprint"]] <- source[["fingerprint"]]
  installation[["files"]][["R/shinyOAuth.rdb"]] <- strrep("7", 64L)
  installation[["fingerprint"]] <- openid_hash_manifest(installation[["files"]])
  for (name in c(
    "installation",
    "regression_installation_after",
    "installation_after"
  )) {
    reports[[2L]][[name]] <- installation
  }
  testthat::expect_false(identical(reports[[1L]][["checkout_source"]], source))
  testthat::expect_false(identical(
    reports[[1L]][["installation"]],
    installation
  ))
  testthat::expect_true(release_matrix_test_check(f, reports)[["gate_passed"]])
  # These are synthetic coherent records, not an OS or physical-file assertion.
})

testthat::test_that("report package versions agree with each other and the independently selected version", {
  f <- release_matrix_test_fixture()
  version <- f[["reports"]][[1L]][["package_version"]]
  check <- function(expected) {
    openid_check_release(
      f[["reports"]],
      f[["matrix"]],
      f[["manifest"]],
      f[["revision"]],
      f[["tree"]],
      f[["archive"]],
      package_version = expected
    )
  }
  testthat::expect_true(check(version)[["gate_passed"]])
  release_matrix_test_failed(check("99.0.0"))
  replace_version <- function(value) {
    if (is.list(value)) {
      return(lapply(value, replace_version))
    }
    if (is.character(value)) {
      value[!is.na(value) & value == version] <- "99.0.0"
    }
    value
  }
  reports <- f[["reports"]]
  reports[[2L]] <- replace_version(reports[[2L]])
  testthat::expect_true(openid_check_report(
    reports[[2L]],
    reports[[2L]],
    f[["manifest"]]
  )[["gate_passed"]])
  release_matrix_test_failed(release_matrix_test_check(f, reports))
})

testthat::test_that("release validation recomputes summary fields and rejects forged credit", {
  f <- release_matrix_test_fixture()
  for (name in c(
    "gate_passed",
    "selection_complete",
    "coverage_complete",
    "upstream_plan_complete"
  )) {
    reports <- f[["reports"]]
    reports[[1L]][[name]] <- !isTRUE(reports[[1L]][[name]])
    release_matrix_test_failed(release_matrix_test_check(f, reports), name)
  }
  for (name in c("assessment", "coverage_limitations")) {
    reports <- f[["reports"]]
    reports[[2L]][[name]] <- NULL
    release_matrix_test_failed(release_matrix_test_check(f, reports), name)
  }
  reports <- f[["reports"]]
  reports[[2L]][["assessment"]][["certification_status"]] <- "certified"
  release_matrix_test_failed(release_matrix_test_check(f, reports))
  reports <- f[["reports"]]
  reports[[2L]][["coverage_limitations"]] <- list()
  release_matrix_test_failed(release_matrix_test_check(f, reports))
  reports <- f[["reports"]]
  reports[[2L]][["results"]][[1L]][["suite_result"]] <- "FAILED"
  release_matrix_test_failed(release_matrix_test_check(f, reports))
  reports <- f[["reports"]]
  reports[[2L]][["images"]][["server"]] <- "unrelated-image"
  release_matrix_test_failed(release_matrix_test_check(f, reports))
})

testthat::test_that("summary object reordering preserves meaning but assessment array reordering does not", {
  reorder <- function(x) {
    if (!is.list(x)) {
      return(x)
    }
    x <- lapply(x, reorder)
    if (!is.null(names(x))) {
      x <- x[rev(seq_along(x))]
    }
    x
  }
  f <- release_matrix_test_fixture()
  reports <- lapply(f[["reports"]], function(report) {
    report[["assessment"]] <- reorder(report[["assessment"]])
    report
  })
  testthat::expect_true(release_matrix_test_check(f, reports)[["gate_passed"]])
  report <- release_matrix_test_report(fapi_full_fixture(
    "sync",
    "fapi-oauth-dpop"
  ))
  matrix <- release_matrix_test_matrix(list(c("fapi-oauth-dpop", "sync")))
  testthat::expect_true(release_matrix_test_check(f, list(report), matrix)[[
    "gate_passed"
  ]])
  exceptions <- report[["assessment"]][["accepted_non_passed_results"]]
  testthat::expect_length(exceptions, 3L)
  report[["assessment"]][["accepted_non_passed_results"]] <- rev(exceptions)
  release_matrix_test_failed(release_matrix_test_check(f, list(report), matrix))
})

testthat::test_that("matrix cleanup policy rejects missing proof and source-qualified legacy callbacks", {
  f <- release_matrix_test_fixture()
  base <- fapi_full_fixture("sync", "fapi-oauth-dpop-reference")
  report <- release_matrix_test_report(base)
  matrix <- release_matrix_test_matrix(list(c(
    "fapi-oauth-dpop-reference",
    "sync"
  )))
  testthat::expect_true(release_matrix_test_check(f, list(report), matrix)[[
    "gate_passed"
  ]])
  i <- which(vapply(
    report[["results"]],
    function(row) !is.null(row[["callback_http"]]),
    logical(1)
  ))[[1L]]
  for (name in c(
    "final_url_verified",
    "pending_state_preserved",
    "redirect_headers_verified"
  )) {
    changed <- report
    changed[["results"]][[i]][["callback_http"]][[name]] <- FALSE
    release_matrix_test_failed(
      release_matrix_test_check(f, list(changed), matrix),
      name
    )
  }
  changed <- report
  changed[["callback_rejection_policy"]] <- NULL
  release_matrix_test_failed(release_matrix_test_check(
    f,
    list(changed),
    matrix
  ))
  legacy <- release_matrix_test_report(base, cleanup = FALSE)
  testthat::expect_true(openid_check_report(legacy, legacy, f[["manifest"]])[[
    "gate_passed"
  ]])
  testthat::expect_true(openid_release_source_matches(
    list(legacy),
    f[["revision"]],
    f[["tree"]],
    f[["archive"]]
  ))
  release_matrix_test_failed(release_matrix_test_check(f, list(legacy), matrix))
})

testthat::test_that("shared-pool rows require their own proof and do not substitute for ordinary rows", {
  f <- release_matrix_test_fixture()
  report <- release_matrix_test_report(shared_evidence_fixture())
  matrix <- release_matrix_test_matrix(list(c("shared-pool", "mirai")))
  testthat::expect_identical(
    report[["regression_installation_after"]],
    report[["installation"]]
  )
  testthat::expect_true(release_matrix_test_check(f, list(report), matrix)[[
    "gate_passed"
  ]])
  changed <- report
  changed[["regression_installation_after"]] <- NULL
  release_matrix_test_failed(release_matrix_test_check(
    f,
    list(changed),
    matrix
  ))
  ordinary <- release_matrix_test_matrix(list(
    c("auth-post", "mirai"),
    c("auth-private-jwt", "mirai")
  ))
  release_matrix_test_failed(release_matrix_test_check(
    f,
    list(report),
    ordinary
  ))
  for (i in seq_along(report[["selections"]])) {
    changed <- report
    changed[["selections"]][[i]][["regression_installation_after"]] <- NULL
    release_matrix_test_failed(release_matrix_test_check(
      f,
      list(changed),
      matrix
    ))
    changed <- report
    changed[["selections"]][[i]][["callback_rejection_policy"]] <- NULL
    release_matrix_test_failed(release_matrix_test_check(
      f,
      list(changed),
      matrix
    ))
    changed <- report
    changed[["selections"]][[i]][["installation_after"]][[
      "archive_sha256"
    ]] <- strrep("9", 64L)
    release_matrix_test_failed(release_matrix_test_check(
      f,
      list(changed),
      matrix
    ))
    changed <- report
    changed[["selections"]][[i]][["assessment"]][["status"]] <- "unavailable"
    release_matrix_test_failed(release_matrix_test_check(
      f,
      list(changed),
      matrix
    ))
  }
})

testthat::test_that("release summaries exclude unrelated diagnostic and credential-bearing input", {
  f <- release_matrix_test_fixture()
  reports <- f[["reports"]]
  reports[[1L]][["unexpected_debug"]] <- list(
    client_secret = "DO_NOT_RELEASE_SECRET",
    url = "https://user:DO_NOT_RELEASE_PASSWORD@example.test/?state=DO_NOT_RELEASE_STATE"
  )
  check <- release_matrix_test_check(f, reports)
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_no_match(
    as.character(jsonlite::toJSON(check, auto_unbox = TRUE, null = "null")),
    "DO_NOT_RELEASE",
    fixed = TRUE
  )
})
