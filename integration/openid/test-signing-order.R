testthat::test_that("discovery signing proof ignores object order but retains exact fields and values", {
  expectation <- list(outcome = "discovery_rejected")
  original <- list(suite_id = "instance", stage = "discovery")
  matches <- function(proof) {
    openid_signing_matches(
      list(suite_id = "instance", message_signing = proof),
      expectation
    )
  }
  for (proof in list(original, original[c("stage", "suite_id")])) {
    testthat::expect_true(matches(proof))
    json <- jsonlite::fromJSON(
      as.character(jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null")),
      simplifyVector = FALSE
    )
    testthat::expect_true(matches(json))
    testthat::expect_true(matches(openid_release_canonical(json)))
  }
  for (proof in list(
    NULL,
    list(),
    list(suite_id = "instance"),
    list(stage = "discovery"),
    c(original, list(extra = TRUE)),
    c(original, list(extra = NULL)),
    c(original, list(suite_id = "instance")),
    c(original, list(stage = "discovery")),
    list(suite_id = "other-instance", stage = "discovery"),
    list(suite_id = "instance", stage = "signed_exchange"),
    list(suite_id = "instance", stage = NULL),
    list(suite_id = list("instance"), stage = "discovery"),
    list(suite_id = "instance", stage = list("discovery")),
    list(suite_id = c("instance", "other-instance"), stage = "discovery"),
    list(suite_id = "instance", stage = c("discovery", "signed_exchange")),
    c(suite_id = "instance", stage = "discovery")
  )) {
    testthat::expect_false(matches(proof))
  }
  duplicated <- jsonlite::fromJSON(
    '{"suite_id":"instance","stage":"discovery","stage":"discovery"}',
    simplifyVector = FALSE
  )
  testthat::expect_false(matches(duplicated))
})

testthat::test_that("Message Signing release validation accepts canonical objects without weakening proof", {
  for (backend in c("sync", "mirai")) {
    fixture <- signing_report_fixture(backend)
    report <- release_matrix_test_report(fixture)
    matrix <- release_matrix_test_matrix(list(c(
      "fapi-message-signing",
      backend
    )))
    source <- report[["checkout_source"]]
    check <- function(candidate) {
      openid_check_release(
        list(candidate),
        matrix,
        fixture[["manifest"]],
        source[["revision"]],
        source[["tree"]],
        report[["installation"]][["archive_sha256"]],
        report[["package_version"]]
      )
    }
    canonical <- openid_release_canonical(report)
    discovery <- which(vapply(
      report[["results"]],
      function(row) {
        identical(row[["message_signing"]][["stage"]], "discovery")
      },
      logical(1)
    ))
    testthat::expect_true(length(discovery) > 0L)
    testthat::expect_identical(
      names(canonical[["results"]][[discovery[[1L]]]][["message_signing"]]),
      c("stage", "suite_id")
    )
    for (candidate in list(
      report,
      canonical,
      jsonlite::fromJSON(
        as.character(jsonlite::toJSON(
          canonical,
          auto_unbox = TRUE,
          null = "null"
        )),
        simplifyVector = FALSE
      )
    )) {
      result <- check(candidate)
      testthat::expect_true(result[["gate_passed"]], info = result[["reason"]])
      testthat::expect_true(result[["matrix_complete"]])
    }
    for (proof in list(
      list(suite_id = report[["results"]][[discovery[[1L]]]][["suite_id"]]),
      c(
        report[["results"]][[discovery[[1L]]]][["message_signing"]],
        list(extra = TRUE)
      ),
      list(suite_id = "other-instance", stage = "discovery"),
      list(
        suite_id = report[["results"]][[discovery[[1L]]]][["suite_id"]],
        stage = "signed_exchange"
      )
    )) {
      invalid <- report
      invalid[["results"]][[discovery[[1L]]]][["message_signing"]] <- proof
      testthat::expect_false(check(invalid)[["gate_passed"]])
    }
    # These reports and installation records are synthetic validator fixtures.
    # They do not establish execution of a real release matrix or a live flow.
  }
})
