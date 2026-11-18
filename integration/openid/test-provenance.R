testthat::test_that("serialized evidence binds images and acquisition to the locked run", {
  fixtures <- list(
    evidence_fixture(),
    signing_report_fixture("sync"),
    shared_evidence_fixture()
  )
  for (f in fixtures) {
    checker <- if (identical(f[["context"]][["profile"]], "shared-pool")) {
      openid_check_shared_report
    } else {
      openid_check_report
    }
    check <- function(report, context = f[["context"]]) {
      checker(report, context, f[["manifest"]])[["gate_passed"]]
    }
    report <- jsonlite::fromJSON(
      jsonlite::toJSON(f[["report"]], auto_unbox = TRUE, null = "null"),
      simplifyVector = FALSE
    )
    testthat::expect_true(check(report))
    for (name in c("images", "image_sources", "checkout_dirty")) {
      changed <- report
      changed[[name]] <- NULL
      testthat::expect_false(check(changed))
      context <- f[["context"]]
      context[[name]] <- NULL
      testthat::expect_false(check(report, context))
    }
    for (name in names(f[["manifest"]][["suite_lock"]][["images"]])) {
      changed <- report
      changed[["images"]][[name]] <- "unrelated-image"
      testthat::expect_false(check(changed))
      context <- f[["context"]]
      context[["images"]] <- changed[["images"]]
      testthat::expect_false(check(changed, context))
      changed <- report
      changed[["image_sources"]][[name]] <- NULL
      testthat::expect_false(check(changed))
      for (value in list(
        "unknown",
        TRUE,
        NA_character_,
        c("cached", "pulled")
      )) {
        changed <- report
        changed[["image_sources"]][[name]] <- value
        testthat::expect_false(check(changed))
      }
      changed <- report
      changed[["image_sources"]][[name]] <- if (
        identical(report[["image_sources"]][[name]], "cached")
      ) {
        "pulled"
      } else {
        "cached"
      }
      testthat::expect_false(check(changed))
    }
    changed <- report
    changed[["image_sources"]][["extra"]] <- "cached"
    testthat::expect_false(check(changed))
    for (value in list(TRUE, "false", NA, c(FALSE, FALSE))) {
      changed <- report
      changed[["checkout_dirty"]] <- value
      testthat::expect_false(check(changed))
    }
    changed <- report
    changed[["checkout_dirty"]] <- TRUE
    for (i in seq_along(changed[["selections"]])) {
      changed[["selections"]][[i]][["checkout_dirty"]] <- TRUE
    }
    context <- f[["context"]]
    context[["checkout_dirty"]] <- TRUE
    testthat::expect_true(check(changed, context))
    context[["checkout_dirty"]] <- "true"
    testthat::expect_false(check(changed, context))
  }
})

testthat::test_that("shared selections retain their own matching provenance", {
  f <- shared_evidence_fixture()
  for (name in c("images", "image_sources", "checkout_dirty")) {
    for (i in seq_along(f[["report"]][["selections"]])) {
      changed <- f[["report"]]
      changed[["selections"]][[i]][[name]] <- NULL
      testthat::expect_false(openid_check_shared_report(
        changed,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})
