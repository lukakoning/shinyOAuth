testthat::test_that("regressions select the private checkout and reject a stale loaded namespace", {
  root <- withr::local_tempdir("openid-installation-current-")
  stale_root <- withr::local_tempdir("openid-installation-stale-")
  output <- withr::local_tempdir("openid-installation-output-")
  stale_output <- withr::local_tempdir("openid-installation-stale-output-")
  source_test_repo(root)
  source_test_repo(stale_root)
  writeLines(
    'source_value <- function() "stale"',
    file.path(stale_root, "R/value.R")
  )
  processx::run(
    "git",
    c(
      "-c",
      "user.name=Source Test",
      "-c",
      "user.email=test@example.com",
      "commit",
      "--quiet",
      "-am",
      "stale namespace fixture"
    ),
    wd = stale_root
  )
  source <- openid_source_identity(root)
  library <- openid_install(root, output, source)
  record <- openid_installation(library, source)
  stale_source <- openid_source_identity(stale_root)
  stale_library <- openid_install(stale_root, stale_output, stale_source)
  helpers <- normalizePath(".", winslash = "/")
  package <- normalizePath(file.path(library, "shinyOAuth"), winslash = "/")
  stale_package <- normalizePath(
    file.path(stale_library, "shinyOAuth"),
    winslash = "/"
  )
  probe <- function(mode) {
    callr::r(
      function(helpers, library, stale_library, source, record, mode) {
        sys.source(file.path(helpers, "helper-source.R"), environment())
        sys.source(file.path(helpers, "helper-app.R"), environment())
        .libPaths(c(stale_library, .libPaths()))
        initial <- normalizePath(find.package("shinyOAuth"), winslash = "/")
        if (identical(mode, "loaded_stale")) {
          loadNamespace("shinyOAuth", lib.loc = stale_library)
          paths <- .libPaths()
          error <- tryCatch(
            {
              openid_use_installation(library, source)
              NULL
            },
            error = conditionMessage
          )
          return(list(
            error = error,
            value = getExportedValue("shinyOAuth", "source_value")(),
            path = normalizePath(
              getNamespaceInfo("shinyOAuth", "path"),
              winslash = "/"
            ),
            library_paths_unchanged = identical(paths, .libPaths())
          ))
        }
        before <- openid_use_installation(library, source)
        # Repeating selection after another library moves ahead must retain the
        # already verified namespace and restore the private library precedence.
        .libPaths(c(stale_library, .libPaths()))
        after <- openid_use_installation(library, source, before)
        result <- list(
          initial = initial,
          value = getExportedValue("shinyOAuth", "source_value")(),
          path = normalizePath(
            getNamespaceInfo("shinyOAuth", "path"),
            winslash = "/"
          ),
          private_library_first = identical(.libPaths()[[1L]], library),
          expected_inventory = identical(before, record),
          inventory_unchanged = identical(before, after)
        )
        if (identical(mode, "changed_record")) {
          changed <- before
          changed[["package_version"]] <- "0.0.0.9001"
          jsonlite::write_json(
            changed,
            file.path(library, "shinyOAuth/Meta/openid-source.json"),
            auto_unbox = TRUE,
            pretty = TRUE
          )
          result[["error"]] <- tryCatch(
            {
              openid_use_installation(library, source, before)
              NULL
            },
            error = conditionMessage
          )
        }
        result
      },
      args = list(helpers, library, stale_library, source, record, mode),
      libpath = c(stale_library, .libPaths())
    )
  }
  selected <- probe("unloaded")
  testthat::expect_identical(selected[["initial"]], stale_package)
  testthat::expect_identical(selected[["value"]], "committed")
  testthat::expect_identical(selected[["path"]], package)
  testthat::expect_true(selected[["private_library_first"]])
  testthat::expect_true(selected[["expected_inventory"]])
  testthat::expect_true(selected[["inventory_unchanged"]])
  stale <- probe("loaded_stale")
  testthat::expect_match(
    stale[["error"]],
    "different shinyOAuth namespace already loaded"
  )
  testthat::expect_match(stale[["error"]], "fresh Rscript process")
  testthat::expect_identical(stale[["value"]], "stale")
  testthat::expect_identical(stale[["path"]], stale_package)
  testthat::expect_true(stale[["library_paths_unchanged"]])
  changed <- probe("changed_record")
  testthat::expect_match(
    changed[["error"]],
    "installation changed during regression checks"
  )
})
