for (installed_version in c("1.1.1", "1.2.0.1", "1.3.2", "1.3.3", "1.5.0")) {
  test_that(paste("future backend handles promises", installed_version), {
    skip_if_not_installed("future")
    skip_if_not_installed("promises", "1.3.3")
    original_is_installed <- rlang::is_installed
    local_mocked_bindings(
      is_installed = function(pkg, ..., version = NULL, compare = NULL) {
        if (identical(pkg, "promises")) {
          return(
            is.null(version) ||
              utils::compareVersion(installed_version, version) >= 0
          )
        }
        original_is_installed(pkg, ..., version = version, compare = compare)
      },
      .package = "rlang"
    )
    local_mocked_bindings(mirai_daemons_active = function() FALSE)
    local_mocked_bindings(nbrOfWorkers = function() 1L, .package = "future")
    dispatched <- FALSE
    local_mocked_bindings(
      future_promise = function(...) {
        dispatched <<- TRUE
        "dispatched"
      },
      .package = "promises"
    )

    if (installed_version %in% c("1.1.1", "1.2.0.1", "1.3.2")) {
      expect_null(async_backend_available())
      expect_error(
        async_dispatch(quote(1 + 1), list()),
        class = "shinyOAuth_no_async_backend"
      )
      expect_false(dispatched)
    } else {
      expect_identical(async_backend_available(), "future")
      expect_identical(async_dispatch(quote(1 + 1), list()), "dispatched")
      expect_true(dispatched)
    }
  })
}
