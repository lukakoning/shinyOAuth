testthat::test_that("rejection continuations stay on the configured route and erase fragments", {
  location <- paste0("?shinyOAuth_callback_error=ce1_", strrep("a", 43L), "#")
  expected <- paste0("http://127.0.0.1:8118/", location)
  testthat::expect_identical(
    keycloak_callback_rejection_target("http://127.0.0.1:8118", location),
    expected
  )
  testthat::expect_true(keycloak_callback_rejection_url_matches(
    expected,
    "http://127.0.0.1:8118"
  ))
  testthat::expect_true(keycloak_callback_rejection_url_matches(
    sub("#$", "", expected),
    "http://127.0.0.1:8118"
  ))
  for (url in c(
    sub("127.0.0.1", "attacker.example", expected, fixed = TRUE),
    sub(":8118/", ":8119/", expected, fixed = TRUE),
    sub("/\\?", "/other?", expected),
    paste0(expected, "SECRET-FRAGMENT"),
    sub("#$", "&code=SECRET", expected)
  )) {
    testthat::expect_false(keycloak_callback_rejection_url_matches(
      url,
      "http://127.0.0.1:8118"
    ))
  }
  for (bad in c(
    "https://attacker.example/",
    "//attacker.example/",
    sub("#$", "", location),
    paste0(location, "SECRET"),
    sub("ce1_", "VALID-HANDLE", location, fixed = TRUE),
    sub("#$", "&state=SECRET#", location)
  )) {
    testthat::expect_error(
      keycloak_callback_rejection_target("http://127.0.0.1:8118", bad),
      "opaque query-only"
    )
  }
})

testthat::test_that("the HTTP rejection check observes both hops and retains terminal status", {
  location <- paste0("?shinyOAuth_callback_error=ce1_", strrep("a", 43L), "#")
  initial <- httr2::response(
    status_code = 303L,
    url = "http://127.0.0.1:8118/?code=SECRET",
    headers = list(
      Location = location,
      `Cache-Control` = "no-store",
      `Referrer-Policy` = "no-referrer"
    )
  )
  for (status in c(400L, 413L, 415L)) {
    requests <- 0L
    perform <- function(request) {
      requests <<- requests + 1L
      testthat::expect_identical(
        request[["url"]],
        paste0("http://127.0.0.1:8118/", location)
      )
      testthat::expect_identical(request[["method"]], "GET")
      testthat::expect_identical(
        request[["options"]][["followlocation"]],
        FALSE
      )
      httr2::response(
        status_code = status,
        url = request[["url"]],
        headers = list(
          `Cache-Control` = "no-store",
          `Referrer-Policy` = "no-referrer",
          `Content-Type` = "text/plain; charset=UTF-8"
        ),
        body = charToRaw("Approved callback diagnosis.")
      )
    }
    final <- keycloak_follow_callback_rejection(
      initial,
      "http://127.0.0.1:8118",
      status,
      sensitive = "SECRET",
      .perform = perform
    )
    testthat::expect_identical(requests, 1L)
    testthat::expect_identical(httr2::resp_status(final), status)
  }
})

testthat::test_that("the HTTP check never follows an accepted handle or an unsafe Location", {
  for (location in c(
    "?shinyOAuth_form_post=VALID-HANDLE",
    "//attacker.example/",
    paste0(
      "?shinyOAuth_callback_error=ce1_",
      strrep("a", 43L),
      "&state=SECRET#"
    )
  )) {
    requests <- 0L
    response <- httr2::response(
      status_code = 303L,
      headers = list(
        Location = location,
        `Cache-Control` = "no-store",
        `Referrer-Policy` = "no-referrer"
      )
    )
    testthat::expect_error(
      keycloak_follow_callback_rejection(
        response,
        "http://127.0.0.1:8118",
        400L,
        .perform = function(...) {
          requests <<- requests + 1L
          stop("Unsafe follow")
        }
      ),
      "opaque query-only"
    )
    testthat::expect_identical(requests, 0L)
  }
})
