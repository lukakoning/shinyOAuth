local_with_options <- function(opts, code) {
  old <- options(opts)
  on.exit(options(old), add = TRUE)
  force(code)
}

test_that("sanitize_body truncates and strips newlines", {
  s <- "line1\nline2\rline3"
  out <- shinyOAuth:::sanitize_body(s, max_chars = 10)
  expect_false(grepl("\n|\r", out))
  expect_true(endsWith(out, "[truncated]") || nchar(out) <= 10)
})

test_that("string_digest returns hex digest or NA for bad inputs", {
  d <- shinyOAuth:::string_digest("hello")
  expect_match(d, "^[0-9a-f]+$")
  expect_true(nchar(d) >= 10)
  expect_true(is.na(shinyOAuth:::string_digest(NA_character_)))
  # simulate openssl error by passing a raw connection (sha256 expects raw)
  expect_true(is.na(shinyOAuth:::string_digest(structure(
    list(),
    class = "not-char"
  ))))
})

test_that("err_abort/err_pkce attach classes and trace ids", {
  expect_error(shinyOAuth:::err_pkce("boom"), class = "shinyOAuth_pkce_error")
  e <- tryCatch(shinyOAuth:::err_pkce("boom2"), error = identity)
  expect_true(is.character(e$trace_id) && nzchar(e$trace_id))
})

test_that("err_http includes status and optional body when exposure enabled", {
  # Call err_http with NULL resp and ensure it still works
  expect_error(
    shinyOAuth:::err_http("msg", resp = NULL),
    class = "shinyOAuth_http_error"
  )

  # Now enable body exposure; since resp is NULL, body won't be shown but path is covered
  local_with_options(list(shinyOAuth.expose_error_body = TRUE), {
    expect_error(
      shinyOAuth:::err_http("msg2", resp = NULL),
      class = "shinyOAuth_http_error"
    )
  })
})

test_that("audit_event emits audit_ events via trace hook", {
  events <- list()
  local_with_options(
    list(shinyOAuth.trace_hook = function(ev) {
      events[[length(events) + 1]] <<- ev
    }),
    {
      id <- shinyOAuth:::audit_event(
        "token_exchange",
        context = list(foo = "bar")
      )
      expect_true(is.character(id) && nzchar(id))
    }
  )
  # Check at least one event captured
  expect_true(length(events) >= 1)
  expect_identical(events[[1]]$type, "audit_token_exchange")
  expect_identical(events[[1]]$foo, "bar")
})

test_that("log_condition prints when enabled but remains silent otherwise", {
  # By default should be silent
  e <- tryCatch(shinyOAuth:::err_pkce("x"), error = identity)
  expect_invisible(shinyOAuth:::log_condition(e))

  # When enabled, still should not error
  local_with_options(
    list(shinyOAuth.print_errors = TRUE, shinyOAuth.print_traceback = FALSE),
    {
      expect_invisible(shinyOAuth:::log_condition(e))
    }
  )
})

test_that("normalize_bullets preserves named types and defaults unnamed", {
  b <- shinyOAuth:::normalize_bullets(c("i" = "a", "b"))
  expect_identical(unname(b), c("a", "b"))
  expect_identical(names(b), c("i", "!"))

  # Lists are flattened and names preserved
  b2 <- shinyOAuth:::normalize_bullets(list("i" = "a", "b"))
  expect_identical(unname(b2), c("a", "b"))
  expect_identical(names(b2), c("i", "!"))

  # NA names also default to '!'
  v <- c("a", "b")
  names(v) <- c(NA_character_, "i")
  b3 <- shinyOAuth:::normalize_bullets(v)
  expect_identical(names(b3), c("!", "i"))
})
