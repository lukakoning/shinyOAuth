test_that("unique form parsing preserves form semantics and rejects decoded aliases", {
  expect_identical(
    parse_unique_form_encoded_members(
      "a=one+two&b=%2B%26%3D&empty=&bare&&",
      "Form"
    ),
    list(a = "one two", b = "+&=", empty = "", bare = "")
  )
  for (text in c("a=1&%61=2", "a+b=1&a%20b=2", "=1&=2")) {
    expect_error(
      parse_unique_form_encoded_members(text, "Form"),
      "duplicate parameter name",
      class = "shinyOAuth_parse_error"
    )
  }
  for (text in c("a=%", "a=%00", "%zz=1")) {
    expect_error(
      parse_unique_form_encoded_members(text, "Form"),
      "malformed percent-encoded",
      class = "shinyOAuth_parse_error"
    )
  }
})

test_that("callback-sized forms with many fields have a bounded allocation budget", {
  body <- paste0(sprintf("%03x", seq_len(5200L)), "=", collapse = "&")
  expect_lte(
    nchar(body, type = "bytes"),
    oauth_callback_limits()[["form_post_body"]]
  )
  # Profile actual callback parsing; a timing threshold alone misses transient
  # allocations and is sensitive to CPU contention on CI.
  skip_if_not(capabilities("profmem"))
  path <- withr::local_tempfile()
  utils::Rprofmem(path)
  tryCatch(
    expect_error(oauth_form_post_parse_body(body), "missing code or error"),
    finally = utils::Rprofmem(NULL)
  )
  sizes <- suppressWarnings(as.numeric(sub(" .*", "", readLines(path))))
  expect_lt(sum(sizes, na.rm = TRUE), 16 * 1024^2)
})
