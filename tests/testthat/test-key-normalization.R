test_that("normalize_key32 raw >32 hashes instead of truncates", {
  # Construct a deterministic raw key of 64 bytes
  r <- as.raw(0:63)
  # Previously would truncate to first 32; now hashes to 32 bytes
  k <- shinyOAuth:::normalize_key32(r)
  expect_type(k, "raw")
  expect_equal(length(k), 32L)
  # Ensure it's not equal to naive truncation result
  expect_false(identical(k, r[1:32]))
  # And equals sha256 of the raw input
  expect_identical(k, openssl::sha256(r))
})

test_that("normalize_key32 raw ==32 uses as-is", {
  r <- as.raw(1:32)
  k <- shinyOAuth:::normalize_key32(r)
  expect_identical(k, r)
})

test_that("normalize_key32 raw <32 errors", {
  r <- as.raw(1:16)
  expect_error(
    shinyOAuth:::normalize_key32(r),
    class = "shinyOAuth_config_error"
  )
})

test_that("normalize_key32 strings derive with sha256 and length checks", {
  s_ok <- paste(rep("x", 32), collapse = "")
  k1 <- shinyOAuth:::normalize_key32(s_ok)
  expect_type(k1, "raw")
  expect_equal(length(k1), 32L)
  expect_identical(k1, openssl::sha256(charToRaw(s_ok)))
  s_short <- "short"
  expect_error(
    shinyOAuth:::normalize_key32(s_short),
    class = "shinyOAuth_config_error"
  )
})
