test_that("mTLS thumbprint cache bounds configuration churn and retains active keys", {
  cache <- shinyOAuth:::mtls_thumbprint_cache
  cache$reset()
  withr::defer(cache$reset())
  for (i in seq_len(128L)) {
    mtls_thumbprint_cache_set(paste0("rotation_", i), paste0("thumbprint_", i))
  }
  expect_equal(cache$size(), 128L)
  expect_identical(mtls_thumbprint_cache_get("rotation_1"), "thumbprint_1")
  for (i in 129:256) {
    mtls_thumbprint_cache_set(paste0("rotation_", i), paste0("thumbprint_", i))
    expect_identical(mtls_thumbprint_cache_get("rotation_1"), "thumbprint_1")
    expect_lte(cache$size(), 128L)
  }
  expect_null(mtls_thumbprint_cache_get("rotation_2"))
  expect_identical(mtls_thumbprint_cache_get("rotation_256"), "thumbprint_256")
})

test_that("certificate changes invalidate cached file signatures", {
  cert <- tempfile()
  writeLines("first certificate", cert)
  withr::defer(unlink(cert))
  first <- mtls_thumbprint_cache_key(cert)
  expect_identical(mtls_thumbprint_cache_key(cert), first)
  writeLines("replacement certificate", cert)
  expect_false(identical(mtls_thumbprint_cache_key(cert), first))
})
