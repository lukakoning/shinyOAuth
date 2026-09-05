test_that("decoded gzip budgets are enforced before full accumulation", {
  skip_if_not_installed("webfakes")
  skip_on_cran()
  withr::local_options(list(shinyOAuth.max_body_bytes = 4096L,
    shinyOAuth.allowed_hosts = c("127.0.0.1", "localhost")))
  gzip <- function(bytes) {
    path <- withr::local_tempfile()
    con <- gzfile(path, "wb", compression = 9L)
    writeBin(bytes, con)
    close(con)
    readBin(path, "raw", n = file.info(path)$size)
  }
  clear <- charToRaw(paste(rep("A", 2 * 1024 * 1024), collapse = ""))
  compressed <- gzip(clear)
  expect_lt(length(compressed), 4096L)
  app <- webfakes::new_app()
  app$locals$large <- compressed
  app$locals$small <- gzip(charToRaw("small response"))
  app$locals$clear <- clear
  app$get("/large", function(req, res) {
    res$set_header("Content-Encoding", "gzip")$send(app$locals$large)
  })
  app$get("/small", function(req, res) {
    res$set_header("Content-Encoding", "gzip")$send(app$locals$small)
  })
  app$get("/plain", function(req, res) res$send(app$locals$clear))
  srv <- webfakes::local_app_process(app)
  before <- list.files(tempdir(), pattern = "^shinyOAuth-response-")
  err <- tryCatch(perform_resource_req("synthetic", srv$url("/large")), error = identity)
  expect_s3_class(err, "shinyOAuth_parse_error")
  # The error records only budget + sentinel, rather than the 2 MiB plaintext.
  expect_equal(err$context$body_bytes, 4097L)
  expect_error(perform_resource_req("synthetic", srv$url("/plain"), idempotent = FALSE),
    class = "shinyOAuth_transport_error")
  resp <- perform_resource_req("synthetic", srv$url("/small"))
  expect_identical(httr2::resp_body_string(resp), "small response")
  expect_identical(list.files(tempdir(), pattern = "^shinyOAuth-response-"), before)
})
