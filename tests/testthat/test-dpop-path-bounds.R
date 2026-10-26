test_that("dot-segment stack allocation grows linearly", {
  skip_if_not(capabilities("profmem"))
  allocated <- function(n, remove = FALSE) {
    url <- paste0(
      "https://api.example/",
      paste(rep("x", n), collapse = "/"),
      if (remove) paste0("/", paste(rep("..", n), collapse = "/")) else "/./"
    )
    path <- tempfile()
    on.exit(unlink(path))
    utils::Rprofmem(path)
    result <- tryCatch(
      normalize_dpop_request_url(url),
      finally = utils::Rprofmem(NULL)
    )
    expect_type(result, "character")
    entries <- readLines(path, warn = FALSE)
    sum(suppressWarnings(as.numeric(sub(" .*", "", entries))), na.rm = TRUE)
  }
  # Warm up the functions before measuring; use allocation rather than timing
  # so the regression is independent of CPU speed and concurrent load.
  allocated(10L)
  for (remove in c(FALSE, TRUE)) {
    small <- allocated(1000L, remove)
    large <- allocated(3000L, remove)
    expect_lt(large, small * 4.5)
    expect_lt(large, 2 * 1024^2)
  }
})

test_that("generic resource URLs are bounded before signing or transport", {
  client <- oauth_client(
    make_test_provider(),
    "dpop-url-budget",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  prefix <- "https://api.example/"
  boundary <- paste0(prefix, strrep("x", 8192L - nchar(prefix)))
  oversized <- paste0(boundary, "/./")
  for (type in c("Bearer", "DPoP")) {
    for (check in c(FALSE, TRUE)) {
      expect_s3_class(resource_req(
        "access", boundary, client = client, token_type = type,
        check_url = check, resource_hosts = "api.example"
      ), "httr2_request")
      for (target in list(oversized, httr2::request(oversized))) {
        expect_error(perform_resource_req(
          "access", target, client = client, token_type = type,
          check_url = check, resource_hosts = "api.example"
        ), "8192 bytes")
      }
      expect_error(resource_req(
        "access", oversized, client = client, token_type = type,
        check_url = check
      ), "8192 bytes")
      expect_error(resource_req(
        "access", boundary, client = client, token_type = type,
        check_url = check, query = list(page = "1")
      ), "8192 bytes")
    }
  }
  # The budget counts bytes, including queries/fragments and multibyte UTF-8.
  expect_error(resource_req(
    "access", paste0(prefix, "?q=", strrep("x", 8192L)), check_url = FALSE
  ), "8192 bytes")
  expect_error(resource_req(
    "access", paste0(prefix, "#", strrep("\u00e9", 4096L)), check_url = FALSE
  ), "8192 bytes")
})
