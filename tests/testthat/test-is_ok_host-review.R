test_that("scheme-less tries http then https", {
  expect_true(is_ok_host("example.com", allowed_hosts = "example.com"))
})

test_that("http requires exemption", {
  expect_false(is_ok_host("http://example.com", allowed_hosts = "example.com"))
  expect_true(is_ok_host("http://localhost:3000"))
})

test_that("IPv6 patterns (bracketless) are honored", {
  # Sanity: the parser should extract bare IPv6 host
  expect_identical(
    shinyOAuth:::parse_url_host("http://[2001:db8::1]:8080"),
    "2001:db8::1"
  )
  expect_true(is_ok_host(
    "http://[2001:db8::1]:8080",
    allowed_non_https_hosts = c("2001:db8::1"),
    allowed_hosts = "2001:db8::1"
  ))
})

test_that("leading-dot matches domain and subdomains", {
  expect_true(is_ok_host(
    "https://a.b.example.com",
    allowed_hosts = ".example.com"
  ))
  expect_true(is_ok_host("https://example.com", allowed_hosts = ".example.com"))
  expect_false(is_ok_host(
    "https://badexample.com",
    allowed_hosts = ".example.com"
  ))
})

test_that("Unicode domains are supported", {
  dom <- "ドメイン.テスト"
  dom_ascii <- urltools::puny_encode(dom)
  expect_true(is_ok_host(paste0("https://", dom), allowed_hosts = dom))
  expect_true(is_ok_host(dom, allowed_hosts = dom)) # scheme-less path
  expect_identical(
    shinyOAuth:::parse_url_host(paste0("https://", dom)),
    dom_ascii
  )
  expect_true(is_ok_host(paste0("https://", dom), allowed_hosts = dom_ascii))
  expect_true(is_ok_host(paste0("https://", dom_ascii), allowed_hosts = dom))
})

test_that("Unicode hosts survive valid UTF-8 bytes marked unknown", {
  dom <- "ドメイン.テスト"
  host <- enc2utf8(dom)
  Encoding(host) <- "unknown"

  expect_identical(
    shinyOAuth:::host_normalize_idna(host),
    urltools::puny_encode(dom)
  )
})

test_that("Unicode host parsing survives Windows non-UTF locales", {
  skip_if(.Platform$OS.type != "windows")

  old_locale <- Sys.getlocale("LC_CTYPE")
  on.exit(
    try(Sys.setlocale("LC_CTYPE", old_locale), silent = TRUE),
    add = TRUE
  )

  locale <- try(
    suppressWarnings(
      Sys.setlocale("LC_CTYPE", "English_United States.1252")
    ),
    silent = TRUE
  )
  if (inherits(locale, "try-error") || !is.character(locale) || is.na(locale)) {
    skip("Windows-1252 locale unavailable")
  }

  dom <- "ドメイン.テスト"
  dom_ascii <- urltools::puny_encode(dom)

  expect_identical(
    shinyOAuth:::parse_url_host(paste0("https://", dom)),
    dom_ascii
  )
  expect_true(is_ok_host(paste0("https://", dom), allowed_hosts = dom))
})

test_that("HTTP exemptions cannot be spoofed by suffix", {
  expect_false(is_ok_host(
    "http://127.0.0.1.evil.com",
    allowed_non_https_hosts = c("127.0.0.1")
  ))
})

test_that("unsupported schemes are rejected quietly", {
  expect_false(is_ok_host("ftp://example.com", allowed_hosts = "example.com"))
})

test_that("vector input uses all-true semantics", {
  expect_true(is_ok_host(
    c("https://a.com", "https://b.com"),
    allowed_hosts = c("a.com", "b.com")
  ))
  expect_false(is_ok_host(
    c("https://a.com", "http://b.com"),
    allowed_hosts = c("a.com", "b.com")
  ))
})
