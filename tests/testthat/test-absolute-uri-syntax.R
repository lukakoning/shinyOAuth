test_that("absolute URIs follow RFC 3986 including opaque resource names", {
  invalid <- c("foo:%ZZ", "foo:[", "x:a|b", "https://example.com/%ZZ",
    "https://example.com/%", "https://example.com/a b", "foo:a\\b",
    "https://[:::]/", "https://host:bad/", "foo://a@b@c/", " foo:a",
    "foo:a\n", "foo:a\r\n")
  for (uri in invalid) expect_false(is_absolute_uri(uri), info = uri)
  valid <- c("urn:example:ledger", "foo:a%20b", "https://example.com/%25",
    "https://[::1]:443/a?x=y", "x:/", "x:", "file:///tmp/a",
    "https://[v1.a:b]/", "mailto:user@example.com")
  for (uri in valid) expect_true(is_absolute_uri(uri), info = uri)
})
