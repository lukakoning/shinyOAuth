test_that("is_ok_host enforces https and host allowlists", {
  # HTTPS is OK by default
  expect_true(is_ok_host("https://example.com/callback"))

  # HTTP only allowed for default localhost patterns
  expect_false(is_ok_host("http://evil.com"))
  expect_true(is_ok_host("http://localhost:8100/path"))
  expect_true(is_ok_host("http://127.0.0.1"))
  expect_true(is_ok_host("http://[::1]/cb"))

  # Custom allowed_non_https_hosts permits http for matching hosts
  expect_true(is_ok_host(
    "http://dev.myapp.local/cb",
    allowed_non_https_hosts = c("*.myapp.local")
  ))
  # But still denies other http hosts
  expect_false(is_ok_host(
    "http://staging.other.local/cb",
    allowed_non_https_hosts = c("*.myapp.local")
  ))

  # allowed_hosts restricts to allowlist (applies to both http/https cases)
  expect_true(is_ok_host(
    c("https://api.example.com/a", "https://cdn.example.com/b"),
    allowed_hosts = c("*.example.com")
  ))
  # Leading dot means exact domain or any subdomain
  expect_true(is_ok_host(
    c("https://example.org/a", "https://sub.example.org/b"),
    allowed_hosts = c(".example.org")
  ))
  expect_false(is_ok_host(
    "https://notexample.org",
    allowed_hosts = c(".example.org")
  ))

  # Invalid inputs return FALSE
  expect_false(is_ok_host(NA_character_))
  expect_false(is_ok_host(""))
  expect_false(is_ok_host("notaurl"))

  # Vectorized: any FALSE makes whole result FALSE
  expect_false(is_ok_host(c("https://ok.com", "not a url")))
})

test_that("is_ok_host respects ? single-char wildcard in allowed_hosts", {
  # ? matches exactly one character
  expect_true(is_ok_host(
    "https://api1.example.com/cb",
    allowed_hosts = c("api?.example.com")
  ))
  expect_true(is_ok_host(
    "https://apiX.example.com/cb",
    allowed_hosts = c("api?.example.com")
  ))
  # ? does NOT match zero chars
  expect_false(is_ok_host(
    "https://api.example.com/cb",
    allowed_hosts = c("api?.example.com")
  ))
  # ? does NOT match multiple chars
  expect_false(is_ok_host(
    "https://api12.example.com/cb",
    allowed_hosts = c("api?.example.com")
  ))

  # Leading-dot patterns with ? wildcard
  expect_true(is_ok_host(
    "https://foo1.org/cb",
    allowed_hosts = c(".foo?.org")
  ))
  expect_true(is_ok_host(
    "https://sub.fooX.org/cb",
    allowed_hosts = c(".foo?.org")
  ))
  expect_false(is_ok_host(
    "https://foo.org/cb",
    allowed_hosts = c(".foo?.org")
  ))
})

test_that("normalize_url collapses path slashes and preserves query/fragment", {
  f <- shinyOAuth:::normalize_url
  u <- "https://example.com//a///b?q=1#frag"
  out <- f(u)
  expect_identical(out, "https://example.com/a/b?q=1#frag")

  # If not matching URL pattern, return unchanged
  expect_identical(f("not a url"), "not a url")

  # Already normalized remains same
  expect_identical(f("https://x.com/a/b"), "https://x.com/a/b")
})

test_that("rtrim_slash removes a single trailing slash only", {
  g <- shinyOAuth:::rtrim_slash
  expect_identical(g("https://ex.com/a/"), "https://ex.com/a")
  expect_identical(g("https://ex.com/a///"), "https://ex.com/a//")
  expect_identical(g("https://ex.com/a"), "https://ex.com/a")
})

test_that("validate_scopes accepts common tokens and rejects bad ones", {
  v <- shinyOAuth:::validate_scopes
  # Empty vector is ok
  expect_invisible(v(character()))
  # Common valid scopes
  expect_invisible(v(c(
    "openid",
    "profile",
    "email",
    "repo:status",
    "user.read",
    "read:packages"
  )))

  # Non-character input -> input error
  expect_error(v(123), class = "shinyOAuth_input_error")
  # NA element -> input error
  expect_error(v(c("ok", NA_character_)), class = "shinyOAuth_input_error")
  # Empty string -> input error
  expect_error(v(c("ok", "")), class = "shinyOAuth_input_error")
  # Space-delimited string is accepted (split into tokens)
  expect_invisible(v("sp ace"))
  # RFC 6749 NQSCHAR allows commas, parens, braces, etc.
  expect_invisible(v("sp,ace"))
  # Double-quote and backslash are forbidden by RFC 6749 section 3.3
  expect_error(v("quote\""), class = "shinyOAuth_input_error")
  expect_error(v("back\\slash"), class = "shinyOAuth_input_error")
  # Broad RFC-valid scope tokens
  expect_invisible(v(c(
    "https://graph.microsoft.com/.default",
    "urn:scope:read",
    "user!admin",
    "scope#tag",
    "a]b[c",
    "key=value",
    "~tilde",
    "paren(ok)"
  )))
})

test_that("validate_scopes is fully compliant with RFC 6749 section 3.3", {
  v <- shinyOAuth:::validate_scopes

  # ── RFC 6749 §3.3 NQSCHAR boundary characters ──
  # scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
  # Allowed: ! (0x21), # through [ (0x23-0x5B), ] through ~ (0x5D-0x7E)
  # Forbidden: SP (0x20), " (0x22), \ (0x5C)

  # Boundary: first allowed char is ! (0x21)
  expect_invisible(v("!"))
  # Boundary: " (0x22) is the only gap between 0x21 and 0x23

  expect_error(v(rawToChar(as.raw(0x22))), class = "shinyOAuth_input_error")
  # Boundary: # (0x23) starts the second range
  expect_invisible(v("#"))
  # Boundary: [ (0x5B) ends the second range
  expect_invisible(v("["))
  # Boundary: \ (0x5C) is the only gap between 0x5B and 0x5D
  expect_error(v(rawToChar(as.raw(0x5C))), class = "shinyOAuth_input_error")
  # Boundary: ] (0x5D) starts the third range
  expect_invisible(v("]"))
  # Boundary: ~ (0x7E) is the last allowed char
  expect_invisible(v("~"))

  # ── Every allowed printable ASCII character (92 of 94) ──
  # Build a string containing every NQSCHAR character
  nqschar_codes <- c(0x21L, 0x23:0x5BL, 0x5D:0x7EL)
  for (code in nqschar_codes) {
    ch <- rawToChar(as.raw(code))
    expect_invisible(
      v(ch),
      label = sprintf("char 0x%02X ('%s') should be accepted", code, ch)
    )
  }

  # ── All three explicitly forbidden printable chars ──
  # SP (0x20) — used as scope-list delimiter
  # When passed as a single space, it splits into zero tokens -> "empty" error
  expect_error(v(" "), class = "shinyOAuth_input_error")
  # " (0x22)
  expect_error(v(rawToChar(as.raw(0x22))), class = "shinyOAuth_input_error")
  # \ (0x5C)
  expect_error(v(rawToChar(as.raw(0x5C))), class = "shinyOAuth_input_error")

  # ── Control characters and DEL must be rejected ──
  expect_error(v("\t"), class = "shinyOAuth_input_error")
  expect_error(v("\n"), class = "shinyOAuth_input_error")
  expect_error(v(rawToChar(as.raw(0x7F))), class = "shinyOAuth_input_error")

  # ── Non-ASCII must be rejected ──
  expect_error(v("\u00e9"), class = "shinyOAuth_input_error") # é
  expect_error(v("\u00f1"), class = "shinyOAuth_input_error") # ñ

  # ── Real-world provider scopes with extended chars ──
  expect_invisible(v(c(
    "https://www.googleapis.com/auth/drive.readonly",
    "api://my-app/.default",
    "urn:example:scope",
    "user_impersonation",
    "repo:status",
    "read:packages",
    "chat:write",
    "openid",
    "profile",
    "email",
    "*",
    "~/.config"
  )))
})

test_that("compact_list drops NULLs and length-1 NAs only", {
  f <- shinyOAuth:::compact_list
  x <- list(a = 1, b = NULL, c = NA_character_, d = c(NA, NA), e = "ok")
  y <- f(x)
  expect_false("b" %in% names(y))
  expect_false("c" %in% names(y))
  expect_true("d" %in% names(y))
  expect_true("a" %in% names(y) && "e" %in% names(y))

  # Non-list: returned unchanged
  expect_identical(f(5), 5)
})

test_that("coerce_expires_in parses digit-only strings and trims space", {
  g <- shinyOAuth:::coerce_expires_in
  expect_identical(g(NULL), NULL)
  expect_identical(g(3600), 3600)
  expect_identical(g("3600"), 3600)
  expect_identical(g("  7200  "), 7200)
  # Non-digit strings left unchanged
  expect_identical(g("3600s"), "3600s")
  expect_identical(g(c("1", "2")), c("1", "2"))
})

test_that("host_glob_to_regex converts * and ? wildcards correctly", {
  f <- shinyOAuth:::host_glob_to_regex

  # Basic cases: * matches any sequence, ? matches single char

  expect_identical(f("*.example.com"), "^.*\\.example\\.com$")
  expect_identical(f("foo?.com"), "^foo.\\.com$")
  expect_identical(f("a*b?.org"), "^a.*b.\\.org$")

  # Leading-dot patterns also support * and ? wildcards
  expect_identical(
    f(".foo*.com"),
    "^(?:foo.*\\.com|(?:[^.]+\\.)+foo.*\\.com)$"
  )
  expect_identical(
    f(".bar?.org"),
    "^(?:bar.\\.org|(?:[^.]+\\.)+bar.\\.org)$"
  )

  # Edge: just * matches any host (subdomain wildcard)
  expect_identical(f("*"), "^.*$")

  # Edge: NA, NULL, blank -> NULL
  expect_null(f(NULL))
  expect_null(f(NA))
  expect_null(f(""))
  expect_null(f("   "))
})
