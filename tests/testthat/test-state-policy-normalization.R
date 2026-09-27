test_that("policy fingerprints retain their canonical encoding", {
  # Golden values from the scalar encoder before vectorization. Existing sealed
  # credentials and pending callbacks must keep the same policy fingerprints.
  values <- list(
    empty = character(),
    scalar = "read",
    tokens = c(
      "read",
      "write",
      NA_character_,
      "<na>",
      "",
      'quote"',
      "back\\slash",
      "\n"
    ),
    named = c(z = "write", a = "read", z = NA_character_),
    matrix = matrix(c("read", NA_character_, "write", ""), 2),
    classed = I(c("read", NA_character_)),
    logical = c(TRUE, FALSE, NA),
    numeric = c(0, 1.125, 1e-12, Inf, -Inf, NA_real_, NaN),
    date = as.Date(c("2026-01-01", NA_character_)),
    nested = list(
      z = list(scopes = c("read", "write"), resource = "urn:api:1"),
      a = NULL
    )
  )
  expected <- c(
    '[]',
    '"read"',
    '["read","write","<na>","<na>","","quote\\\"","back\\\\slash","\\n"]',
    '{"a":"read","z":"write","z.1":"<na>"}',
    '["read","<na>","write",""]',
    '["read","<na>"]',
    '["true","false","<na>"]',
    '["0","1.125","0.000000000001","Inf","-Inf","<na>","<na>"]',
    '["2026-01-01","<na>"]',
    '{"a":null,"z":{"resource":"urn:api:1","scopes":["read","write"]}}'
  )
  for (i in seq_along(values)) {
    expect_identical(
      as.character(state_policy_component_string(values[[i]])),
      expected[[i]],
      info = names(values)[[i]]
    )
  }
  expect_identical(
    state_policy_digest(values),
    "sha256:1eb3d9cfffb85b740506d72f4154d878890f0e83d1488185a0e8d2326beac76d"
  )
})

test_that("character policy normalization preserves encoding and container semantics", {
  latin1 <- iconv("caf\u00e9", from = "UTF-8", to = "latin1")
  expected <- c("caf\u00e9", "<na>", "")
  expect_identical(
    state_policy_normalize_value(c(latin1, NA_character_, "")),
    expected
  )
  expect_identical(
    state_policy_normalize_value(matrix(
      c(latin1, NA_character_, ""),
      nrow = 1
    )),
    expected
  )
  expect_identical(
    state_policy_normalize_value(c(z = NA_character_, a = latin1)),
    list(a = "caf\u00e9", z = "<na>")
  )
  expect_identical(state_policy_normalize_value(character()), character())
  expect_identical(state_policy_normalize_value(list()), list())
  expect_null(state_policy_normalize_value(NULL))

  # Policy digests must continue to bind every scope, including a change late
  # in the largest permitted target declaration.
  scopes <- sprintf("permission.%03d", seq_len(128))
  original <- state_policy_digest(list(scopes = scopes))
  scopes[[128]] <- "permission.admin"
  expect_false(identical(state_policy_digest(list(scopes = scopes)), original))
})
