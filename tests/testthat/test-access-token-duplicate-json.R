test_that("best-effort binding observation rejects ambiguous JSON quietly", {
  events <- list()
  local_options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  for (payload in c(
    '{"cnf":{"jkt":"one"},"cnf":{"jkt":"two"}}',
    '{"cnf":{"jkt":"one","jkt":"two"}}',
    '{"cnf":{},"c\\u006ef":{}}'
  )) {
    jwt <- paste(base64url_encode(charToRaw('{"alg":"RS256"}')),
                 base64url_encode(charToRaw(payload)), "AA", sep = ".")
    expect_null(parse_jwt_payload_or_null(jwt))
  }
  expect_null(parse_jwt_payload_or_null("opaque"))
  expect_length(events, 0L)
  jwt <- paste(base64url_encode(charToRaw('{"alg":"RS256"}')),
               base64url_encode(charToRaw('{"cnf":{"jkt":"one"}}')),
               "AA", sep = ".")
  expect_identical(parse_jwt_payload_or_null(jwt)[["cnf"]][["jkt"]], "one")
})
