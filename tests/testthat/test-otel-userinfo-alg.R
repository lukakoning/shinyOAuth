test_that("OTel retains the documented UserInfo JWT algorithm field", {
  attrs <- otel_event_attributes(list(
    type = "audit_userinfo",
    jwt_alg = "RS256"
  ))
  expect_identical(attrs[[otel_translate_event_key("jwt_alg")]], "RS256")
})

test_that("unverified JWT algorithms cannot escape diagnostic redaction", {
  events <- list()
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  client <- make_test_client()
  for (alg in c(
    paste0(
      "https://user:password@example.test/private?token=secret-marker\nFORGED",
      intToUtf8(27),
      "[31m"
    ),
    strrep("oversized", 200)
  )) {
    jwt <- paste(
      base64url_encode(charToRaw(as.character(jsonlite::toJSON(
        list(alg = alg),
        auto_unbox = TRUE
      )))),
      base64url_encode(charToRaw("{}")),
      base64url_encode(as.raw(1)),
      sep = "."
    )
    resp <- httr2::response(
      headers = list("content-type" = "application/jwt"),
      body = charToRaw(jwt)
    )
    user_error <- tryCatch(decode_userinfo_jwt(resp, client), error = identity)
    id_error <- tryCatch(validate_id_token(client, jwt), error = identity)
    expect_s3_class(user_error, "shinyOAuth_userinfo_error")
    expect_s3_class(id_error, "shinyOAuth_id_token_error")
    for (error in list(user_error, id_error)) {
      expect_false(grepl(alg, conditionMessage(error), fixed = TRUE))
      expect_false(grepl(
        "secret-marker|FORGED|oversized",
        conditionMessage(error)
      ))
    }
  }
  user_events <- Filter(
    function(e) identical(e[["type"]], "audit_userinfo"),
    events
  )
  expect_length(user_events, 2L)
  for (event in user_events) {
    expect_identical(event[["jwt_alg"]], "unknown")
    expect_identical(otel_event_attributes(event)[["jwt_alg"]], "unknown")
  }
  expect_identical(
    otel_event_attributes(list(
      type = "audit_userinfo",
      jwt_alg = "arbitrary"
    ))[["jwt_alg"]],
    "unknown"
  )
})
