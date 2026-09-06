test_that("OTel retains the documented UserInfo JWT algorithm field", {
  attrs <- otel_event_attributes(list(
    type = "audit_userinfo",
    jwt_alg = "RS256"
  ))
  expect_identical(attrs[[otel_translate_event_key("jwt_alg")]], "RS256")
})
