test_that("token media types match exactly after parameter normalization", {
  response <- function(type) {
    httr2::response(
      status = 200,
      headers = list("content-type" = type),
      body = charToRaw('{"access_token":"fixture","token_type":"Bearer"}')
    )
  }
  for (type in c(
    "application/json",
    "Application/JSON; charset=utf-8",
    " application/json ; charset=UTF-8",
    "text/plain",
    ""
  )) {
    expect_identical(
      parse_token_response(response(type))$access_token,
      "fixture"
    )
  }
  for (type in c(
    "application/jsonp",
    "foo-application/json",
    "text/plainx",
    "application/x-www-form-urlencodedx",
    "application/vnd.test+json"
  )) {
    expect_error(
      parse_token_response(response(type)),
      "Unsupported content type"
    )
  }
  form <- httr2::response(
    status = 200,
    headers = list(
      "content-type" = "Application/X-WWW-Form-Urlencoded; charset=utf-8"
    ),
    body = charToRaw("access_token=fixture&token_type=Bearer")
  )
  expect_identical(parse_token_response(form)$access_token, "fixture")
})
