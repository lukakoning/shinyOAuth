test_that("resource headers reject malformed fields before credentials", {
  for (headers in list(
    setNames(list("value"), "Host: other.example\r\nX-Injected"),
    setNames(list("value"), "Authorization:"),
    setNames(list("value"), "Host "),
    setNames(list("value"), ":authority"),
    list(`X-App` = "value\r\nHost: other.example"),
    list(`X-App` = "value\nAuthorization: injected"),
    list(`X-App` = "value\001other"),
    list(`X-App` = "value\177other"),
    list(`X-App` = NA_character_),
    list(`X-App` = "one", `x-app` = "two")
  )) {
    expect_error(
      resource_req(NULL, "https://example.com/resource", headers = headers),
      "HTTP header", class = "shinyOAuth_input_error"
    )
    req <- httr2::request("https://example.com/resource")
    req[["headers"]] <- headers
    expect_error(perform_resource_req(NULL, req),
      "HTTP header", class = "shinyOAuth_input_error")
  }
  req <- httr2::request("https://example.com/resource") |>
    httr2::req_body_raw("body", type = "text/plain\r\nHost: other.example")
  expect_error(perform_resource_req(NULL, req), "HTTP header")
  redacted <- httr2::request("https://example.com/resource") |>
    httr2::req_auth_bearer_token("token\r\nHost: other.example")
  expect_error(perform_resource_req(NULL, redacted), "HTTP header")
  expect_error(
    resource_req("token\r\nHost: other.example", "https://example.com/resource"),
    "invalid characters"
  )
  expect_no_error(resource_req("synthetic", "https://example.com/resource",
    headers = list(`X-App` = "valid\tvalue", `X-Count` = 1,
      Accept = c("application/json", "text/plain"))))
  expect_no_error(resource_req("synthetic", "https://example.com/resource",
    headers = list(`X-Removed` = NULL)))
})

test_that("provider and endpoint configuration require valid HTTP header syntax", {
  for (headers in list(
    setNames("value", "Authorization:"),
    setNames("value", "Host: other.example\r\nX-Injected"),
    c(`X-App` = "value\r\nHost: other.example"),
    c(`X-App` = "value\177other"),
    c(`X-App` = "one", `x-app` = "two")
  )) {
    provider <- make_test_provider()
    expect_error({ provider@extra_token_headers <- headers }, "HTTP header")
    client <- make_test_client()
    expect_error({
      client@endpoint_auth <- list(introspection = list(extra_headers = headers))
    }, "safe headers")
  }
})

test_that("DPoP requests cannot override their signed authority", {
  cli <- make_test_client(use_nonce = FALSE)
  cli@dpop_private_key <- openssl::ec_keygen()
  for (req in list(
    httr2::request("https://example.com/resource"),
    httr2::request("https://example.com/resource") |>
      httr2::req_headers(Host = "other.example")
  )) {
    expect_error(
      perform_resource_req("synthetic", req, client = cli, token_type = "DPoP",
        headers = list(Host = "other.example")),
      "must not override the Host header"
    )
  }
  expect_error(perform_resource_req("synthetic",
    httr2::request("https://example.com/resource") |>
      httr2::req_headers(Host = "other.example"),
    client = cli, token_type = "DPoP"), "must not override the Host header")
})

test_that("managed header rejection is observable at the actual HTTP receiver", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app[["locals"]][["requests"]] <- list()
  app[["get"]]("/evidence", function(req, res) {
    res[["send_json"]](req[["app"]][["locals"]][["requests"]])
  })
  app[["use"]](function(req, res) {
    entry <- list(
      host = req[["get_header"]]("host"),
      authorization = req[["get_header"]]("authorization"),
      dpop = req[["get_header"]]("dpop"),
      application = req[["get_header"]]("x-app")
    )
    req[["app"]][["locals"]][["requests"]] <- c(
      req[["app"]][["locals"]][["requests"]], list(entry)
    )
    res[["send_json"]](entry)
  })
  server <- webfakes::local_app_process(app)
  url <- server[["url"]]("/resource")
  cli <- make_test_client(use_nonce = FALSE)
  cli@dpop_private_key <- openssl::ec_keygen()
  cli@resource_bases <- c(api = url)
  token <- OAuthToken(access_token = "synthetic", token_type = "DPoP",
    expires_at = as.numeric(Sys.time()) + 120)
  shiny::testServer(function(input, output, session) {}, {
    connection <- oauth_connection(cli, shiny::reactive(token))
    configurations <- list(
      function(req) httr2::req_headers(req, `X-App` = "value\r\nHost: other.example"),
      function(req) do.call(httr2::req_headers,
        c(list(req), setNames(list("value"), "Host: other.example\r\nX-Injected"))),
      function(req) httr2::req_headers(req, `Host:` = "other.example"),
      function(req) httr2::req_headers(req, hOsT = "other.example"),
      function(req) httr2::req_body_raw(req, "body",
        type = "text/plain\r\nHost: other.example")
    )
    for (configure in configurations) {
      expect_error(connection[["request"]]("api", configure = configure),
        class = "shinyOAuth_http_error")
    }
    response <- connection[["request"]]("api", method = "POST",
      configure = function(req) httr2::req_body_json(req, list(action = "valid")) |>
        httr2::req_headers(`X-App` = "valid"))
    received <- httr2::resp_body_json(response, simplifyVector = TRUE)
    expect_identical(received[["authorization"]], "DPoP synthetic")
    expect_identical(received[["application"]], "valid")
    expect_identical(shinyOAuth:::parse_jwt_payload(received[["dpop"]])[["htu"]], url)
  })
  evidence <- httr2::request(server[["url"]]("/evidence")) |>
    httr2::req_perform() |>
    httr2::resp_body_json(simplifyVector = FALSE)
  expect_length(evidence, 1L)
  expect_match(unlist(evidence[[1L]][["host"]]),
    "^(127\\.0\\.0\\.1|localhost):[0-9]+$")
})
