test_that("method-changing curl options are rejected before credentials", {
  base <- httr2::request("https://example.com/mutate") |>
    httr2::req_body_json(list(action = "create"))
  options <- list(
    customrequest = "TRACE",
    nobody = FALSE,
    httpget = TRUE,
    post = FALSE,
    upload = TRUE,
    put = TRUE,
    postfields = "action=create",
    copypostfields = "action=create",
    httppost = list(),
    mimepost = list()
  )
  for (name in names(options)) {
    req <- base
    req[["options"]][name] <- options[name]
    expect_error(
      perform_resource_req(NULL, req),
      "method-changing curl options",
      class = "shinyOAuth_input_error",
      info = name
    )
  }
})

test_that("wire methods agree with DPoP and retry policy", {
  skip_if_not_installed("webfakes")
  withr::local_options(list(
    shinyOAuth.retry_max_tries = 2L,
    shinyOAuth.retry_backoff_base = 0.001,
    shinyOAuth.retry_backoff_cap = 0.002
  ))
  app <- webfakes::new_app()
  app[["locals"]][["requests"]] <- list()
  app[["get"]]("/evidence", function(req, res) {
    res[["send_json"]](req[["app"]][["locals"]][["requests"]])
  })
  app[["use"]](function(req, res) {
    req[["app"]][["locals"]][["requests"]] <- c(
      req[["app"]][["locals"]][["requests"]],
      list(list(
        method = req[["method"]],
        label = req[["get_header"]]("x-case"),
        dpop = req[["get_header"]]("dpop")
      ))
    )
    res[["set_status"]](500L)
    res[["send"]]("")
  })
  server <- webfakes::local_app_process(app)
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@dpop_private_key <- openssl::ec_keygen()
  base <- httr2::request(server[["url"]]("/mutate"))

  # Rejected conflicts must not reach the server, even with an explicit method.
  conflict <- httr2::req_body_json(base, list(action = "create")) |>
    httr2::req_options(nobody = FALSE, customrequest = "TRACE")
  for (method in list(NULL, "HEAD", "POST")) {
    expect_error(
      perform_resource_req("fixture", conflict, method = method),
      "method-changing curl options"
    )
  }
  for (req in list(
    httr2::req_body_json(base, list(action = "create")),
    httr2::req_body_form(base, action = "create"),
    httr2::req_body_raw(base, "create")
  )) {
    expect_error(
      perform_resource_req(
        "fixture",
        httr2::req_method(req, "HEAD"),
        client = client,
        token_type = "DPoP"
      ),
      "HEAD resource requests must not include a body"
    )
  }

  for (method in c("GET", "HEAD", "POST", "PATCH", "PUT", "DELETE")) {
    req <- if (identical(method, "POST")) {
      httr2::req_body_json(base, list(action = "create"))
    } else {
      if (identical(method, "HEAD")) {
        httr2::req_method(base, method)
      } else {
        httr2::req_body_json(base, list(action = "create")) |>
          httr2::req_method(method)
      }
    }
    req <- httr2::req_headers(req, `X-Case` = method)
    response <- perform_resource_req(
      "fixture",
      req,
      client = client,
      token_type = "DPoP"
    )
    expect_identical(httr2::resp_status(response), 500L)
  }
  evidence <- httr2::request(server[["url"]]("/evidence")) |>
    httr2::req_perform() |>
    httr2::resp_body_json(simplifyVector = FALSE)
  evidence <- lapply(evidence, function(x) lapply(x, unlist, use.names = FALSE))
  labels <- vapply(evidence, function(x) x[["label"]], character(1))
  for (method in c("GET", "HEAD", "POST", "PATCH", "PUT", "DELETE")) {
    expect_equal(
      sum(labels == method),
      if (method %in% c("POST", "PATCH")) 1 else 2
    )
  }
  expect_length(evidence, 10L)
  for (entry in evidence) {
    expect_identical(toupper(entry[["method"]]), entry[["label"]])
    expect_identical(
      parse_jwt_payload(entry[["dpop"]])[["htm"]],
      toupper(entry[["method"]])
    )
  }
})
