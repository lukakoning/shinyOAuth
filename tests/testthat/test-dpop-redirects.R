test_that("DPoP resource helpers reject redirects before signing or transport", {
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-redirect-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  signed <- 0L
  sent <- 0L
  testthat::local_mocked_bindings(
    build_dpop_proof = function(...) {
      signed <<- signed + 1L
      stop("Unexpected proof signing")
    },
    req_with_retry = function(...) {
      sent <<- sent + 1L
      stop("Unexpected request transport")
    },
    .package = "shinyOAuth"
  )
  withr::local_options(shinyOAuth.allow_redirect = TRUE)

  for (follow in list(TRUE, NULL)) {
    expect_error(
      resource_req(
        "access-token",
        "https://resource.example.com/redirect",
        client = client,
        token_type = "DPoP",
        follow_redirect = follow
      ),
      regexp = "DPoP requests cannot follow HTTP redirects",
      class = "shinyOAuth_input_error"
    )
    expect_error(
      perform_resource_req(
        "access-token",
        httr2::request("https://resource.example.com/redirect"),
        client = client,
        token_type = "DPoP",
        follow_redirect = follow
      ),
      regexp = "DPoP requests cannot follow HTTP redirects",
      class = "shinyOAuth_input_error"
    )
  }
  expect_identical(signed, 0L)
  expect_identical(sent, 0L)
})

test_that("DPoP resource default overrides globally enabled redirects", {
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-redirect-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  withr::local_options(shinyOAuth.allow_redirect = TRUE)
  request <- resource_req(
    "access-token",
    "https://resource.example.com/resource",
    client = client,
    token_type = "DPoP"
  )
  expect_false(request[["options"]][["followlocation"]])
  expect_true(nzchar(request[["headers"]][["DPoP"]]))

  bearer <- resource_req(
    "access-token",
    "https://resource.example.com/resource",
    follow_redirect = NULL
  )
  expect_true(bearer[["options"]][["followlocation"]])
})

test_that("DPoP provider and retry proofs reject inherited or explicit redirects", {
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-redirect-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  testthat::local_mocked_bindings(
    build_dpop_proof = function(...) stop("Unexpected proof signing"),
    req_with_retry = function(...) stop("Unexpected request transport"),
    .package = "shinyOAuth"
  )
  withr::local_options(shinyOAuth.allow_redirect = TRUE)
  request <- httr2::request("https://example.com/token") |>
    httr2::req_method("POST")
  expect_error(
    shinyOAuth:::req_with_dpop_retry(request, client),
    regexp = "DPoP requests cannot follow HTTP redirects",
    class = "shinyOAuth_input_error"
  )
  withr::local_options(shinyOAuth.allow_redirect = FALSE)
  request <- httr2::req_options(request, followlocation = TRUE)
  expect_error(
    shinyOAuth:::req_add_dpop_proof(request, client),
    regexp = "DPoP requests cannot follow HTTP redirects",
    class = "shinyOAuth_input_error"
  )
})

test_that("DPoP resource calls return redirect responses without following them", {
  testthat::skip_if_not_installed("webfakes")
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-redirect-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  app <- webfakes::new_app()
  app[["get"]]("/redirect", function(req, res) {
    res[["set_status"]](302L)
    res[["set_header"]]("Location", "/target")
    res[["send"]]("redirect")
  })
  app[["get"]]("/target", function(req, res) res[["send"]]("target"))
  server <- webfakes::local_app_process(app)
  withr::local_options(shinyOAuth.allow_redirect = TRUE)

  response <- perform_resource_req(
    "access-token",
    paste0(server[["url"]](), "/redirect"),
    client = client,
    token_type = "DPoP",
    idempotent = FALSE
  )
  expect_identical(httr2::resp_status(response), 302L)
  expect_identical(httr2::resp_header(response, "location"), "/target")
})
