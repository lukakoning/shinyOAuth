# --- Relative URLs -----------------------------------------------------------

test_that("client_bearer_req rejects relative URLs", {
  expect_error(
    client_bearer_req(token = "tok", url = "/api/resource"),
    class = "shinyOAuth_input_error"
  )

  expect_error(
    client_bearer_req(token = "tok", url = "api/resource"),
    class = "shinyOAuth_input_error"
  )

  expect_error(
    client_bearer_req(token = "tok", url = ""),
    class = "shinyOAuth_input_error"
  )
})

# --- Insecure HTTP hosts ----------------------------------------------------

test_that("client_bearer_req rejects plain HTTP to non-loopback hosts", {
  expect_error(
    client_bearer_req(token = "tok", url = "http://evil.example.com/leak"),
    class = "shinyOAuth_input_error"
  )

  expect_error(
    client_bearer_req(token = "tok", url = "http://api.example.com/v1"),
    class = "shinyOAuth_input_error"
  )
})

# --- Allowed HTTP loopback hosts --------------------------------------------

test_that("client_bearer_req allows HTTP to localhost/loopback", {
  req <- client_bearer_req(token = "tok", url = "http://localhost:8080/api")
  expect_s3_class(req, "httr2_request")

  req2 <- client_bearer_req(token = "tok", url = "http://127.0.0.1:3000/api")
  expect_s3_class(req2, "httr2_request")
})

# --- HTTPS always allowed ---------------------------------------------------

test_that("client_bearer_req allows HTTPS URLs", {
  req <- client_bearer_req(
    token = "tok",
    url = "https://api.example.com/resource"
  )
  expect_s3_class(req, "httr2_request")
})

# --- Disallowed hosts via option --------------------------------------------

test_that("client_bearer_req rejects hosts not in allowed_hosts option", {
  withr::local_options(shinyOAuth.allowed_hosts = c("trusted.example.com"))

  # Allowed host passes
  req <- client_bearer_req(
    token = "tok",
    url = "https://trusted.example.com/api"
  )
  expect_s3_class(req, "httr2_request")

  # Disallowed host is rejected
  expect_error(
    client_bearer_req(token = "tok", url = "https://evil.example.com/steal"),
    class = "shinyOAuth_input_error"
  )
})

# --- check_url = FALSE override ---------------------------------------------

test_that("client_bearer_req skips validation when check_url = FALSE", {
  # Even a blatantly bad URL is accepted
  req <- client_bearer_req(
    token = "tok",
    url = "http://evil.example.com/leak",
    check_url = FALSE
  )
  expect_s3_class(req, "httr2_request")
})

# --- Non-string / NULL URL --------------------------------------------------

test_that("client_bearer_req rejects NULL and non-string URLs", {
  expect_error(
    client_bearer_req(token = "tok", url = NULL),
    class = "shinyOAuth_input_error"
  )

  expect_error(
    client_bearer_req(token = "tok", url = 42),
    class = "shinyOAuth_input_error"
  )
})
