test_that("resource builders reject additional query token transport after shaping", {
  for (name in c("access_token", "access%5ftoken", "%61ccess_token")) {
    target <- paste0(
      "https://api.example.com/items?",
      name,
      "=other-credential"
    )
    expect_error(
      resource_req("managed-credential", target),
      "must not combine",
      class = "shinyOAuth_input_error"
    )
    expect_error(
      resource_req("managed-credential", target, check_url = FALSE),
      "must not combine"
    )
    expect_error(
      perform_resource_req("managed-credential", httr2::request(target)),
      "must not combine"
    )
  }
  expect_error(
    resource_req(
      "managed",
      "https://api.example.com",
      query = list(access_token = "other")
    ),
    "must not combine"
  )
  req <- resource_req(
    "managed",
    "https://api.example.com?token=business&Access_token=case-sensitive"
  )
  expect_match(req$url, "token=business", fixed = TRUE)
  err <- tryCatch(
    resource_req(
      "managed-credential",
      "https://api.example.com?access_token=other-credential"
    ),
    error = identity
  )
  expect_false(grepl(
    "managed-credential|other-credential",
    conditionMessage(err)
  ))
})

test_that("prebuilt supported form bodies cannot supply a second token", {
  base <- httr2::request("https://api.example.com/items")
  bodies <- list(
    httr2::req_body_form(base, access_token = "other"),
    httr2::req_body_raw(
      base,
      "access%5ftoken=other",
      type = "application/x-www-form-urlencoded"
    ),
    httr2::req_body_raw(
      base,
      charToRaw("access_token=other"),
      type = "application/x-www-form-urlencoded; charset=UTF-8"
    ),
    httr2::req_body_raw(base, "access_token=other") |>
      httr2::req_headers(`content-type` = "application/x-www-form-urlencoded")
  )
  for (req in bodies) {
    expect_error(
      perform_resource_req("managed", req, check_url = FALSE),
      "must not combine",
      class = "shinyOAuth_input_error"
    )
  }
})

test_that("JSON and unrelated form fields retain ordinary header authentication", {
  base <- httr2::request("https://api.example.com/items")
  bodies <- list(
    httr2::req_body_form(base, token = "business", Access_token = "business"),
    httr2::req_body_json(base, list(access_token = "business")),
    httr2::req_body_raw(
      base,
      '{"access_token":"business"}',
      type = "application/json"
    )
  )
  testthat::local_mocked_bindings(
    req_perform = function(req, ...) {
      dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
      expect_identical(dry$headers$authorization, "Bearer managed")
      httr2::response(status = 200, body = charToRaw("ok"))
    },
    .package = "httr2"
  )
  for (req in bodies) {
    expect_s3_class(perform_resource_req("managed", req), "httr2_response")
  }
})

test_that("DPoP requests enforce the same token transport boundary", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@dpop_private_key <- openssl::ec_keygen()
  expect_error(
    resource_req(
      "managed",
      "https://api.example.com?access_token=other",
      token_type = "DPoP",
      oauth_client = client
    ),
    "must not combine"
  )
})
