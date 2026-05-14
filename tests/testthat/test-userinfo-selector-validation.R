make_provider <- function(...) {
  oauth_provider(
    name = "ex",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    issuer = "https://example.com",
    ...
  )
}

make_client <- function(provider) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "secret",
    redirect_uri = "https://app.example.com/callback"
  )
}

test_that("userinfo_id_selector must yield scalar string", {
  prov <- make_provider(
    id_token_validation = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(x) list("not-a-scalar", "extra")
  )
  cli <- make_client(prov)
  # Create a minimal HS256 token for deterministic test; enable HS* temporarily
  withr::local_options(list(shinyOAuth.allow_hs = TRUE))
  header <- list(alg = "HS256")
  now <- as.numeric(Sys.time())
  claim <- jose::jwt_claim(
    iss = prov@issuer,
    aud = cli@client_id,
    sub = "123",
    exp = now + 3600,
    iat = now
  )
  token <- jose::jwt_encode_hmac(claim, cli@client_secret, header = header)

  ui <- list(sub = c("123", "456"))

  expect_error(
    verify_userinfo_id_token_subject_match(cli, ui, token),
    regexp = "selector .* scalar|coercible|invalid userinfo subject",
    class = "shinyOAuth_userinfo_error"
  )
})

test_that("userinfo subject mismatch still errors specifically", {
  prov <- make_provider(
    id_token_validation = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(x) x$sub
  )
  cli <- make_client(prov)
  withr::local_options(list(shinyOAuth.allow_hs = TRUE))
  header <- list(alg = "HS256")
  now <- as.numeric(Sys.time())
  claim <- jose::jwt_claim(
    iss = prov@issuer,
    aud = cli@client_id,
    sub = "123",
    exp = now + 3600,
    iat = now
  )
  token <- jose::jwt_encode_hmac(claim, cli@client_secret, header = header)

  ui <- list(sub = "different-sub")

  expect_error(
    verify_userinfo_id_token_subject_match(cli, ui, token),
    regexp = "does not match",
    class = "shinyOAuth_userinfo_mismatch"
  )
})

test_that("custom selector also drives the UserInfo OIDC comparison", {
  prov <- make_provider(
    id_token_validation = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(x) x$id
  )
  cli <- make_client(prov)
  withr::local_options(list(shinyOAuth.allow_hs = TRUE))
  header <- list(alg = "HS256")
  now <- as.numeric(Sys.time())
  claim <- jose::jwt_claim(
    iss = prov@issuer,
    aud = cli@client_id,
    sub = "id-token-sub",
    exp = now + 3600,
    iat = now
  )
  token <- jose::jwt_encode_hmac(claim, cli@client_secret, header = header)
  ui <- list(sub = "different-sub", id = "id-token-sub")

  expect_true(isTRUE(verify_userinfo_id_token_subject_match(cli, ui, token)))
})

test_that("get_userinfo audit normalizes custom selector output", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@userinfo_id_selector <- function(x) x$id

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events <<- c(events, list(event))
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(sub = "fallback-sub", id = 12345),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  result <- get_userinfo(cli, token = "access-token")
  expect_equal(result$id, 12345)

  ui_events <- Filter(function(e) identical(e$type, "audit_userinfo"), events)
  expect_length(ui_events, 1L)
  expect_identical(ui_events[[1L]]$status, "ok")
  expect_identical(
    ui_events[[1L]]$sub_digest,
    shinyOAuth:::string_digest("12345")
  )
})
