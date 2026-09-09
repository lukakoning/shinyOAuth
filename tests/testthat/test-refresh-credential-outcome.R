test_that("refresh failures report the renewal credential lifecycle", {
  client <- make_test_client(use_nonce = FALSE)
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@userinfo_required <- TRUE
  previous <- OAuthToken(
    access_token = "previous",
    refresh_token = "previous-refresh"
  )
  response <- function(body, status = 200L) {
    httr2::response(
      url = client@provider@token_url,
      status = status,
      headers = list("content-type" = "application/json"),
      body = charToRaw(body)
    )
  }
  scenario <- "rotated"
  local_mocked_bindings(
    req_with_retry = function(...) {
      switch(
        scenario,
        transport = stop("connection interrupted"),
        rejected = response('{"error":"invalid_grant"}', 400L),
        unavailable = response('{"error":"temporarily_unavailable"}', 503L),
        rotated = response(paste0(
          '{"access_token":"replacement","token_type":"Bearer",',
          '"refresh_token":"replacement-refresh","expires_in":3600}'
        )),
        unchanged = response(paste0(
          '{"access_token":"replacement","token_type":"Bearer",',
          '"expires_in":3600}'
        ))
      )
    },
    get_userinfo = function(...) stop("UserInfo unavailable"),
    .package = "shinyOAuth"
  )
  expected <- c(
    rotated = "consumed",
    unchanged = "not_consumed",
    transport = "possibly_consumed",
    rejected = "rejected",
    unavailable = "not_consumed"
  )
  for (scenario in names(expected)) {
    error <- tryCatch(refresh_token(client, previous), error = identity)
    expect_s3_class(error, "error")
    expect_identical(error$refresh_credential_outcome, expected[[scenario]])
    expect_identical(previous@access_token, "previous")
    expect_identical(previous@refresh_token, "previous-refresh")
  }
  local_mocked_bindings(
    apply_direct_client_auth = function(...) stop("credentials unavailable"),
    .package = "shinyOAuth"
  )
  error <- tryCatch(refresh_token(client, previous), error = identity)
  expect_identical(error$refresh_credential_outcome, "not_consumed")
})

test_that("refresh lifecycle errors survive async dispatch and replay", {
  skip_if_not_installed("mirai")
  skip_if_not_installed("promises")
  skip_if_not_installed("later")
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))
  client <- make_test_client(use_nonce = FALSE)
  previous <- OAuthToken(
    access_token = "previous",
    refresh_token = "previous-refresh"
  )
  local_mocked_bindings(
    req_with_retry = function(...) {
      httr2::response(
        url = client@provider@token_url,
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(paste0(
          '{"access_token":"replacement","token_type":"Bearer",',
          '"refresh_token":"replacement-refresh","expires_in":3600}'
        ))
      )
    },
    verify_token_set = function(...) stop("candidate validation failed"),
    .package = "shinyOAuth"
  )
  error <- NULL
  promises::catch(refresh_token(client, previous, async = TRUE), function(e) {
    error <<- e
    NULL
  })
  deadline <- Sys.time() + 5
  while (is.null(error) && Sys.time() < deadline) {
    later::run_now(0.01)
  }
  expect_s3_class(error, "error")
  expect_identical(error$refresh_credential_outcome, "consumed")
  expect_match(conditionMessage(error), "candidate validation failed")
  expect_identical(
    unserialize(serialize(error, NULL))$refresh_credential_outcome,
    "consumed"
  )
})

for (async in c(FALSE, TRUE)) {
  for (outcome in c(
    "not_consumed",
    "consumed",
    "possibly_consumed",
    "rejected"
  )) {
    test_that(
      paste("module retains only retryable credentials", async, outcome),
      {
        skip_if_not_installed("promises")
        skip_if_not_installed("later")
        local_options(shinyOAuth.skip_browser_token = TRUE)
        calls <- 0L
        local_mocked_bindings(
          refresh_token = function(...) {
            calls <<- calls + 1L
            error <- refresh_outcome_error(
              simpleError("refresh failed"),
              outcome
            )
            if (async) promises::promise_reject(error) else stop(error)
          },
          .package = "shinyOAuth"
        )
        shiny::testServer(
          oauth_module_server,
          args = list(
            id = "auth",
            client = make_test_client(use_nonce = FALSE),
            auto_redirect = FALSE,
            async = async,
            indefinite_session = TRUE,
            refresh_proactively = TRUE
          ),
          {
            values$token <- OAuthToken(
              access_token = "previous",
              refresh_token = "previous-refresh",
              expires_at = as.numeric(Sys.time()) + 30
            )
            for (i in seq_len(10L)) {
              session$flushReact()
              later::run_now(0)
            }
            expect_identical(values$token@access_token, "previous")
            expect_identical(
              values$token@refresh_token,
              if (outcome == "not_consumed") {
                "previous-refresh"
              } else {
                NA_character_
              }
            )
            expect_true(values$token_stale)
            expect_false(values$refresh_in_progress)
            if (outcome != "not_consumed") {
              values$refresh_next_attempt_at <- 0
              session$flushReact()
              expect_identical(calls, 1L)
            }
          }
        )
      }
    )
  }
}
