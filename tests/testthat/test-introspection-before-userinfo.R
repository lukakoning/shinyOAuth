test_that("login and refresh reject ineligible introspection before UserInfo", {
  cli <- make_test_client(use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@userinfo_required <- TRUE
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@introspect <- TRUE
  cli@introspect_elements <- c("client_id", "scope", "sub")
  cli@scope_validation <- "strict"
  cli@scopes <- "profile"
  calls <- character()
  intro <- NULL
  token_set <- list(access_token = "new", token_type = "Bearer",
                    expires_in = 3600, scope = "profile")
  local_mocked_bindings(
    swap_code_for_token_set = function(...) token_set,
    req_with_retry = function(req, ...) httr2::response(
      url = req$url, status = 200,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(token_set, auto_unbox = TRUE))
    ),
    introspect_token = function(...) {
      calls <<- c(calls, "introspection")
      intro
    },
    get_userinfo = function(...) {
      calls <<- c(calls, "userinfo")
      list(sub = "user")
    },
    .package = "shinyOAuth"
  )
  valid <- list(supported = TRUE, active = TRUE, status = "ok",
                raw = list(client_id = cli@client_id, scope = "profile", sub = "user"))
  cases <- list(
    unsupported = modifyList(valid, list(supported = FALSE)),
    unknown = modifyList(valid, list(active = NA)),
    inactive = modifyList(valid, list(active = FALSE)),
    client = modifyList(valid, list(raw = list(client_id = "another-client"))),
    scope = modifyList(valid, list(raw = list(scope = "other"))),
    expired = modifyList(valid, list(raw = list(exp = 1))),
    malformed_expiry = modifyList(valid, list(raw = list(exp = "later"))),
    missing_subject = modifyList(valid, list(raw = list(sub = ""))),
    valid = valid,
    subject_mismatch = modifyList(valid, list(raw = list(sub = "different-user")))
  )
  for (operation in c("login", "refresh")) {
    for (case in names(cases)) {
      intro <- cases[[case]]
      calls <- character()
      result <- tryCatch({
        if (operation == "login") {
          browser <- valid_browser_token()
          state <- parse_query_param(prepare_call(cli, browser_token = browser), "state")
          handle_callback(cli, code = "sample-code", payload = state, browser_token = browser)
        } else {
          refresh_token(cli, OAuthToken(access_token = "old", refresh_token = "refresh"))
        }
      }, error = identity)
      if (case == "valid") {
        expect_s3_class(result, "shinyOAuth::OAuthToken")
      } else {
        expect_s3_class(result, "shinyOAuth_token_error")
      }
      expected <- if (case %in% c("valid", "subject_mismatch")) {
        c("introspection", "userinfo")
      } else "introspection"
      expect_identical(calls, expected, info = paste(operation, case))
    }
  }
})
