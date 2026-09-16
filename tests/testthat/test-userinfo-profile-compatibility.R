test_that("JSON profiles keep their released shapes on retrieval, login and refresh", {
  client <- make_test_client(use_nonce = FALSE)
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@userinfo_required <- TRUE
  client@provider@userinfo_id_selector <- function(x) x[["id"]]
  profile_json <- paste0(
    '{"id":"portal-A",',
    '"allowedOrigins":["https://one.example","https://two.example"],',
    '"featuredGroups":[{"owner":"jsmith","title":"Group A"},',
    '{"owner":"adoe","title":"Group B"}],',
    '"user":{"id":"user-A","username":"jsmith",',
    '"privileges":["portal:user:createItem","portal:user:joinGroup"]}}'
  )
  expected <- jsonlite::fromJSON(profile_json)
  token_set <- list(
    access_token = "new-access",
    refresh_token = "new-refresh",
    token_type = "Bearer",
    expires_in = 3600
  )
  local_mocked_bindings(
    swap_code_for_token_set = function(...) token_set,
    req_with_retry = function(req, ...) {
      body <- if (identical(req[["url"]], client@provider@userinfo_url)) {
        profile_json
      } else {
        jsonlite::toJSON(token_set, auto_unbox = TRUE)
      }
      httr2::response(
        url = req[["url"]],
        status_code = 200L,
        headers = list("Content-Type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser_token = browser),
    "state"
  )
  logged_in <- handle_callback(
    client,
    code = "sample-code",
    state = state,
    browser_token = browser
  )
  refreshed <- refresh_token(client, logged_in)
  for (profile in list(
    get_userinfo(client, "access-token"),
    logged_in@userinfo,
    refreshed@userinfo
  )) {
    expect_identical(profile, expected)
    expect_identical(
      profile[["featuredGroups"]][["title"]],
      c("Group A", "Group B")
    )
    expect_type(profile[["allowedOrigins"]], "character")
    expect_type(profile[["user"]][["privileges"]], "character")
  }
})

test_that("login and refresh check raw claim values before simplifying profiles", {
  client <- make_test_client(use_nonce = FALSE)
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@userinfo_required <- TRUE
  client@claims_validation <- "strict"
  token_set <- list(
    access_token = "new-access",
    token_type = "Bearer",
    expires_in = 3600
  )
  body <- NULL
  local_mocked_bindings(
    swap_code_for_token_set = function(...) token_set,
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status_code = 200L,
        headers = list("Content-Type" = "application/json"),
        body = charToRaw(
          if (identical(req[["url"]], client@provider@userinfo_url)) {
            body
          } else {
            jsonlite::toJSON(token_set, auto_unbox = TRUE)
          }
        )
      )
    },
    .package = "shinyOAuth"
  )
  for (operation in c("login", "refresh")) {
    run <- function() {
      if (operation == "refresh") {
        refresh_token(
          client,
          OAuthToken(access_token = "old", refresh_token = "refresh")
        )
      } else {
        browser <- valid_browser_token()
        state <- parse_query_param(
          prepare_call(client, browser_token = browser),
          "state"
        )
        handle_callback(
          client,
          code = "sample-code",
          state = state,
          browser_token = browser
        )
      }
    }
    for (value in list("staff", list("staff"), list(groups = list("staff")))) {
      body <- as.character(jsonlite::toJSON(
        list(sub = "user", role = value),
        auto_unbox = TRUE
      ))
      client@claims <- list(userinfo = list(role = list(value = value)))
      result <- run()
      expect_identical(result@userinfo, jsonlite::fromJSON(body))

      other <- if (is.list(value)) "staff" else list("staff")
      client@claims <- list(userinfo = list(role = list(value = other)))
      expect_error(run(), class = "shinyOAuth_userinfo_error")
    }
    client@claims <- list(userinfo = list(email = list(essential = TRUE)))
    expect_error(run(), class = "shinyOAuth_userinfo_error")
  }
})
