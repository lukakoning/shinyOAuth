guid_target_client <- function(
  resource = "499b84ac-1321-427f-aa17-267ca6975798",
  mode = "microsoft",
  permission = ".default"
) {
  provider <- make_test_provider()
  provider@token_target_mode <- mode
  scope <- if (mode == "microsoft") {
    paste0(resource, "/", permission)
  } else {
    "read"
  }
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = scope,
    scope_validation = "strict",
    token_targets = list(api = list(resource = resource, scopes = scope))
  )
}

test_that("Microsoft GUID resources preserve exact code and refresh wire scopes", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (resource in c(
    "499b84ac-1321-427f-aa17-267ca6975798",
    "499B84AC-1321-427F-AA17-267CA6975798"
  )) {
    for (permission in c(".default", "Read")) {
      client <- guid_target_client(resource, permission = permission)
      sent <- list()
      evidence <- "Read"
      local_mocked_bindings(req_with_retry = function(req, ...) {
        sent[[length(sent) + 1L]] <<- lapply(
          req[["body"]][["data"]],
          function(x) {
            utils::URLdecode(gsub("+", " ", as.character(x), fixed = TRUE))
          }
        )
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(
            list(
              access_token = "access",
              refresh_token = "refresh",
              token_type = "Bearer",
              expires_in = 3600,
              scope = evidence
            ),
            auto_unbox = TRUE
          ))
        )
      })
      browser <- valid_browser_token()
      url <- prepare_call(client, browser)
      expect_identical(
        parse_query_param(url, "scope", decode = TRUE),
        client@scopes
      )
      token <- handle_callback(
        client,
        "code",
        parse_query_param(url, "state"),
        browser
      )
      fresh <- refresh_token(client, token)
      expect_identical(fresh@granted_scopes, paste0(resource, "/Read"))
      expect_length(sent, 2L)
      for (request in sent) {
        expect_null(request[["resource"]])
      }
      expect_identical(sent[[1L]][["scope"]], client@scopes)
      expect_identical(sent[[2L]][["scope"]], paste0(resource, "/Read"))
      expect_no_error(token_target_bundle_decode(
        client,
        token_target_bundle_encode(token_target_bundle(client, fresh))
      ))
      for (foreign in c(
        "11111111-1111-1111-1111-111111111111/Read",
        "api://foreign/Read",
        paste0(resource, "x/Read")
      )) {
        evidence <- foreign
        expect_error(
          refresh_token(client, fresh),
          class = "shinyOAuth_token_error"
        )
      }
    }
  }
})

test_that("GUID resource support does not relax RFC 8707 or malformed input checks", {
  guid <- "499b84ac-1321-427f-aa17-267ca6975798"
  expect_error(guid_target_client(guid, "rfc8707"), "absolute URI")
  for (invalid in c(
    paste0(guid, c("\n", "\r", " ", "#fragment", "/")),
    paste0(" ", guid),
    substring(guid, 2L),
    gsub("-", "", guid),
    sub("4", "g", guid),
    paste0("{", guid, "}")
  )) {
    expect_error(
      guid_target_client(invalid, permission = "Read"),
      "absolute URI",
      info = invalid
    )
  }
})
