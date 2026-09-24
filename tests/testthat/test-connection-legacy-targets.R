test_that("legacy wrappers reject target clients before reading token evidence", {
  for (mode in c("rfc8707", "microsoft")) {
    client <- make_test_client(scopes = "https://api.example/read")
    provider <- client@provider
    provider@token_target_mode <- mode
    S7::props(client) <- list(
      provider = provider,
      token_targets = list(
        api = list(
          resource = "https://api.example",
          scopes = "https://api.example/read"
        )
      ),
      default_token_target = "api"
    )
    shiny::testServer(function(input, output, session) {}, {
      reads <- 0L
      source <- shiny::reactive({
        reads <<- reads + 1L
        manager_test_token()
      })
      expect_error(oauth_connection(client, source), "connection\\(\\) factory")
      expect_identical(reads, 0L)
    })
  }
})

test_that("broader Microsoft refresh cannot escape the factory permission limit", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  read <- "https://api.example/read"
  write <- "https://api.example/write"
  client <- make_test_client(use_nonce = FALSE, scopes = c(read, write))
  client@scope_validation <- "none"
  provider <- client@provider
  provider@token_target_mode <- "microsoft"
  S7::props(client) <- list(
    provider = provider,
    resource_bases = c(api = "https://api.example/v1"),
    token_targets = list(
      api = list(
        resource = "https://api.example",
        scopes = c(read, write),
        resource_ids = "api"
      )
    ),
    default_token_target = "api"
  )
  resource_calls <- 0L
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    perform_resource_req = function(...) resource_calls <<- resource_calls + 1L,
    req_with_retry = function(req, ...) {
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(paste0(
          '{"access_token":"new","refresh_token":"rotated",',
          '"token_type":"Bearer","expires_in":3600,"scope":"read write"}'
        ))
      )
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      initial <- manager_test_token()
      initial@granted_scopes <- read
      .accept_login_token(initial, NULL)
      current <- values[["connection"]]()
      expect_true(current[["refresh"]]())
      expect_true(write %in% values[["token"]]@granted_scopes)
      expect_false(current[["has_scopes"]](write))
      expect_error(
        current[["request"]]("api", required_scopes = write),
        "does not cover"
      )
      expect_error(
        oauth_connection(client, shiny::reactive(values[["token"]])),
        "connection\\(\\) factory"
      )
      expect_identical(resource_calls, 0L)
    }
  )
})
