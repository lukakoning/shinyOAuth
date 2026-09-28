test_that("rejected target credentials are discarded when the module clears authorization", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("api://primary/.default", "api://secondary/.default"),
    token_targets = list(
      primary = list(
        resource = "api://primary",
        scopes = "api://primary/.default"
      ),
      secondary = list(
        resource = "api://secondary",
        scopes = "api://secondary/.default"
      )
    ),
    default_token_target = "primary"
  )
  primary <- manager_test_token()
  primary@granted_scopes <- paste0("api://primary/permission", 1:64)
  for (async in c(FALSE, TRUE)) {
    for (indefinite in c(FALSE, TRUE)) {
      for (rejection in c("bundle_budget", "foreign_grant", "logout")) {
        fresh <- manager_test_token(
          access = "fresh-rejected",
          refresh = "rotated"
        )
        fresh@granted_scopes <- if (rejection == "foreign_grant") {
          "api://foreign/read"
        } else {
          paste0("api://secondary/permission", 1:65)
        }
        complete <- NULL
        revoked <- list()
        local_mocked_bindings(
          refresh_token_dispatch = function(..., async = FALSE) {
            if (async) {
              promises::promise(function(resolve, reject) {
                complete <<- resolve
              })
            } else {
              fresh
            }
          },
          revoke_token = function(client, token, token_kind, ...) {
            revoked[[length(revoked) + 1L]] <<- list(
              kind = token_kind,
              access = token@access_token,
              refresh = token@refresh_token
            )
            # Cleanup remains best effort if the provider rejects revocation.
            if (identical(token@access_token, "fresh-rejected")) {
              stop("synthetic revocation failure")
            }
          }
        )
        if (rejection == "logout" && !async) {
          next
        }
        shiny::testServer(
          oauth_module_server,
          args = list(
            id = "auth",
            client = client,
            async = async,
            indefinite_session = indefinite,
            auto_redirect = FALSE
          ),
          {
            .accept_login_token(primary, NULL)
            current <- values[["connection"]]()
            result <- NULL
            if (async) {
              promises::then(
                current[["access_token"]](target = "secondary", async = TRUE),
                function(value) {
                  result <<- value
                },
                function(error) {
                  result <<- error
                }
              )
              if (rejection == "logout") {
                values[["logout"]]()
                revoked <<- list()
              }
              complete(fresh)
              poll_for_async(function() !is.null(result), session)
            } else {
              result <- tryCatch(
                current[["access_token"]](target = "secondary"),
                error = identity
              )
            }
            expect_s3_class(result, "shinyOAuth_access_error")
            if (indefinite && rejection != "logout") {
              expect_length(revoked, 0L)
              expect_identical(
                values[["token"]]@access_token,
                primary@access_token
              )
              expect_identical(
                current[["access_token"]](),
                primary@access_token
              )
              expect_false(is_valid_string(values[["token"]]@refresh_token))
            } else {
              expect_null(values[["token"]])
              expect_error(
                current[["access_token"]](),
                class = "shinyOAuth_access_error"
              )
              expect_length(revoked, 2L)
              expect_identical(
                vapply(revoked, function(x) x[["kind"]], ""),
                c("refresh", "access")
              )
              expect_true(all(vapply(
                revoked,
                function(x) {
                  identical(x[["access"]], "fresh-rejected") &&
                    identical(x[["refresh"]], "rotated")
                },
                logical(1)
              )))
              values[["logout"]]()
              expect_length(revoked, 2L)
            }
          }
        )
      }
    }
  }
})
