for (base in c("/", "/app/")) {
  for (method in c("GET", "POST")) {
    for (async in c(FALSE, TRUE)) {
      test_that(
        paste(
          "managed Request Objects use the application base",
          base,
          method,
          async
        ),
        {
          local_options(shinyOAuth.skip_browser_token = TRUE)
          client <- make_test_client()
          client@redirect_uri <- paste0("https://app.example", base, "callback")
          client@client_secret <- strrep("s", 32)
          client@request_object_audience <- "https://issuer.example"
          client@request_object_mode <- "request_uri"
          client@authorization_method <- method
          client@resource_bases <- c(api = "https://api.example/")
          manager <- oauth_connections(
            list(site = client),
            "https://app.example"
          )
          ui <- oauth_connections_ui(
            shiny::fluidPage("App"),
            "health",
            manager,
            app_base_path = base
          )
          sent <- NULL
          work <- new.env(parent = emptyenv())
          local_mocked_bindings(
            send_oauth_module_redirect = function(session, url) {
              sent <<- url
            },
            async_dispatch = function(expr, args, ...) {
              work[["args"]] <- args
              promises::promise(function(resolve, reject) {
                work[["resolve"]] <- resolve
              })
            }
          )
          shiny::testServer(
            oauth_connections_server,
            args = list(id = "health", manager = manager, async = async),
            session = manager_test_session(),
            {
              health <- session[["getReturned"]]()
              health[["connect"]]("site")
              if (async) {
                expect_null(sent)
                work[["resolve"]](build_prepared_authorization(
                  work[["args"]][["worker"]],
                  work[["args"]][["prepared"]]
                ))
                poll_for_async(function() !is.null(sent), session)
              }
              fields <- if (method == "GET") {
                expect_type(sent, "character")
                decode_form_pairs(url_raw_query(sent), "test")
              } else {
                expect_identical(sent[["method"]], "POST")
                stats::setNames(
                  lapply(sent[["fields"]], `[[`, "value"),
                  vapply(sent[["fields"]], `[[`, "", "name")
                )
              }
              uri <- fields[["request_uri"]]
              expect_identical(
                sub("[?].*$", "", uri),
                paste0("https://app.example", base)
              )
              response <- ui(manager_test_request(
                path = base,
                query = url_raw_query(uri)
              ))
              expect_identical(response[["status"]], 200L)
              expect_identical(
                response[["content_type"]],
                "application/oauth-authz-req+jwt"
              )
              claims <- parse_jwt_payload(response[["content"]])
              expect_identical(claims[["redirect_uri"]], client@redirect_uri)
              expect_identical(claims[["client_id"]], client@client_id)
            }
          )
        }
      )
    }
  }
}
