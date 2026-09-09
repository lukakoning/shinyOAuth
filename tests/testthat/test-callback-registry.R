registry_test_clients <- function(shared = FALSE, jarm = FALSE, post = FALSE) {
  redirects <- if (shared) {
    rep("https://app.example/callback", 2L)
  } else {
    c("https://app.example/a/callback", "https://app.example/b/callback")
  }
  clients <- lapply(seq_len(2L), function(i) {
    issuer <- paste0("https://issuer", i, ".example")
    provider <- oauth_provider(
      name = paste0("provider", i),
      issuer = issuer,
      issuer_thus_oidc = FALSE,
      auth_url = paste0(issuer, "/authorize"),
      token_url = paste0(issuer, "/token"),
      token_auth_style = "public",
      use_nonce = FALSE,
      authorization_response_iss_parameter_supported = TRUE
    )
    oauth_client(
      provider,
      client_id = paste0("client", i),
      client_secret = strrep(as.character(i), 64),
      redirect_uri = redirects[[i]],
      state_key = strrep(as.character(i), 64),
      authorization_server_mode = if (shared) {
        "multi_issuer"
      } else {
        "multi_redirect_uri"
      },
      authorization_server_redirect_uris = if (shared) {
        character()
      } else {
        redirects
      },
      response_mode = paste0(
        if (post) "form_post" else "query",
        if (jarm) ".jwt" else ""
      ),
      jarm_signed_response_alg = if (jarm) "HS256" else NULL
    )
  })
  stats::setNames(clients, c("auth_a", "auth_b"))
}

for (shared in c(FALSE, TRUE)) {
  for (jarm in c(FALSE, TRUE)) {
    for (post in c(FALSE, TRUE)) {
      test_that(
        paste("registry completes both provider flows", shared, jarm, post),
        {
          clients <- registry_test_clients(shared, jarm, post)
          browsers <- lapply(clients, function(...) valid_browser_token())
          rendered <- 0L
          base_ui <- function(req) {
            rendered <<- rendered + 1L
            shiny::fluidPage("App")
          }
          ui <- if (post) {
            oauth_form_post_ui(base_ui, clients = clients)
          } else {
            oauth_ui(base_ui, clients = clients)
          }
          responses <- lapply(names(clients), function(id) {
            client <- clients[[id]]
            state <- parse_query_param(
              prepare_call(client, browsers[[id]]),
              "state",
              decode = TRUE
            )
            fields <- if (jarm) {
              list(
                response = jose::jwt_encode_hmac(
                  jose::jwt_claim(
                    iss = client@provider@issuer,
                    aud = client@client_id,
                    exp = as.numeric(Sys.time()) + 60,
                    code = "example-code",
                    state = state
                  ),
                  client@client_secret
                )
              )
            } else {
              list(
                code = "example-code",
                state = state,
                iss = client@provider@issuer
              )
            }
            encoded <- httr2::url_query_build(fields)
            req <- list(
              REQUEST_METHOD = if (post) "POST" else "GET",
              PATH_INFO = httr2::url_parse(client@redirect_uri)$path,
              QUERY_STRING = if (post) "" else encoded,
              rook.url_scheme = "https",
              HTTP_HOST = "app.example"
            )
            if (post) {
              req$CONTENT_TYPE <- "application/x-www-form-urlencoded"
              req$rook.input <- list(read = function(n) charToRaw(encoded))
            }
            response <- ui(req)
            expect_identical(response$status, 303L, info = response$content)
            expect_identical(rendered, 0L)
            expect_identical(
              response$headers[["Referrer-Policy"]],
              "no-referrer"
            )
            expect_false(grepl(
              "code=|state=|response=",
              response$headers$Location
            ))
            response
          })
          names(responses) <- names(clients)
          local_mocked_bindings(
            swap_code_for_token_set = function(...) {
              list(
                access_token = "example-access",
                token_type = "Bearer",
                expires_in = 3600
              )
            },
            .package = "shinyOAuth"
          )
          server <- function(input, output, session) {
            auth <- lapply(names(clients), function(id) {
              oauth_module_server(
                id,
                clients[[id]],
                auto_redirect = FALSE,
                async = FALSE
              )
            })
            names(auth) <- names(clients)
          }
          shiny::testServer(server, {
            for (id in names(clients)) {
              do.call(
                session$setInputs,
                stats::setNames(
                  list(browsers[[id]]),
                  paste0(id, "-shinyOAuth_sid")
                )
              )
              query <- responses[[id]]$headers$Location
              for (module in auth) {
                module$.process_query(
                  query,
                  current_uri = paste0(clients[[id]]@redirect_uri, query)
                )
              }
              session$flushReact()
              expect_true(auth[[id]]$authenticated, info = auth[[id]]$error)
            }
            expect_true(all(vapply(
              auth,
              function(value) value$authenticated,
              logical(1)
            )))
          })
        }
      )
    }
  }
}

test_that("registry early rejections emit one sanitized routing event and error span", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  events <- list()
  withr::local_options(
    shinyOAuth.otel_tracing_enabled = TRUE,
    shinyOAuth.audit_redact_http = TRUE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  clients <- registry_test_clients(shared = TRUE)
  cases <- list(
    route_unavailable = list(uri = NA_character_),
    route_unregistered = list(uri = "https://app.example/unregistered"),
    unexpected_transport = list(post = TRUE),
    issuer_missing = list(),
    issuer_unrecognized = list(
      issuer = "https://unrecognized.example/ISSUER-SENTINEL"
    )
  )
  for (reason in names(cases)) {
    case <- cases[[reason]]
    events <- list()
    fields <- list(code = "CODE-SENTINEL", state = "STATE-SENTINEL")
    if (!is.null(case$issuer)) {
      fields$iss <- case$issuer
    }
    request <- list(
      REQUEST_METHOD = if (isTRUE(case$post)) "POST" else "GET",
      PATH_INFO = "/callback",
      QUERY_STRING = httr2::url_query_build(fields),
      rook.url_scheme = "https",
      HTTP_HOST = "app.example"
    )
    record <- otelsdk::with_otel_record({
      response <- oauth_registry_http_handler(
        request,
        clients,
        function(req) case$uri %||% "https://app.example/callback"
      )
    })
    expect_identical(response$status, 400L)
    routing <- Filter(
      function(event) event$type == "audit_callback_routing_rejected",
      events
    )
    expect_length(routing, 1L)
    expect_length(events, 1L)
    expect_identical(routing[[1L]]$reason, reason)
    expect_identical(routing[[1L]]$phase, "callback_registry_routing")
    expect_identical(routing[[1L]]$shiny_session$http$host, "app.example")
    expect_null(routing[[1L]]$provider)
    expect_null(routing[[1L]]$issuer)
    span <- record$traces[["shinyOAuth.callback.route"]]
    expect_identical(span$status, "error")
    expect_identical(span$attributes[["oauth.reason"]], reason)
    expect_identical(
      span$attributes[["oauth.phase"]],
      "callback_registry_routing"
    )
    expect_null(span$attributes[["oauth.provider.name"]])
    expect_false(any(grepl("SENTINEL", unlist(list(events, span$attributes)))))
  }
})

test_that("registry does not duplicate parser diagnostics or report ordinary page visits", {
  clients <- registry_test_clients(shared = TRUE)
  events <- list()
  withr::local_options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  resolver <- function(req) "https://app.example/callback"
  response <- oauth_registry_http_handler(
    list(REQUEST_METHOD = "GET", QUERY_STRING = "code=a&code=b&state=s"),
    clients,
    resolver
  )
  expect_identical(response$status, 400L)
  expect_true(length(events) > 0L)
  expect_false(any(vapply(
    events,
    function(event) event$type == "audit_callback_routing_rejected",
    logical(1)
  )))
  events <- list()
  expect_null(oauth_registry_http_handler(
    list(REQUEST_METHOD = "GET"),
    clients,
    resolver
  ))
  expect_length(events, 0L)
})

test_that("registry validates configuration and does not render unrecognized GET callbacks", {
  clients <- registry_test_clients(shared = TRUE)
  expect_error(
    oauth_ui(shiny::fluidPage(), clients = unname(clients)),
    "module IDs"
  )
  expect_error(
    oauth_ui(shiny::fluidPage(), "auth", clients[[1L]], clients = clients),
    "not both"
  )
  duplicate <- stats::setNames(list(clients[[1L]], clients[[1L]]), c("a", "b"))
  expect_error(
    oauth_ui(shiny::fluidPage(), clients = duplicate),
    "distinct issuers"
  )
  ui <- oauth_ui(function(req) stop("must not render"), clients = clients)
  response <- ui(list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/unregistered",
    QUERY_STRING = "error=access_denied",
    rook.url_scheme = "https",
    HTTP_HOST = "app.example"
  ))
  expect_identical(response$status, 400L)
})
