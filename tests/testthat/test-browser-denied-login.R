# shinyOAuth-browser-suite

test_that("completed denied logins do not exhaust browser cookie headers", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  skip_if(Sys.which("node") == "")
  withr::local_options(list(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.allowed_hosts = c("127.0.0.1", "issuer.example")
  ))
  server <- processx::process[["new"]](
    Sys.which("node"),
    c(
      test_path("..", "browser-two-port-server.cjs"),
      system.file("www", "shinyOAuth.js", package = "shinyOAuth"),
      mtls_pem_fixture("server-cert.pem"),
      mtls_pem_fixture("client-key.pem")
    ),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server[["kill"]]())
  server[["poll_io"]](5000)
  ports <- jsonlite::fromJSON(server[["read_output_lines"]]()[[1L]])
  browser <- chromote::ChromoteSession[["new"]]()
  withr::defer(browser[["close"]]())
  browser[["Security"]][["setIgnoreCertificateErrors"]](ignore = TRUE)
  origin <- paste0("https://127.0.0.1:", ports[[1L]])
  browser[["go_to"]](paste0(origin, "/app"))
  evaluate <- function(script) {
    browser[["Runtime"]][["evaluate"]](
      script,
      returnByValue = TRUE,
      awaitPromise = TRUE
    )[["result"]][["value"]]
  }
  # The suite shares Chrome's cookie jar. Earlier fixtures may intentionally
  # retain markers for pending transactions, which this module must preserve.
  initial_cookie_bytes <- evaluate("document.cookie.length")
  provider <- oauth_provider(
    name = "Denied login fixture",
    issuer = "https://issuer.example",
    infer_oidc_from_issuer = FALSE,
    auth_url = "https://issuer.example/authorize",
    token_url = "https://issuer.example/token",
    token_auth_style = "public"
  )
  client <- oauth_client(
    provider,
    "denied-login-client",
    redirect_uri = paste0(origin, "/app"),
    state_store = cachem::cache_mem(max_age = 300)
  )
  ui <- oauth_ui(shiny::fluidPage("Fixture"), "auth", client)
  messages <- list()
  redirects <- character()
  clears <- 0L
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      root <- session[["rootScope"]]()
      root[["sendCustomMessage"]] <- function(type, message) {
        messages[[length(messages) + 1L]] <<- list(
          type = type,
          message = message
        )
      }
      deliver <- function() {
        current <- messages
        messages <<- list()
        for (message in current) {
          type <- message[["type"]]
          payload <- message[["message"]]
          if (identical(type, "shinyOAuth:redirect")) {
            redirects <<- c(redirects, payload[["url"]])
            next
          }
          if (identical(type, "shinyOAuth:clearBrowserToken")) {
            clears <<- clears + 1L
          }
          inputs <- jsonlite::fromJSON(
            evaluate(paste0(
              "Shiny.handlers[",
              jsonlite::toJSON(type, auto_unbox = TRUE),
              "](",
              jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null"),
              "); JSON.stringify(window.inputs)"
            )),
            simplifyVector = FALSE
          )
          if (identical(type, "shinyOAuth:setBrowserToken")) {
            session[["setInputs"]](
              shinyOAuth_sid = inputs[[payload[["inputId"]]]]
            )
            if (!is.null(payload[["requestId"]])) {
              session[["setInputs"]](
                shinyOAuth_cookie_ack = inputs[[payload[["ackInputId"]]]]
              )
            }
          }
        }
      }
      settle <- function() {
        for (step in seq_len(8L)) {
          later::run_now()
          session[["flushReact"]]()
          deliver()
        }
      }
      session[["flushReact"]]()
      settle()
      # Without retiring verified errors, 100 markers exceed Node's 16 KiB
      # header limit. Use the public login, HTTP bridge and callback paths.
      for (attempt in seq_len(100L)) {
        expect_true(values[["request_login"]]())
        settle()
        expect_length(redirects, attempt)
        state <- parse_query_param(redirects[[attempt]], "state")
        logical_state <- state_payload_decrypt_validate(client, state)[[
          "state"
        ]]
        callback <- ui(list(
          REQUEST_METHOD = "GET",
          PATH_INFO = "/app",
          QUERY_STRING = httr2::url_query_build(list(
            error = "access_denied",
            state = state,
            iss = provider@issuer
          )),
          HTTP_HOST = paste0("127.0.0.1:", ports[[1L]]),
          "rook.url_scheme" = "https"
        ))
        expect_identical(callback[["status"]], 303L)
        continuation <- callback[["headers"]][["Location"]]
        values[[".process_query"]](
          continuation,
          current_uri = paste0(origin, "/app", continuation)
        )
        settle()
        expect_identical(values[["error"]], "access_denied")
        expect_null(client@state_store[["get"]](
          state_cache_key(logical_state),
          missing = NULL
        ))
        expect_lte(
          evaluate("document.cookie.length"),
          initial_cookie_bytes + 512L
        )
      }
      expect_identical(clears, 100L)
      expect_identical(evaluate("fetch('/cookie').then(r => r.status)"), 200L)
    }
  )
})
