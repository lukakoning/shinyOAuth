## Attack vector: login CSRF / subject substitution in a real browser flow
##
## Verifies the browser-visible semantics of the classic OAuth account-
## substitution case: the package completes the flow for whoever actually logs
## in at the provider, and the app can make its own policy decision using the
## verified subject and userinfo claims exposed by the token.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_login_csrf_browser_app <- function(client, title, module_id = "auth") {
  published_auth_url <- shiny::reactiveVal(NA_character_)
  published_auth_error <- shiny::reactiveVal(NULL)

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel(title),
    shiny::actionButton("prepare_login_btn", "Prepare login"),
    shiny::tags$hr(),
    shiny::verbatimTextOutput("ready_state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::verbatimTextOutput("auth_url"),
    shiny::verbatimTextOutput("browser_state")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      module_id,
      client,
      auto_redirect = FALSE
    )

    shiny::observeEvent(input$prepare_login_btn, ignoreInit = TRUE, {
      tryCatch(
        {
          published_auth_url(auth$build_auth_url())
          published_auth_error(NULL)
        },
        error = function(e) {
          published_auth_error(conditionMessage(e))
        }
      )
    })

    output$ready_state <- shiny::renderText({
      paste("browser_ready:", isTRUE(auth$has_browser_token()))
    })

    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "has_token:",
        !is.null(auth$token),
        "error:",
        auth$error %||% "<none>",
        "error_description:",
        auth$error_description %||% "<none>"
      )
    })

    output$auth_url <- shiny::renderText({
      auth_error <- published_auth_error() %||% NULL
      if (
        is.character(auth_error) &&
          length(auth_error) == 1L &&
          nzchar(auth_error)
      ) {
        return(paste("<error>", auth_error))
      }

      auth_url <- published_auth_url() %||% NA_character_
      if (
        !is.character(auth_url) ||
          length(auth_url) != 1L ||
          is.na(auth_url) ||
          !nzchar(auth_url)
      ) {
        return("<none>")
      }

      auth_url
    })

    output$browser_state <- shiny::renderText({
      token <- auth$token
      userinfo <- if (is.null(token)) {
        list()
      } else {
        token@userinfo %||% list()
      }
      id_claims <- if (is.null(token)) {
        list()
      } else {
        token@id_token_claims %||% list()
      }
      username <- userinfo[["preferred_username"]] %||% NA_character_

      jsonlite::toJSON(
        list(
          authenticated = isTRUE(auth$authenticated),
          has_token = !is.null(token),
          error = auth$error %||% NULL,
          error_description = auth$error_description %||% NULL,
          preferred_username = username,
          userinfo_sub = userinfo[["sub"]] %||% NULL,
          id_sub = id_claims$sub %||% NULL,
          app_policy_rejected = !is.null(token) && !identical(username, "alice")
        ),
        auto_unbox = TRUE,
        null = "null",
        na = "null"
      )
    })
  }

  shiny::shinyApp(ui, server)
}

read_login_csrf_browser_state <- function(drv) {
  raw <- drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var authUrl = document.querySelector('#auth_url');
      var browserState = document.querySelector('#browser_state');
      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        browser_state: browserState ? (browserState.innerText || '{}') : '{}'
      };
    })())
  "
  )

  state <- jsonlite::fromJSON(raw)
  browser_state <- state$browser_state %||% "{}"
  if (!is.character(browser_state) || length(browser_state) != 1L) {
    browser_state <- "{}"
  }
  state$browser_state <- jsonlite::fromJSON(browser_state)
  state
}

wait_for_login_csrf_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  read_login_csrf_browser_state(drv)
}

navigate_browser_to_url <- function(drv, url) {
  url_json <- jsonlite::toJSON(url, auto_unbox = TRUE)
  drv$run_js(paste0("window.location.href = ", url_json, ";"))
}

testthat::test_that("browser login CSRF exposes the substituted subject for app-side rejection", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_LOGIN_CSRF", "8100"))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping login-CSRF browser E2E"
    ))
  }

  provider <- make_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_login_csrf_browser_app(
      client,
      title = "Login CSRF browser E2E",
      module_id = "auth"
    ),
    name = sprintf("keycloak-login-csrf-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  drv$set_inputs(prepare_login_btn = "click")
  browser_state <- wait_for_login_csrf_auth_url(drv)

  testthat::expect_match(
    browser_state$ready_state,
    "browser_ready: TRUE",
    fixed = TRUE
  )
  testthat::expect_true(
    is.character(browser_state$auth_url) && nzchar(browser_state$auth_url)
  )

  login <- perform_login_form_as(
    browser_state$auth_url,
    username = "bob",
    password = "bob",
    redirect_uri = client@redirect_uri
  )
  testthat::expect_true(
    is.character(login$callback_url) && nzchar(login$callback_url)
  )

  navigate_browser_to_url(drv, login$callback_url)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_state');
      if (!el) return false;
      var text = el.innerText || '';
      return text.indexOf('authenticated: TRUE') !== -1 ||
        text.indexOf('error_description: <none>') === -1;
    })();
  ",
    timeout = 20000
  )

  auth_state <- keycloak_get_auth_state_robust(drv)
  browser_state <- read_login_csrf_browser_state(drv)
  claims <- browser_state$browser_state

  testthat::expect_match(auth_state, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_true(isTRUE(claims$authenticated))
  testthat::expect_true(isTRUE(claims$has_token))
  testthat::expect_identical(claims$preferred_username, "bob")
  testthat::expect_true(
    is.character(claims$userinfo_sub) && nzchar(claims$userinfo_sub)
  )
  testthat::expect_identical(claims$id_sub, claims$userinfo_sub)
  testthat::expect_true(
    isTRUE(claims$app_policy_rejected),
    info = paste0(
      "Expected app policy to reject non-alice subject. Browser state: ",
      jsonlite::toJSON(claims, auto_unbox = TRUE, null = "null")
    )
  )
})
