## Attack vector: Browser-token callback CSRF in a real browser flow
##
## Verifies that a live callback fails when the browser-token cookie is
## tampered after the authorization request is prepared but before the browser
## returns from Keycloak.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

random_browser_token_hex <- function(bytes = 64L) {
  paste0(
    sample(c(0:9, letters[1:6]), as.integer(bytes) * 2L, replace = TRUE),
    collapse = ""
  )
}

read_browser_csrf_payload <- function(drv) {
  jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var authUrl = document.querySelector('#auth_url');
      var cookie = document.cookie || '';
      var parts = cookie ? cookie.split('; ') : [];
      var cookiePrefixes = ['shinyOAuth_sid-auth-', '__Host-shinyOAuth_sid-auth-'];
      var cookieName = '';
      var cookieValue = '';

      for (var i = 0; i < parts.length; i++) {
        for (var j = 0; j < cookiePrefixes.length; j++) {
          if (parts[i].lastIndexOf(cookiePrefixes[j], 0) === 0) {
            var eq = parts[i].indexOf('=');
            if (eq !== -1) {
              cookieName = parts[i].substring(0, eq);
              cookieValue = parts[i].substring(eq + 1);
              break;
            }
          }
        }
        if (cookieName) { break; }
      }

      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        cookie_name: cookieName,
        cookie_value: cookieValue
      };
    })())
  "
  ))
}

tamper_browser_token_cookie <- function(drv, cookie_name, cookie_value) {
  cookie_name_json <- jsonlite::toJSON(cookie_name, auto_unbox = TRUE)
  cookie_value_json <- jsonlite::toJSON(cookie_value, auto_unbox = TRUE)

  jsonlite::fromJSON(drv$get_js(
    paste0(
      "JSON.stringify((function () {",
      "  var cookieName = ",
      cookie_name_json,
      ";",
      "  var cookieValue = ",
      cookie_value_json,
      ";",
      "  document.cookie = cookieName + '=' + cookieValue + '; Path=/; SameSite=Strict';",
      "  var parts = document.cookie ? document.cookie.split('; ') : [];",
      "  var currentValue = '';",
      "  for (var i = 0; i < parts.length; i++) {",
      "    if (parts[i].lastIndexOf(cookieName + '=', 0) === 0) {",
      "      currentValue = parts[i].substring(cookieName.length + 1);",
      "      break;",
      "    }",
      "  }",
      "  return { current_value: currentValue, cookie: document.cookie || '' };",
      "})())"
    )
  ))
}

testthat::test_that("browser callback with tampered cookie is rejected", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_CSRF", "8100"))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping browser-token CSRF E2E"
    ))
  }

  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  published_auth_url <- shiny::reactiveVal(NA_character_)

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel("Browser-token CSRF E2E"),
    shiny::actionButton("prepare_login_btn", "Prepare login"),
    shiny::tags$hr(),
    shiny::verbatimTextOutput("ready_state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::verbatimTextOutput("auth_url")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE
    )

    shiny::observeEvent(input$prepare_login_btn, ignoreInit = TRUE, {
      published_auth_url(auth$build_auth_url())
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
        if (!is.null(auth$error)) auth$error else "<none>",
        "error_description:",
        if (!is.null(auth$error_description)) {
          auth$error_description
        } else {
          "<none>"
        }
      )
    })

    output$auth_url <- shiny::renderText({
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
  }

  drv <- shinytest2::AppDriver$new(
    shiny::shinyApp(ui, server),
    name = "keycloak-browser-token-csrf",
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

  drv$click("prepare_login_btn")
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = 15000
  )

  payload <- read_browser_csrf_payload(drv)
  testthat::expect_true(
    grepl("browser_ready: TRUE", payload$ready_state, fixed = TRUE),
    info = paste0(
      "Expected browser_ready before preparing login. Got: ",
      payload$ready_state
    )
  )
  testthat::expect_true(nzchar(payload$cookie_name))
  testthat::expect_true(nzchar(payload$cookie_value))
  testthat::expect_true(nzchar(payload$auth_url))
  testthat::expect_false(identical(payload$auth_url, "<none>"))

  attacker_cookie <- random_browser_token_hex()
  testthat::expect_false(identical(attacker_cookie, payload$cookie_value))

  tampered <- tamper_browser_token_cookie(
    drv,
    cookie_name = payload$cookie_name,
    cookie_value = attacker_cookie
  )
  testthat::expect_identical(tampered$current_value, attacker_cookie)

  drv$run_js(
    paste0(
      "window.location = ",
      jsonlite::toJSON(payload$auth_url, auto_unbox = TRUE),
      ";"
    )
  )

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 20000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
  }

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
  testthat::expect_true(
    nchar(auth_state) > 0,
    info = "The '#auth_state' content never stabilized"
  )
  testthat::expect_match(
    auth_state,
    "authenticated: FALSE",
    fixed = TRUE,
    info = paste0("Expected callback failure. auth_state:\n", auth_state)
  )
  testthat::expect_match(
    auth_state,
    "has_token: FALSE",
    fixed = TRUE,
    info = paste0("Unexpected token leak. auth_state:\n", auth_state)
  )
  testthat::expect_match(
    auth_state,
    "error: invalid_state",
    fixed = TRUE,
    info = paste0("Expected invalid_state. auth_state:\n", auth_state)
  )
  testthat::expect_match(
    auth_state,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE,
    info = paste0(
      "Expected browser-token validation failure. auth_state:\n",
      auth_state
    )
  )
})
