## Browser E2E: authorization error callbacks and live cookie metadata
##
## Covers the real browser callback boundary for provider error callbacks,
## including issuer checks, browser-token enforcement, replay blocking, URL
## cleanup, and cookie metadata inspection via Chromote.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_error_callback_browser_app <- function(
  client,
  title,
  module_id = "auth",
  browser_cookie_samesite = "Strict",
  browser_cookie_path = NULL
) {
  published_auth_url <- shiny::reactiveVal(NA_character_)
  published_auth_error <- shiny::reactiveVal(NULL)

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel(title),
    shiny::actionButton("prepare_login_btn", "Prepare login"),
    shiny::tags$hr(),
    shiny::verbatimTextOutput("ready_state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::verbatimTextOutput("browser_state"),
    shiny::verbatimTextOutput("auth_url"),
    shiny::verbatimTextOutput("state_store_count")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      module_id,
      client,
      auto_redirect = FALSE,
      browser_cookie_samesite = browser_cookie_samesite,
      browser_cookie_path = browser_cookie_path
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
        auth$error_description %||% "<none>",
        "error_uri:",
        auth$error_uri %||% "<none>"
      )
    })

    output$browser_state <- shiny::renderText({
      jsonlite::toJSON(
        list(
          authenticated = isTRUE(auth$authenticated),
          has_token = !is.null(auth$token),
          error = auth$error %||% NULL,
          error_description = auth$error_description %||% NULL,
          error_uri = auth$error_uri %||% NULL
        ),
        auto_unbox = TRUE,
        null = "null",
        na = "null"
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

    output$state_store_count <- shiny::renderText({
      as.character(length(client@state_store$keys()))
    })
  }

  shiny::shinyApp(ui, server)
}

read_error_callback_browser_state <- function(drv) {
  raw <- drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var browserState = document.querySelector('#browser_state');
      var authUrl = document.querySelector('#auth_url');
      var stateCount = document.querySelector('#state_store_count');
      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        browser_state: browserState ? (browserState.innerText || '{}') : '{}',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        state_store_count: stateCount ? (stateCount.innerText || '0') : '0'
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
  state$state_store_count <- suppressWarnings(as.integer(
    state$state_store_count
  ))
  state
}

wait_for_error_callback_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  read_error_callback_browser_state(drv)
}

wait_for_error_state_transition <- function(
  drv,
  previous_state = "",
  timeout = 20000,
  interval = 0.25
) {
  deadline <- Sys.time() + (timeout / 1000)
  previous_state <- trimws(previous_state %||% "")
  current_state <- previous_state

  while (Sys.time() < deadline) {
    current_state <- trimws(
      read_error_callback_browser_state(drv)$auth_state %||% ""
    )
    if (
      nchar(current_state) > 0 &&
        !identical(current_state, previous_state) &&
        (grepl("authenticated: TRUE", current_state, fixed = TRUE) ||
          !grepl("error: <none>", current_state, fixed = TRUE))
    ) {
      return(current_state)
    }

    Sys.sleep(interval)
  }

  stop(
    paste0(
      "Timed out waiting for auth state transition. Previous: ",
      previous_state,
      " Current: ",
      current_state
    ),
    call. = FALSE
  )
}

keycloak_error_query <- function(
  error = "access_denied",
  state = NA_character_,
  iss = NA_character_,
  error_description = NA_character_,
  error_uri = NA_character_
) {
  parts <- list(
    error = error,
    error_description = error_description,
    error_uri = error_uri,
    state = state,
    iss = iss
  )
  keep <- vapply(
    parts,
    function(value) {
      is.character(value) &&
        length(value) == 1L &&
        !is.na(value)
    },
    logical(1)
  )
  parts <- parts[keep]

  paste0(
    "?",
    paste(
      vapply(
        names(parts),
        function(name) {
          paste0(
            utils::URLencode(name, reserved = TRUE),
            "=",
            utils::URLencode(parts[[name]], reserved = TRUE)
          )
        },
        character(1)
      ),
      collapse = "&"
    )
  )
}

build_error_callback_url <- function(
  client,
  state = NA_character_,
  error = "access_denied",
  error_description = NA_character_,
  error_uri = NA_character_,
  iss = client@provider@issuer
) {
  paste0(
    client@redirect_uri,
    keycloak_error_query(
      error = error,
      state = state,
      iss = iss,
      error_description = error_description,
      error_uri = error_uri
    )
  )
}

make_browser_error_provider <- function() {
  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  provider@par_url <- NA_character_
  provider
}

navigate_browser_to_url <- function(drv, url) {
  url_json <- jsonlite::toJSON(url, auto_unbox = TRUE)
  drv$run_js(paste0("window.location.href = ", url_json, ";"))
}

clear_browser_cookie <- function(drv, cookie_name, path = "/") {
  cookie_name_json <- jsonlite::toJSON(cookie_name, auto_unbox = TRUE)
  path_json <- jsonlite::toJSON(path, auto_unbox = TRUE)

  drv$run_js(paste0(
    "document.cookie = ",
    cookie_name_json,
    " + '=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=' + ",
    path_json,
    ";"
  ))
}

wait_for_callback_cleanup <- function(drv, timeout = 5000) {
  drv$wait_for_js(
    "
    (function () {
      var forbidden = [
        'code=', 'state=', 'iss=', 'error=',
        'error_description=', 'error_uri=',
        'id_token=', 'access_token='
      ];
      var href = window.location.href || '';
      var title = document.title || '';
      return forbidden.every(function (key) {
        return href.indexOf(key) === -1 && title.indexOf(key) === -1;
      });
    })();
  ",
    timeout = timeout
  )

  jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify({
      href: window.location.href || '',
      title: document.title || ''
    });
  "
  ))
}

testthat::test_that("browser callback app sets the default HTTP cookie metadata", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_ERR_COOKIE", "8100"))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::fail(paste0(
      "Port ",
      app_port,
      " is already in use; cannot run browser cookie metadata E2E"
    ))
  }

  provider <- make_browser_error_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_error_callback_browser_app(
      client,
      title = "Error callback cookie metadata",
      module_id = "auth"
    ),
    name = sprintf("keycloak-error-cookie-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  cookie <- find_browser_token_cookie(drv, "auth")

  testthat::expect_false(is.null(cookie))
  testthat::expect_match(cookie$value %||% "", "^[a-f0-9]{128}$")
  testthat::expect_identical(cookie$path, "/")
  testthat::expect_identical(cookie$sameSite, "Strict")
  testthat::expect_false(isTRUE(cookie$secure))
  testthat::expect_false(startsWith(cookie$name %||% "", "__Host-"))
})

testthat::test_that("browser callback app honors configured SameSite and path metadata", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_ERR_COOKIE_LAX",
    "3000"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::fail(paste0(
      "Port ",
      app_port,
      " is already in use; cannot run browser cookie metadata E2E"
    ))
  }

  provider <- make_browser_error_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_error_callback_browser_app(
      client,
      title = "Error callback cookie metadata custom",
      module_id = "authpath",
      browser_cookie_samesite = "Lax",
      browser_cookie_path = "/foo"
    ),
    name = sprintf("keycloak-error-cookie-lax-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  cookie <- find_browser_token_cookie(drv, "authpath")

  testthat::expect_false(is.null(cookie))
  testthat::expect_identical(cookie$path, "/foo")
  testthat::expect_identical(cookie$sameSite, "Lax")
  testthat::expect_false(isTRUE(cookie$secure))
  testthat::expect_false(startsWith(cookie$name %||% "", "__Host-"))
})

testthat::test_that("browser authorization error callbacks preserve state on issuer mismatch, then surface the provider error and clean up", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_ERR_FLOW", "8100"))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::fail(paste0(
      "Port ",
      app_port,
      " is already in use; cannot run browser error-callback E2E"
    ))
  }

  provider <- make_browser_error_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_error_callback_browser_app(
      client,
      title = "Error callback browser flow",
      module_id = "auth"
    ),
    name = sprintf("keycloak-error-flow-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)

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
  initial_state <- wait_for_error_callback_auth_url(drv)
  callback_state <- parse_query_param(
    initial_state$auth_url,
    "state",
    decode = TRUE
  )

  issuer_mismatch_url <- build_error_callback_url(
    client,
    state = callback_state,
    error = "access_denied",
    error_description = "Wrong issuer should not be trusted",
    iss = "http://localhost:8080/realms/attacker"
  )
  valid_error_url <- build_error_callback_url(
    client,
    state = callback_state,
    error = "access_denied",
    error_description = "Consent denied by user",
    error_uri = paste0(get_https_issuer(), "/oauth-error"),
    iss = provider@issuer
  )

  navigate_browser_to_url(drv, issuer_mismatch_url)
  mismatch_auth_state <- wait_for_error_state_transition(
    drv,
    previous_state = initial_state$auth_state,
    timeout = 15000
  )
  mismatch_state <- read_error_callback_browser_state(drv)

  testthat::expect_match(
    mismatch_auth_state,
    "error: issuer_mismatch",
    fixed = TRUE
  )
  testthat::expect_false(isTRUE(mismatch_state$browser_state$authenticated))

  navigate_browser_to_url(drv, valid_error_url)
  valid_auth_state <- wait_for_error_state_transition(
    drv,
    previous_state = mismatch_auth_state,
    timeout = 15000
  )
  valid_state <- read_error_callback_browser_state(drv)
  cleaned <- wait_for_callback_cleanup(drv)

  testthat::expect_match(valid_auth_state, "error: access_denied", fixed = TRUE)
  testthat::expect_false(isTRUE(valid_state$browser_state$authenticated))
  testthat::expect_false(isTRUE(valid_state$browser_state$has_token))
  testthat::expect_identical(valid_state$browser_state$error, "access_denied")
  testthat::expect_identical(
    valid_state$browser_state$error_description,
    "Consent denied by user"
  )
  testthat::expect_identical(
    valid_state$browser_state$error_uri,
    paste0(get_https_issuer(), "/oauth-error")
  )

  for (key in c(
    "code=",
    "state=",
    "iss=",
    "error=",
    "error_description=",
    "error_uri=",
    "id_token=",
    "access_token="
  )) {
    testthat::expect_false(grepl(key, cleaned$href, fixed = TRUE))
    testthat::expect_false(grepl(key, cleaned$title, fixed = TRUE))
  }

  navigate_browser_to_url(drv, valid_error_url)
  replay_auth_state <- wait_for_error_state_transition(
    drv,
    previous_state = valid_auth_state,
    timeout = 15000
  )
  replay_state <- read_error_callback_browser_state(drv)

  testthat::expect_match(
    replay_auth_state,
    "error: invalid_state",
    fixed = TRUE
  )
  testthat::expect_identical(replay_state$browser_state$error, "invalid_state")
})

testthat::test_that("browser authorization error callback rejects unbound state", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_ERR_INVALID_STATE",
    "3000"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::fail(paste0(
      "Port ",
      app_port,
      " is already in use; cannot run browser error-callback E2E"
    ))
  }

  provider <- make_browser_error_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_error_callback_browser_app(
      client,
      title = "Error callback invalid state",
      module_id = "auth"
    ),
    name = sprintf("keycloak-error-invalid-state-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  initial_state <- read_error_callback_browser_state(drv)
  unsolicited_url <- build_error_callback_url(
    client,
    state = "attacker-state",
    error = "access_denied",
    error_description = "Unbound provider error",
    iss = provider@issuer
  )

  navigate_browser_to_url(drv, unsolicited_url)
  auth_state <- wait_for_error_state_transition(
    drv,
    previous_state = initial_state$auth_state,
    timeout = 15000
  )
  browser_state <- read_error_callback_browser_state(drv)

  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_identical(browser_state$browser_state$error, "invalid_state")
  testthat::expect_match(
    browser_state$browser_state$error_description %||% "",
    "state",
    ignore.case = TRUE
  )
})

testthat::test_that("browser authorization error callback fails closed when the browser token cookie is missing", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_ERR_MISSING_COOKIE",
    "8100"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::fail(paste0(
      "Port ",
      app_port,
      " is already in use; cannot run browser error-callback E2E"
    ))
  }

  provider <- make_browser_error_provider()
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  drv <- shinytest2::AppDriver$new(
    make_error_callback_browser_app(
      client,
      title = "Error callback missing browser token",
      module_id = "auth"
    ),
    name = sprintf("keycloak-error-missing-cookie-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)

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
  initial_state <- wait_for_error_callback_auth_url(drv)
  cookie <- find_browser_token_cookie(drv, "auth")

  testthat::expect_false(is.null(cookie))

  state <- parse_query_param(initial_state$auth_url, "state", decode = TRUE)

  clear_browser_cookie(drv, cookie$name, path = cookie$path %||% "/")
  drv$wait_for_idle(250)

  error_url <- build_error_callback_url(
    client,
    state = state,
    error = "access_denied",
    error_description = "Consent denied by user",
    iss = provider@issuer
  )

  navigate_browser_to_url(drv, error_url)
  auth_state <- wait_for_error_state_transition(
    drv,
    previous_state = initial_state$auth_state,
    timeout = 15000
  )
  browser_state <- read_error_callback_browser_state(drv)

  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_identical(browser_state$browser_state$error, "invalid_state")
  testthat::expect_match(
    browser_state$browser_state$error_description %||% "",
    "browser token|state",
    ignore.case = TRUE
  )
})
