# Integration tests for token expiry and authenticated flag behavior
# Uses a headless browser via shinytest2 against a local Keycloak server

# These tests verify that the authenticated flag correctly flips to FALSE
# when tokens expire, without requiring manual reactive value changes.

testthat::test_that("authenticated flips FALSE after reauth_after_seconds in real browser", {
  # Skip if Keycloak isn't reachable
  issuer <- "http://localhost:8080/realms/shinyoauth"
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  testthat::skip_if_not(ok, "Keycloak not reachable at localhost:8080")

  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  is_port_in_use <- function(port) {
    con <- suppressWarnings(try(
      socketConnection(
        host = "127.0.0.1",
        port = as.integer(port),
        server = FALSE,
        blocking = TRUE,
        open = "r+",
        timeout = 1
      ),
      silent = TRUE
    ))
    if (!inherits(con, "try-error")) {
      try(close(con), silent = TRUE)
      return(TRUE)
    }
    FALSE
  }
  if (is_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping shinytest2 E2E"
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

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("Reauth Window E2E Test"),
    shiny::actionButton("login_btn", "Login"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::h4("Session age"),
    shiny::verbatimTextOutput("session_age")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      # Very short reauth window for testing
      reauth_after_seconds = 3,
      refresh_proactively = FALSE,
      # Disable auto-redirect on reauth so we can observe the FALSE state
      auto_redirect = FALSE
    )

    shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
      auth$request_login()
    })

    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "has_token:",
        !is.null(auth$token)
      )
    })

    output$session_age <- shiny::renderText({
      started <- auth$auth_started_at
      if (is.na(started)) {
        return("not started")
      }
      age <- round(as.numeric(Sys.time()) - started, 1)
      paste("session_age_seconds:", age)
    })
  }

  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "reauth-e2e",
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  # Click login button (auto_redirect = FALSE)
  drv$wait_for_js("document.querySelector('#login_btn')", timeout = 5000)
  drv$click("login_btn")

  # Wait for KeyCloak login page
  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 5000)

  # Login
  drv$run_js(
    "
    document.querySelector('#username').value = 'alice';
    document.querySelector('#password').value = 'alice';
    document.querySelector('#kc-login').click();
  "
  )

  # Wait for authenticated state with more robust polling
  max_wait <- 30
  auth_state <- ""
  for (i in seq_len(max_wait)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (grepl("authenticated: TRUE", auth_state, fixed = TRUE)) {
      break
    }
    Sys.sleep(1)
  }

  # Verify we're authenticated
  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("Expected authenticated: TRUE after login. Got: ", auth_state)
  )

  # Wait for reauth window to pass (3 seconds + buffer)
  Sys.sleep(4)

  # Poll for authenticated to become FALSE
  max_attempts <- 20
  for (i in seq_len(max_attempts)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (grepl("authenticated: FALSE", auth_state, fixed = TRUE)) {
      break
    }
    Sys.sleep(0.5)
  }

  # Verify authenticated is now FALSE due to reauth_after_seconds
  testthat::expect_true(
    grepl("authenticated: FALSE", auth_state, fixed = TRUE),
    info = paste0(
      "Expected authenticated: FALSE after reauth_after_seconds window. ",
      "The invalidateLater timer should have flipped it. Got: ",
      auth_state
    )
  )
})


testthat::test_that("authenticated flips FALSE after actual token expiry (short-lived tokens)", {
  # This test uses the shiny-shortlived client which issues 5-second access tokens

  # Skip if Keycloak isn't reachable
  issuer <- "http://localhost:8080/realms/shinyoauth"
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  testthat::skip_if_not(ok, "Keycloak not reachable at localhost:8080")

  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  is_port_in_use <- function(port) {
    con <- suppressWarnings(try(
      socketConnection(
        host = "127.0.0.1",
        port = as.integer(port),
        server = FALSE,
        blocking = TRUE,
        open = "r+",
        timeout = 1
      ),
      silent = TRUE
    ))
    if (!inherits(con, "try-error")) {
      try(close(con), silent = TRUE)
      return(TRUE)
    }
    FALSE
  }
  if (is_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping shinytest2 E2E"
    ))
  }

  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )

  # Use the short-lived token client (5-second access tokens)
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-shortlived",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("Token Expiry E2E Test"),
    shiny::actionButton("login_btn", "Login"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::h4("Token info"),
    shiny::verbatimTextOutput("token_info")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      # No reauth window - rely purely on token expiry
      reauth_after_seconds = NULL,
      refresh_proactively = FALSE,
      # Disable auto-redirect on expiry so we can observe the FALSE state
      auto_redirect = FALSE
    )

    shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
      auth$request_login()
    })

    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "has_token:",
        !is.null(auth$token)
      )
    })

    output$token_info <- shiny::renderText({
      tok <- auth$token
      if (is.null(tok)) {
        return("no token")
      }
      exp <- tok@expires_at
      if (is.na(exp) || is.infinite(exp)) {
        return(paste("expires_at:", exp))
      }
      remaining <- round(exp - as.numeric(Sys.time()), 1)
      paste("expires_in_seconds:", remaining)
    })
  }

  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "token-expiry-e2e",
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  # Click login button (auto_redirect = FALSE)
  drv$wait_for_js("document.querySelector('#login_btn')", timeout = 5000)
  drv$click("login_btn")

  # Wait for KeyCloak login page
  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 5000)

  # Login
  drv$run_js(
    "
    document.querySelector('#username').value = 'alice';
    document.querySelector('#password').value = 'alice';
    document.querySelector('#kc-login').click();
  "
  )

  # Wait for authenticated state with robust polling
  max_wait <- 30
  auth_state <- ""
  for (i in seq_len(max_wait)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (grepl("authenticated: TRUE", auth_state, fixed = TRUE)) {
      break
    }
    Sys.sleep(1)
  }

  # Verify we're authenticated
  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("Expected authenticated: TRUE after login. Got: ", auth_state)
  )

  # Get initial token info to confirm we have a short-lived token
  token_info <- drv$get_js(
    "(function(){ var el=document.querySelector('#token_info'); return el?el.innerText:''; })()"
  )
  message("Initial token info: ", token_info)

  # Wait for token to expire (5 seconds + buffer)
  Sys.sleep(7)

  # Poll for authenticated to become FALSE
  max_attempts <- 20
  for (i in seq_len(max_attempts)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (grepl("authenticated: FALSE", auth_state, fixed = TRUE)) {
      break
    }
    Sys.sleep(0.5)
  }

  # Verify authenticated is now FALSE due to token expiry
  testthat::expect_true(
    grepl("authenticated: FALSE", auth_state, fixed = TRUE),
    info = paste0(
      "Expected authenticated: FALSE after token expiry. ",
      "The invalidateLater timer should have flipped it. Got: ",
      auth_state
    )
  )
})
