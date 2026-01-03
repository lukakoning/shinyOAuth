# This tests integration of the shinyOAuth module in a Shiny app,
# using a headless browser via shinytest2, against a local Keycloak server

# Note: can't use Shiny's exported test values, are shinytest2 loses
# connection to test values during redirect flows (app -> Keycloak -> app)
# Therefore, we read authentication state from the page DOM directly
# This is suboptimal, but works for E2E testing purposes here

testthat::test_that("Shiny module E2E in headless browser against Keycloak", {
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

  # Need a browser automation stack
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  # Build the minimal app inline, mirroring playground/example-keycloak-docker.R
  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  # Skip if chosen port is already in use to avoid flaky CI failures
  is_port_in_use <- function(port) {
    # socketConnection can emit warnings when the port is not open; suppress them to avoid noisy tests
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
    # Use the same host as the Shiny app to keep cookies and state consistent
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("shinyOAuth + Keycloak (E2E)"),
    shiny::actionButton("login_btn", "Login"),
    shiny::actionButton("logout_btn", "Logout"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::tags$hr(),
    shiny::h4("User info"),
    shiny::verbatimTextOutput("user_info")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server("auth", client)

    shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
      auth$request_login()
    })
    shiny::observeEvent(input$logout_btn, ignoreInit = TRUE, {
      auth$logout()
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

    output$user_info <- shiny::renderText({
      if (is.null(auth$token)) {
        return("{}")
      }
      jsonlite::toJSON(auth$token@userinfo, auto_unbox = TRUE, null = "null")
    })
  }

  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "keycloak-e2e",
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  # Wait for KeyCloak login button to show (after auto-redirect by Shiny app)
  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 5000)

  # Fill credentials & submit in one atomic JavaScript block
  drv$run_js(
    "
    document.querySelector('#username').value = 'alice';
    document.querySelector('#password').value = 'alice';
    document.querySelector('#kc-login').click();
  "
  )

  # Wait for a definitive authentication state: success or with error
  drv$wait_for_js(
    "
  (function () {
    var el = document.querySelector('#auth_state');
    if (!el) return false;
    var t = el.innerText;
    return t.includes('authenticated: TRUE') ||
           !t.includes('error_description: <none>');
  })();
  ",
    timeout = 20000
  )

  # Helper to get auth_state robustly, ensuring non-empty result
  get_auth_state_robust <- function(
    drv,
    selector,
    max_attempts = 10,
    delay = 0.5
  ) {
    for (i in seq_len(max_attempts)) {
      # Get auth_state from page
      auth_state <- drv$get_js(
        "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
      )

      # Return immediately if content is found
      # We return only when 'authenticated' is TRUE, or 'error' is not '<none>'
      if (
        nchar(auth_state) > 0 &&
          (grepl("authenticated: TRUE", auth_state, fixed = TRUE) ||
            !grepl("error_description: <none>", auth_state, fixed = TRUE))
      ) {
        return(trimws(auth_state))
      }

      # If empty/invalid, wait briefly before retrying
      Sys.sleep(delay)
    }

    # Return empty string if the content never appears
    return("")
  }
  auth_state <- get_auth_state_robust(drv, "#auth_state")

  # Explicitly verify that auth_state is NOT an empty string.
  testthat::expect_true(
    nchar(auth_state) > 0,
    info = "The '#auth_state' content never stabilized (remained empty after multiple attempts)"
  )

  # Extract specifically the `authenticated: ...` part (as boolean)
  authenticated_flag <- sub(
    ".*authenticated:\\s*(TRUE|FALSE).*",
    "\\1",
    auth_state,
    perl = TRUE
  ) ==
    "TRUE"
  testthat::expect_true(
    authenticated_flag,
    info = paste0(
      "Login failed; 'authenticated' flag was not TRUE. Full auth_state:\n",
      auth_state
    )
  )

  # Extract specifically the `error_description: ...` part
  error_description <- sub(
    "(?s).*error_description: (.*?)(?:\\n|ℹ|Caused|$).*",
    "\\1",
    auth_state,
    perl = TRUE
  )
  error_description <- trimws(error_description) # Trim again after extraction
  # Error should be equal to '<none>'
  testthat::expect_identical(
    error_description,
    "<none>",
    info = paste0(
      "Login failed; error_description was not '<none>'. Full auth_state:\n",
      auth_state
    )
  )

  # Verify user info content
  user_info <- drv$get_js(
    "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
  ) |>
    jsonlite::fromJSON()

  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})

testthat::test_that("Shiny module E2E with introspect=TRUE succeeds", {
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
    testthat::skip(paste0("Port ", app_port, " already in use"))
  }

  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("E2E introspect"),
    shiny::verbatimTextOutput("auth_state")
  )
  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server("auth", client, introspect = TRUE)
    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "error:",
        if (!is.null(auth$error)) auth$error else "<none>",
        "error_desc:",
        if (!is.null(auth$error_description)) {
          auth$error_description
        } else {
          "<none>"
        }
      )
    })
  }
  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "keycloak-e2e-introspect",
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 10000)
  drv$run_js(
    "document.querySelector('#username').value = 'alice'; document.querySelector('#password').value = 'alice'; document.querySelector('#kc-login').click();"
  )
  drv$wait_for_js(
    "(function () { var el = document.querySelector('#auth_state'); if (!el) return false; var t = el.innerText; return t.includes('authenticated: TRUE') || t.includes('error_desc:') && !t.includes('error_desc: <none>'); })();",
    timeout = 20000
  )

  # Poll a few times to get a stable auth_state
  auth_state <- ""
  for (i in 1:15) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (
      nchar(auth_state) > 0 &&
        (grepl("authenticated: TRUE", auth_state, fixed = TRUE) ||
          (grepl("error_desc:", auth_state, fixed = TRUE) &&
            !grepl("error_desc: <none>", auth_state, fixed = TRUE)))
    ) {
      break
    }
    Sys.sleep(0.5)
  }
  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("auth_state was: ", auth_state)
  )
})
