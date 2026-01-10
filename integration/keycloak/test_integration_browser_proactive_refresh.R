# Integration test: Proactive refresh with short-lived tokens
#
# This test uses a CONFIDENTIAL client with 5-second access tokens.
# It proves that proactive refresh works by:
#   1. Logging in and capturing the initial token expiry time
#   2. Waiting longer than the token lifespan
#   3. Verifying the session is still authenticated
#   4. Verifying the token's expires_at has INCREASED (proving refresh occurred)
#
# This test file should be run in isolation to avoid SSO cookie conflicts.

testthat::test_that("proactive refresh actually refreshes token before expiry", {
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
  testthat::skip_if_not_installed("digest")

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

  # Use public client with 5-second access tokens
  # Public clients with PKCE also get refresh tokens from Keycloak
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-shortlived",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("Proactive Refresh Test"),
    shiny::actionButton("login_btn", "Login"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::h4("Auth error"),
    shiny::verbatimTextOutput("auth_error"),
    shiny::h4("Token expires_at (Unix timestamp)"),
    shiny::verbatimTextOutput("expires_at_raw"),
    shiny::h4("Seconds until expiry"),
    shiny::verbatimTextOutput("expires_in"),
    shiny::h4("Refresh count"),
    shiny::verbatimTextOutput("refresh_count")
  )

  server <- function(input, output, session) {
    # Simple audit log to file
    log_file <- "C:/Users/dhrko/Documents/GitHub/shinyOAuth/audit.txt"
    options(
      shinyOAuth.audit_hook = function(event) {
        cat(Sys.time(), " [AUDIT] ", event$event, "\n", file = log_file, append = TRUE)
      },
      shinyOAuth.trace_hook = function(event) {
        cat(Sys.time(), " [TRACE] ", event$event, ": ", event$message %||% "", "\n", file = log_file, append = TRUE)
      }
    )
    cat("Server started\n", file = log_file, append = TRUE)

    # Track how many times the token changes (= refresh count)
    refresh_count <- shiny::reactiveVal(0L)
    last_token_hash <- shiny::reactiveVal(NULL)

    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      reauth_after_seconds = NULL, # Don't use reauth, rely on token expiry
      refresh_proactively = TRUE, # THIS IS WHAT WE'RE TESTING
      auto_redirect = FALSE, # Use manual login for more control
      async = FALSE # SYNC mode for debugging
    )

    shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
      auth$request_login()
    })

    # Detect token changes by comparing a hash of the access_token
    shiny::observe({
      tok <- auth$token
      shiny::req(tok)
      current_hash <- digest::digest(tok@access_token, algo = "md5")
      prev_hash <- shiny::isolate(last_token_hash())

      if (!is.null(prev_hash) && current_hash != prev_hash) {
        # Token changed = refresh happened
        shiny::isolate({
          refresh_count(refresh_count() + 1L)
        })
      }
      last_token_hash(current_hash)
    })

    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "has_token:",
        !is.null(auth$token)
      )
    })

    output$auth_error <- shiny::renderText({
      err <- auth$error
      desc <- auth$error_description
      if (is.null(err)) {
        return("no_error")
      }
      paste0("error:", err, "|desc:", desc)
    })

    output$expires_at_raw <- shiny::renderText({
      tok <- auth$token
      if (is.null(tok)) {
        return("no_token")
      }
      # Return raw unix timestamp for parsing
      paste0("expires_at:", as.numeric(tok@expires_at))
    })

    output$expires_in <- shiny::renderText({
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

    output$refresh_count <- shiny::renderText({
      paste0("refresh_count:", refresh_count())
    })
  }

  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "proactive-refresh-proof",
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  # Click login button (using manual login for more control)
  drv$wait_for_js("document.querySelector('#login_btn')", timeout = 5000)
  drv$click("login_btn")

  # Wait for KeyCloak login page
  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 5000)
  message("On Keycloak login page, URL: ", drv$get_js("window.location.href"))

  # Login
  drv$run_js(
    "
    document.querySelector('#username').value = 'alice';
    document.querySelector('#password').value = 'alice';
    document.querySelector('#kc-login').click();
  "
  )

  # Wait for the redirect back to our app
  Sys.sleep(0.5)
  for (i in 1:20) {
    current_url <- drv$get_js("window.location.href")
    message("URL check (", i * 0.25, "s): ", current_url)
    if (grepl("127.0.0.1:8100", current_url)) {
      break
    }
    Sys.sleep(0.25)
  }

  # Check for any errors
  Sys.sleep(1)
  auth_error <- drv$get_js(
    "(function(){ var el=document.querySelector('#auth_error'); return el?el.innerText:''; })()"
  )
  message("Auth error (1s): ", auth_error)

  # Wait for authenticated state with robust polling
  max_wait <- 45
  auth_state <- ""
  for (i in seq_len(max_wait)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    if (i <= 5 || i %% 10 == 0) {
      auth_error <- drv$get_js(
        "(function(){ var el=document.querySelector('#auth_error'); return el?el.innerText:''; })()"
      )
      message("Polling auth_state (", i, "): ", auth_state, " | error: ", auth_error)
    }
    if (grepl("authenticated: TRUE", auth_state, fixed = TRUE)) {
      break
    }
    Sys.sleep(1)
  }

  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("Expected authenticated: TRUE after login. Got: ", auth_state)
  )

  # Capture the INITIAL expires_at timestamp
  initial_expires_at_text <- drv$get_js(
    "(function(){ var el=document.querySelector('#expires_at_raw'); return el?el.innerText:''; })()"
  )
  message("Initial expires_at: ", initial_expires_at_text)

  # Parse the initial timestamp
  initial_expires_at <- as.numeric(
    sub("expires_at:", "", initial_expires_at_text)
  )
  testthat::expect_true(
    !is.na(initial_expires_at) && initial_expires_at > 0,
    info = paste0("Could not parse initial expires_at: ", initial_expires_at_text)
  )

  # The token has a 5-second lifespan. Wait 8 seconds.
  # If proactive refresh works, the token will be refreshed before expiry,
  # and we'll still be authenticated with a NEW expires_at in the future.
  message("Waiting 8 seconds for proactive refresh to occur...")
  Sys.sleep(8)

  # Check we're STILL authenticated
  auth_state <- drv$get_js(
    "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
  )

  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0(
      "Expected authenticated: TRUE after proactive refresh. Got: ",
      auth_state
    )
  )

  # Get the NEW expires_at - it should be GREATER than the initial
  final_expires_at_text <- drv$get_js(
    "(function(){ var el=document.querySelector('#expires_at_raw'); return el?el.innerText:''; })()"
  )
  message("Final expires_at: ", final_expires_at_text)

  final_expires_at <- as.numeric(sub("expires_at:", "", final_expires_at_text))
  testthat::expect_true(
    !is.na(final_expires_at) && final_expires_at > 0,
    info = paste0("Could not parse final expires_at: ", final_expires_at_text)
  )

  # THE KEY ASSERTION: expires_at must have INCREASED
  # This proves the token was refreshed
  testthat::expect_gt(
    final_expires_at,
    initial_expires_at,
    label = paste0(
      "Token expires_at should have increased after refresh. ",
      "Initial: ",
      initial_expires_at,
      ", Final: ",
      final_expires_at
    )
  )

  # Also check refresh count increased
  refresh_count_text <- drv$get_js(
    "(function(){ var el=document.querySelector('#refresh_count'); return el?el.innerText:''; })()"
  )
  message("Refresh count: ", refresh_count_text)

  # Print the audit log
  message("\n=== AUDIT LOG ===")
  if (file.exists(audit_log_file)) {
    cat(readLines(audit_log_file), sep = "\n")
  } else {
    message("No audit log file found")
  }
  message("=== END AUDIT LOG ===\n")

  refresh_count <- as.integer(sub("refresh_count:", "", refresh_count_text))
  testthat::expect_true(
    !is.na(refresh_count) && refresh_count >= 1,
    info = paste0(
      "Expected at least 1 refresh. Got: ",
      refresh_count_text
    )
  )
})
