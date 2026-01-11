# Integration test: Proactive refresh with short-lived tokens
#
# This test uses a CONFIDENTIAL client with 5-second access tokens.
# It proves that proactive refresh works by:
#   1. Logging in and capturing the initial token expiry time
#   2. Waiting longer than the token lifespan
#   3. Verifying the session is still authenticated
#   4. Verifying the token's expires_at has INCREASED (proving refresh occurred)

testthat::test_that("proactive refresh keeps session alive with short-lived tokens", {
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

  # Use confidential client with short-lived tokens (5-second access tokens)
  # Confidential clients can use refresh tokens reliably
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-shortlived-confidential",
    client_secret = "secret",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("Proactive Refresh E2E Test"),
    shiny::actionButton("login_btn", "Login"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::h4("Token info"),
    shiny::verbatimTextOutput("token_info"),
    shiny::h4("Refresh count"),
    shiny::verbatimTextOutput("refresh_count")
  )

  server <- function(input, output, session) {
    # Track refresh events via counter
    refresh_count <- shiny::reactiveVal(0L)

    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      # Enable proactive refresh with aggressive settings for testing
      refresh_proactively = TRUE,
      # Refresh 2 seconds before expiry (with 5-second tokens, this means
      # refresh happens ~3 seconds after obtaining the token)
      refresh_lead_seconds = 2,
      # Check frequently for refresh opportunities
      refresh_check_interval = 500,
      # Disable auto-redirect so we can observe states
      auto_redirect = FALSE
    )

    # Observe token changes to track refresh count
    shiny::observeEvent(auth$token, {
      if (!is.null(auth$token)) {
        # Increment count each time we get a new token (after initial login)
        current <- shiny::isolate(refresh_count())
        refresh_count(current + 1L)
      }
    })

    shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
      auth$request_login()
    })

    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
        "has_token:",
        !is.null(auth$token),
        "error:",
        if (!is.null(auth$error)) auth$error else "<none>"
      )
    })

    output$token_info <- shiny::renderText({
      tok <- auth$token
      if (is.null(tok)) {
        return("no_token")
      }
      exp <- tok@expires_at
      if (is.na(exp) || is.infinite(exp)) {
        return(paste("expires_at:", exp))
      }
      now <- as.numeric(Sys.time())
      remaining <- round(exp - now, 1)
      paste0(
        "expires_at:",
        round(exp, 2),
        " remaining_seconds:",
        remaining
      )
    })

    output$refresh_count <- shiny::renderText({
      paste("token_count:", refresh_count())
    })
  }

  app <- shiny::shinyApp(ui, server)

  drv <- shinytest2::AppDriver$new(
    app,
    name = "proactive-refresh-e2e",
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

  # Capture initial token info (expires_at)
  initial_token_info <- drv$get_js(
    "(function(){ var el=document.querySelector('#token_info'); return el?el.innerText:''; })()"
  )
  message("Initial token info: ", initial_token_info)

  # Extract initial expires_at value using regmatches for reliability
  initial_expires_match <- regmatches(
    initial_token_info,
    regexpr("expires_at:([0-9.]+)", initial_token_info, perl = TRUE)
  )
  initial_expires_at <- if (length(initial_expires_match) > 0) {
    as.numeric(sub("expires_at:", "", initial_expires_match, fixed = TRUE))
  } else {
    NA_real_
  }

  testthat::expect_true(
    !is.na(initial_expires_at) && initial_expires_at > 0,
    info = paste0(
      "Could not parse initial expires_at. Token info: ",
      initial_token_info
    )
  )

  # Wait longer than token lifespan (5s) plus buffer for refresh to complete
  # Given: 5s token, 2s lead = refresh at ~3s, and we need time for it to complete
  message("Waiting for proactive refresh to occur...")
  Sys.sleep(8)

  # Poll to get updated token info after refresh should have occurred
  final_token_info <- ""
  final_auth_state <- ""
  for (i in seq_len(20)) {
    final_auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )
    final_token_info <- drv$get_js(
      "(function(){ var el=document.querySelector('#token_info'); return el?el.innerText:''; })()"
    )

    # Check if we're still authenticated and have token info
    if (
      grepl("authenticated: TRUE", final_auth_state, fixed = TRUE) &&
        grepl("expires_at:", final_token_info, fixed = TRUE) &&
        !grepl("no_token", final_token_info, fixed = TRUE)
    ) {
      break
    }
    Sys.sleep(0.5)
  }

  message("Final auth state: ", final_auth_state)
  message("Final token info: ", final_token_info)

  # CRITICAL ASSERTION 1: Session should still be authenticated
  testthat::expect_true(
    grepl("authenticated: TRUE", final_auth_state, fixed = TRUE),
    info = paste0(
      "Expected session to remain authenticated after proactive refresh. ",
      "If authenticated is FALSE, proactive refresh may have failed. ",
      "Auth state: ",
      final_auth_state
    )
  )

  # CRITICAL ASSERTION 2: Token should have new expires_at (proving refresh occurred)
  final_expires_match <- regmatches(
    final_token_info,
    regexpr("expires_at:([0-9.]+)", final_token_info, perl = TRUE)
  )
  final_expires_at <- if (length(final_expires_match) > 0) {
    as.numeric(sub("expires_at:", "", final_expires_match, fixed = TRUE))
  } else {
    NA_real_
  }

  testthat::expect_true(
    !is.na(final_expires_at),
    info = paste0(
      "Could not parse final expires_at. Token info: ",
      final_token_info
    )
  )

  # The new expires_at should be greater than the initial one
  # (This proves refresh actually happened and we got a new token)
  testthat::expect_true(
    final_expires_at > initial_expires_at,
    info = paste0(
      "Expected expires_at to INCREASE after proactive refresh. ",
      "Initial: ",
      initial_expires_at,
      ", Final: ",
      final_expires_at,
      ". ",
      "If they're the same or final < initial, refresh may not have occurred."
    )
  )

  # Check refresh count (should be >= 2: initial login + at least one refresh)
  refresh_count_text <- drv$get_js(
    "(function(){ var el=document.querySelector('#refresh_count'); return el?el.innerText:''; })()"
  )
  message("Refresh count: ", refresh_count_text)

  token_count_match <- regmatches(
    refresh_count_text,
    regexpr("token_count:\\s*(\\d+)", refresh_count_text, perl = TRUE)
  )
  token_count <- if (length(token_count_match) > 0) {
    as.integer(sub("token_count:\\s*", "", token_count_match))
  } else {
    NA_integer_
  }

  testthat::expect_true(
    !is.na(token_count) && token_count >= 2,
    info = paste0(
      "Expected at least 2 token acquisitions (initial + refresh). ",
      "Got: ",
      token_count,
      ". Refresh count text: ",
      refresh_count_text
    )
  )

  # Success message
  message(
    "Proactive refresh verified: expires_at increased from ",
    initial_expires_at,
    " to ",
    final_expires_at,
    " (diff: ",
    round(final_expires_at - initial_expires_at, 2),
    "s)"
  )
})
