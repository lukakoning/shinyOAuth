# Integration tests for oauth_module_server() login-time introspection
# against a real Keycloak provider (Docker realm in this folder).

# This mirrors test_integration_module_shiny_browser.R but enables
# oauth_module_server(introspect = TRUE).

.test_keycloak_reachable <- function() {
  issuer <- "http://localhost:8080/realms/shinyoauth"
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
}

.is_port_in_use <- function(port) {
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

.get_auth_state_robust <- function(drv, max_attempts = 10, delay = 0.5) {
  for (i in seq_len(max_attempts)) {
    auth_state <- drv$get_js(
      "(function(){ var el=document.querySelector('#auth_state'); return el?el.innerText:''; })()"
    )

    if (
      nchar(auth_state) > 0 &&
        (grepl("authenticated: TRUE", auth_state, fixed = TRUE) ||
          !grepl("error_description: <none>", auth_state, fixed = TRUE))
    ) {
      return(trimws(auth_state))
    }

    Sys.sleep(delay)
  }

  ""
}

.extract_error_description <- function(auth_state) {
  out <- sub(
    "(?s).*error_description: (.*?)(?:\\n|ℹ|Caused|$).*",
    "\\1",
    auth_state,
    perl = TRUE
  )
  trimws(out)
}

.test_shiny_module_e2e <- function(
  app_port,
  provider,
  client_id,
  client_secret,
  introspect,
  introspect_elements
) {
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = sprintf("http://127.0.0.1:%d", as.integer(app_port)),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::h3("shinyOAuth + Keycloak (E2E introspection)"),
    shiny::tags$hr(),
    shiny::h4("Auth state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::tags$hr(),
    shiny::h4("User info"),
    shiny::verbatimTextOutput("user_info")
  )

  server <- function(input, output, session) {
    # auto_redirect = TRUE (default) — the module redirects immediately
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      introspect = introspect,
      introspect_elements = introspect_elements
    )

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
    name = sprintf("keycloak-e2e-introspection-%d", as.integer(app_port)),
    load_timeout = 15000,
    shiny_args = list(
      port = as.integer(app_port),
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  # auto_redirect sends us to Keycloak automatically; wait for login page
  drv$wait_for_js("document.querySelector('#kc-login')", timeout = 15000)

  # Fill credentials & submit
  drv$run_js(
    "
    document.querySelector('#username').value = 'alice';
    document.querySelector('#password').value = 'alice';
    document.querySelector('#kc-login').click();
  "
  )

  # Wait for either success or error state
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

  auth_state <- .get_auth_state_robust(drv)
  testthat::expect_true(
    nchar(auth_state) > 0,
    info = "The '#auth_state' content never stabilized"
  )

  authenticated_flag <- grepl("authenticated: TRUE", auth_state, fixed = TRUE)
  error_description <- .extract_error_description(auth_state)

  list(
    auth_state = auth_state,
    authenticated = authenticated_flag,
    error_description = error_description,
    user_info = drv$get_js(
      "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
    )
  )
}

testthat::test_that("Shiny module E2E with login-time introspection succeeds", {
  testthat::skip_if_not(Sys.getenv("SHINYOAUTH_INT", "") == "1")
  testthat::skip_if_not(
    .test_keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )

  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  # Keycloak realm config pins redirect URIs to port 8100.
  # Keep this aligned or Keycloak will show an error page (no #kc-login).
  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_INTROSPECT", "8100"))
  if (.is_port_in_use(app_port)) {
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

  res <- .test_shiny_module_e2e(
    app_port = app_port,
    provider = provider,
    client_id = "shiny-confidential",
    client_secret = "secret",
    introspect = TRUE,
    introspect_elements = "client_id" # verify client_id match
  )

  testthat::expect_true(
    isTRUE(res$authenticated),
    info = paste0("Login did not succeed. auth_state:\n", res$auth_state)
  )
  testthat::expect_identical(
    res$error_description,
    "<none>",
    info = paste0("Login had error_description. auth_state:\n", res$auth_state)
  )

  user_info <- jsonlite::fromJSON(res$user_info)
  testthat::expect_identical(user_info$preferred_username, "alice")
})

testthat::test_that("Shiny module E2E with introspection endpoint failing does not authenticate", {
  testthat::skip_if_not(Sys.getenv("SHINYOAUTH_INT", "") == "1")
  testthat::skip_if_not(
    .test_keycloak_reachable(),
    "Keycloak not reachable at localhost:8080"
  )

  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  # Keycloak realm config pins redirect URIs to port 8100.
  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_INTROSPECT_BAD",
    "8100"
  ))
  if (.is_port_in_use(app_port)) {
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
  # Make introspection fail against the real provider by pointing to a non-existent endpoint.
  provider@introspection_url <- paste0(
    provider@issuer,
    "/protocol/openid-connect/token/does-not-exist"
  )

  res <- .test_shiny_module_e2e(
    app_port = app_port,
    provider = provider,
    client_id = "shiny-confidential",
    client_secret = "secret",
    introspect = TRUE,
    introspect_elements = character(0)
  )

  testthat::expect_false(
    isTRUE(res$authenticated),
    info = paste0("Unexpected success. auth_state:\n", res$auth_state)
  )
  testthat::expect_false(
    identical(res$error_description, "<none>"),
    info = "Expected an error_description when introspection fails"
  )
})
