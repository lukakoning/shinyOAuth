## Attack vector: swapped callbacks across real browser sessions
##
## Verifies that a callback minted for one live app/browser session is rejected
## when delivered to another, and that each app can still complete its own
## legitimate callback afterward.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_callback_swap_browser_app <- function(client, title, module_id) {
  published_auth_url <- shiny::reactiveVal(NA_character_)

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel(title),
    shiny::actionButton("prepare_login_btn", "Prepare login"),
    shiny::tags$hr(),
    shiny::verbatimTextOutput("ready_state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::verbatimTextOutput("auth_url"),
    shiny::verbatimTextOutput("user_info")
  )

  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server(
      module_id,
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

    output$user_info <- shiny::renderText({
      if (is.null(auth$token)) {
        return("{}")
      }
      jsonlite::toJSON(auth$token@userinfo, auto_unbox = TRUE, null = "null")
    })
  }

  shiny::shinyApp(ui, server)
}

read_callback_swap_browser_state <- function(drv) {
  jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var authUrl = document.querySelector('#auth_url');
      var userInfo = document.querySelector('#user_info');
      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        user_info: userInfo ? (userInfo.innerText || '') : '{}'
      };
    })())
  "
  ))
}

wait_for_published_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  state <- read_callback_swap_browser_state(drv)
  stopifnot(is.character(state$auth_url), nzchar(state$auth_url))
  state
}

navigate_browser_to_url <- function(drv, url) {
  url_json <- jsonlite::toJSON(url, auto_unbox = TRUE)
  drv$run_js(paste0(
    "window.location.href = ",
    url_json,
    ";"
  ))
}

replace_callback_base_url <- function(callback_url, new_base_url) {
  query <- sub("^[^?]*", "", callback_url)
  paste0(sub("/+$", "", new_base_url), query)
}

read_browser_user_info <- function(drv) {
  raw <- read_callback_swap_browser_state(drv)$user_info %||% "{}"
  if (!is.character(raw) || length(raw) != 1L || !nzchar(raw)) {
    raw <- "{}"
  }
  jsonlite::fromJSON(raw)
}

wait_for_auth_state_transition <- function(
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
      read_callback_swap_browser_state(drv)$auth_state %||% ""
    )
    if (
      nchar(current_state) > 0 &&
        !identical(current_state, previous_state) &&
        (grepl("authenticated: TRUE", current_state, fixed = TRUE) ||
          !grepl("error_description: <none>", current_state, fixed = TRUE))
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

testthat::test_that("swapped browser callbacks are rejected without consuming the rightful callbacks", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  port_a <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_SWAP_A", "8100"))
  port_b <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_SWAP_B", "3000"))
  host_a <- Sys.getenv("SHINYOAUTH_E2E_HOST_SWAP_A", "127.0.0.1")
  host_b <- Sys.getenv("SHINYOAUTH_E2E_HOST_SWAP_B", "127.0.0.1")
  module_id_a <- "auth_a"
  module_id_b <- "auth_b"

  testthat::skip_if(
    identical(port_a, port_b),
    "Callback-swap E2E requires two distinct app ports"
  )

  busy_ports <- c()
  if (keycloak_browser_port_in_use(port_a)) {
    busy_ports <- c(busy_ports, as.character(port_a))
  }
  if (keycloak_browser_port_in_use(port_b)) {
    busy_ports <- c(busy_ports, as.character(port_b))
  }
  testthat::skip_if(
    length(busy_ports) > 0L,
    paste0(
      "Port(s) ",
      paste(busy_ports, collapse = ", "),
      " already in use; skipping callback-swap browser E2E"
    )
  )

  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  client_a <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://%s:%d", host_a, port_a),
    scopes = c("openid", "profile", "email")
  )
  client_b <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://%s:%d", host_b, port_b),
    scopes = c("openid", "profile", "email")
  )

  drv_a <- shinytest2::AppDriver$new(
    make_callback_swap_browser_app(client_a, "Callback swap A", module_id_a),
    name = sprintf("keycloak-callback-swap-a-%d", port_a),
    load_timeout = 15000,
    shiny_args = list(port = port_a, host = host_a, test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_a$stop(), silent = TRUE), add = TRUE)

  drv_b <- shinytest2::AppDriver$new(
    make_callback_swap_browser_app(client_b, "Callback swap B", module_id_b),
    name = sprintf("keycloak-callback-swap-b-%d", port_b),
    load_timeout = 15000,
    shiny_args = list(port = port_b, host = host_b, test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_b$stop(), silent = TRUE), add = TRUE)

  drv_a$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )
  drv_b$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  drv_a$click("prepare_login_btn")
  drv_b$click("prepare_login_btn")

  state_a <- wait_for_published_auth_url(drv_a)
  state_b <- wait_for_published_auth_url(drv_b)

  testthat::expect_true(
    grepl("browser_ready: TRUE", state_a$ready_state, fixed = TRUE)
  )
  testthat::expect_true(
    grepl("browser_ready: TRUE", state_b$ready_state, fixed = TRUE)
  )

  login_a <- perform_login_form_as(
    state_a$auth_url,
    username = "alice",
    password = "alice",
    redirect_uri = client_a@redirect_uri
  )
  login_b <- perform_login_form_as(
    state_b$auth_url,
    username = "bob",
    password = "bob",
    redirect_uri = client_b@redirect_uri
  )

  swapped_for_a <- replace_callback_base_url(
    login_b$callback_url,
    sprintf("http://%s:%d", host_a, port_a)
  )
  legit_for_a <- replace_callback_base_url(
    login_a$callback_url,
    sprintf("http://%s:%d", host_a, port_a)
  )
  legit_for_b <- replace_callback_base_url(
    login_b$callback_url,
    sprintf("http://%s:%d", host_b, port_b)
  )

  navigate_browser_to_url(drv_a, swapped_for_a)
  attacked_state <- keycloak_get_auth_state_robust(drv_a)
  testthat::expect_match(attacked_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(
    attacked_state,
    "invalid_state|state",
    ignore.case = TRUE
  )

  navigate_browser_to_url(drv_b, legit_for_b)
  auth_state_b <- wait_for_auth_state_transition(
    drv_b,
    previous_state = state_b$auth_state,
    timeout = 20000
  )
  user_b <- read_browser_user_info(drv_b)
  testthat::expect_match(auth_state_b, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_identical(user_b$preferred_username, "bob")

  navigate_browser_to_url(drv_a, legit_for_a)
  recovered_state_a <- wait_for_auth_state_transition(
    drv_a,
    previous_state = attacked_state,
    timeout = 20000
  )
  user_a <- read_browser_user_info(drv_a)
  testthat::expect_match(recovered_state_a, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_identical(user_a$preferred_username, "alice")
})
