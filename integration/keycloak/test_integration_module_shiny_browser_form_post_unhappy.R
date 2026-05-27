## Browser E2E: form_post unhappy and attacker paths against Keycloak-backed apps

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

.make_form_post_browser_client <- function(app_port) {
  shinyOAuth::oauth_client(
    provider = make_provider(),
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email"),
    response_mode = "form_post"
  )
}

.browser_form_post_repo_root <- function() {
  cwd <- normalizePath(".", winslash = "/", mustWork = TRUE)
  candidates <- unique(c(
    cwd,
    normalizePath(file.path(cwd, "..", ".."), winslash = "/", mustWork = FALSE)
  ))

  for (candidate in candidates) {
    if (
      file.exists(file.path(candidate, "DESCRIPTION")) &&
        dir.exists(file.path(candidate, "R"))
    ) {
      return(candidate)
    }
  }

  stop("Could not find the shinyOAuth repository root", call. = FALSE)
}

.read_form_post_browser_log <- function(path) {
  if (!file.exists(path)) {
    return("")
  }

  paste(readLines(path, warn = FALSE), collapse = "\n")
}

.create_form_post_jarm_browser_fixture <- function(app_url, prefix) {
  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id(prefix),
      public_client = TRUE,
      redirect_uris = list(app_url, paste0(app_url, "/*")),
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "authorization.signed.response.alg" = "RS256"
      )
    )
  )

  list(admin_token = admin_token, fixture = fixture)
}

.start_form_post_jarm_browser_app <- function(
  repo_root,
  app_port,
  app_url,
  title,
  client_id
) {
  stdout <- tempfile("form-post-jarm-app-stdout-", fileext = ".log")
  stderr <- tempfile("form-post-jarm-app-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(repo_root, app_port, app_url, title, client_id) {
      setwd(repo_root)
      if (requireNamespace("pkgload", quietly = TRUE)) {
        pkgload::load_all(
          repo_root,
          quiet = TRUE,
          helpers = FALSE,
          attach_testthat = FALSE
        )
      } else if (requireNamespace("devtools", quietly = TRUE)) {
        devtools::load_all(
          repo_root,
          quiet = TRUE,
          helpers = FALSE,
          attach_testthat = FALSE
        )
      } else if (!requireNamespace("shinyOAuth", quietly = TRUE)) {
        stop(
          paste(
            "Could not load shinyOAuth for the form_post.jwt background app.",
            "Install pkgload or devtools, or install shinyOAuth into this library.",
            sep = " "
          ),
          call. = FALSE
        )
      }
      source("integration/keycloak/helper-keycloak.R")

      provider <- make_provider()
      client <- shinyOAuth::oauth_client(
        provider = provider,
        client_id = client_id,
        client_secret = "",
        redirect_uri = app_url,
        scopes = c("openid", "profile", "email"),
        response_mode = "form_post.jwt",
        authorization_signed_response_alg = "RS256"
      )

      base_ui <- shiny::fluidPage(
        shinyOAuth::use_shinyOAuth(),
        shiny::titlePanel(title),
        shiny::actionButton("prepare_login_btn", "Prepare login"),
        shiny::tags$hr(),
        shiny::verbatimTextOutput("ready_state"),
        shiny::verbatimTextOutput("auth_url"),
        shiny::verbatimTextOutput("auth_state"),
        shiny::verbatimTextOutput("state_store_count")
      )
      ui <- shinyOAuth::oauth_form_post_ui(
        base_ui,
        id = "auth",
        client = client
      )

      server <- function(input, output, session) {
        published_auth_urls <- shiny::reactiveValues()
        session_browser_tokens <- shiny::reactiveValues()

        auth <- shinyOAuth::oauth_module_server(
          "auth",
          client,
          auto_redirect = FALSE,
          indefinite_session = TRUE
        )

        shiny::observe({
          browser_token <- auth$browser_token %||% NA_character_
          if (keycloak_nonempty_string(browser_token)) {
            session_browser_tokens[[session$token]] <- browser_token
          }
        })

        shiny::observeEvent(input$prepare_login_btn, ignoreInit = TRUE, {
          url <- auth$build_auth_url()
          browser_token <- auth$browser_token %||% NA_character_
          if (keycloak_nonempty_string(browser_token)) {
            published_auth_urls[[browser_token]] <- url
          }
        })

        output$ready_state <- shiny::renderText({
          paste("browser_ready:", isTRUE(auth$has_browser_token()))
        })

        output$auth_url <- shiny::renderText({
          browser_token <- session_browser_tokens[[session$token]] %||%
            NA_character_
          auth_url <- if (keycloak_nonempty_string(browser_token)) {
            published_auth_urls[[browser_token]] %||% NA_character_
          } else {
            NA_character_
          }

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

        output$state_store_count <- shiny::renderText({
          shiny::invalidateLater(100, session)
          as.character(length(client@state_store$keys()))
        })
      }

      shiny::runApp(
        shiny::shinyApp(ui, server, uiPattern = ".*"),
        port = app_port,
        host = "0.0.0.0",
        launch.browser = FALSE
      )
    },
    args = list(
      repo_root = repo_root,
      app_port = app_port,
      app_url = app_url,
      title = title,
      client_id = client_id
    ),
    stdout = stdout,
    stderr = stderr,
    supervise = TRUE
  )

  list(process = process, stdout = stdout, stderr = stderr)
}

.wait_for_form_post_jarm_browser_app <- function(
  app_process,
  app_port,
  timeout = 20
) {
  deadline <- Sys.time() + timeout

  while (Sys.time() < deadline) {
    if (!app_process$process$is_alive()) {
      stop(
        paste(
          "Shiny form_post.jwt app exited before it was reachable.",
          .read_form_post_browser_log(app_process$stderr),
          sep = "\n"
        ),
        call. = FALSE
      )
    }

    if (keycloak_browser_port_in_use(app_port)) {
      return(invisible(app_process))
    }

    Sys.sleep(0.25)
  }

  stop(
    paste(
      "Timed out waiting for the Shiny form_post.jwt app to listen.",
      .read_form_post_browser_log(app_process$stderr),
      sep = "\n"
    ),
    call. = FALSE
  )
}

.fetch_form_post_jarm_callback_fields <- function(auth_url, redirect_uri) {
  login <- perform_login_form_as(auth_url, redirect_uri = redirect_uri)

  testthat::expect_identical(
    login$response_mode %||% NA_character_,
    "form_post.jwt"
  )
  testthat::expect_true(is.list(login$form_post_fields))
  testthat::expect_true(
    keycloak_nonempty_string(login$form_post_fields$response)
  )
  testthat::expect_true(startsWith(login$callback_url, redirect_uri))

  login$form_post_fields
}

.make_form_post_browser_app <- function(client, title, module_id = "auth") {
  base_ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel(title),
    shiny::actionButton("prepare_login_btn", "Prepare login"),
    shiny::tags$hr(),
    shiny::verbatimTextOutput("ready_state"),
    shiny::verbatimTextOutput("auth_state"),
    shiny::verbatimTextOutput("auth_url"),
    shiny::verbatimTextOutput("state_store_count")
  )

  ui <- shinyOAuth::oauth_form_post_ui(
    base_ui,
    id = module_id,
    client = client
  )

  server <- function(input, output, session) {
    published_auth_urls <- shiny::reactiveValues()
    session_browser_tokens <- shiny::reactiveValues()

    session$onSessionEnded(function() {
      session_browser_tokens[[session$token]] <- NULL
    })

    auth <- shinyOAuth::oauth_module_server(
      module_id,
      client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )

    shiny::observe({
      browser_token <- auth$browser_token %||% NA_character_
      if (keycloak_nonempty_string(browser_token)) {
        session_browser_tokens[[session$token]] <- browser_token
      }
    })

    build_and_capture_auth_url <- function() {
      url <- auth$build_auth_url()
      browser_token <- auth$browser_token %||% NA_character_

      if (keycloak_nonempty_string(browser_token)) {
        published_auth_urls[[browser_token]] <- url
      }

      url
    }

    shiny::observeEvent(input$prepare_login_btn, ignoreInit = TRUE, {
      build_and_capture_auth_url()
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
      browser_token <- session_browser_tokens[[session$token]] %||%
        NA_character_
      auth_url <- if (keycloak_nonempty_string(browser_token)) {
        published_auth_urls[[browser_token]] %||% NA_character_
      } else {
        NA_character_
      }

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
      shiny::invalidateLater(100, session)
      as.character(length(client@state_store$keys()))
    })
  }

  shiny::shinyApp(ui, server, uiPattern = ".*")
}

.read_form_post_browser_state <- function(drv) {
  state <- jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var authUrl = document.querySelector('#auth_url');
      var stateCount = document.querySelector('#state_store_count');
      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        state_store_count: stateCount ? (stateCount.innerText || '0') : '0',
        href: window.location.href || '',
        title: document.title || '',
        body_text: document.body ? (document.body.innerText || '') : ''
      };
    })())
  "
  ))

  state$state_store_count <- suppressWarnings(as.integer(
    state$state_store_count
  ))
  state
}

.wait_for_form_post_ready <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = timeout
  )

  .read_form_post_browser_state(drv)
}

.wait_for_form_post_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  .read_form_post_browser_state(drv)
}

.wait_for_form_post_auth_state_transition <- function(
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
      .read_form_post_browser_state(drv)$auth_state %||% ""
    )
    if (
      nchar(current_state) > 0 &&
        !identical(current_state, previous_state) &&
        (grepl("authenticated: TRUE", current_state, fixed = TRUE) ||
          !grepl("error: <none>", current_state, fixed = TRUE) ||
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

.wait_for_form_post_page_text <- function(
  drv,
  pattern,
  timeout = 10000,
  interval = 0.25,
  ignore_case = TRUE
) {
  deadline <- Sys.time() + (timeout / 1000)
  current_text <- ""

  while (Sys.time() < deadline) {
    current_text <- .read_form_post_browser_state(drv)$body_text %||% ""
    if (grepl(pattern, current_text, perl = TRUE, ignore.case = ignore_case)) {
      return(current_text)
    }

    Sys.sleep(interval)
  }

  stop(
    paste0(
      "Timed out waiting for page text pattern '",
      pattern,
      "'. Current text: ",
      current_text
    ),
    call. = FALSE
  )
}

.wait_for_form_post_callback_cleanup <- function(drv, timeout = 5000) {
  drv$wait_for_js(
    "
    (function () {
      var forbidden = [
        'code=', 'state=', 'iss=', 'error=',
        'error_description=', 'error_uri=',
        'response=',
        'shinyOAuth_form_post=', 'shinyOAuth_form_post_id=',
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

  .read_form_post_browser_state(drv)
}

.wait_for_form_post_state_store_count <- function(
  drv,
  expected,
  timeout = 5000,
  interval = 0.1
) {
  deadline <- Sys.time() + (timeout / 1000)
  current <- NA_integer_

  while (Sys.time() < deadline) {
    current <- .read_form_post_browser_state(drv)$state_store_count
    if (identical(current, as.integer(expected))) {
      return(current)
    }

    Sys.sleep(interval)
  }

  stop(
    paste0(
      "Timed out waiting for state_store_count = ",
      as.integer(expected),
      ". Current value: ",
      if (is.na(current)) "NA" else as.character(current)
    ),
    call. = FALSE
  )
}

.submit_form_post_browser_callback <- function(drv, action_url, fields) {
  action_url_json <- jsonlite::toJSON(action_url, auto_unbox = TRUE)
  fields_json <- jsonlite::toJSON(fields, auto_unbox = TRUE, null = "null")

  drv$run_js(paste0(
    "(function () {",
    "  var actionUrl = ",
    action_url_json,
    ";",
    "  var fields = ",
    fields_json,
    ";",
    "  var form = document.createElement('form');",
    "  form.method = 'POST';",
    "  form.action = actionUrl;",
    "  Object.keys(fields).forEach(function (name) {",
    "    var value = fields[name];",
    "    if (value === null || value === undefined) { return; }",
    "    var input = document.createElement('input');",
    "    input.type = 'hidden';",
    "    input.name = name;",
    "    input.value = String(value);",
    "    form.appendChild(input);",
    "  });",
    "  document.body.appendChild(form);",
    "  HTMLFormElement.prototype.submit.call(form);",
    "  return true;",
    "})()"
  ))
}

.fetch_form_post_code_callback <- function(auth_url, redirect_uri) {
  login <- perform_login_form_as(auth_url, redirect_uri = redirect_uri)

  testthat::expect_identical(
    login$response_mode %||% NA_character_,
    "form_post"
  )
  testthat::expect_true(is.list(login$form_post_fields))
  testthat::expect_true(keycloak_nonempty_string(login$form_post_fields$code))
  testthat::expect_true(keycloak_nonempty_string(login$form_post_fields$state))
  testthat::expect_true(keycloak_nonempty_string(login$form_post_fields$iss))
  testthat::expect_true(startsWith(login$callback_url, redirect_uri))

  login$form_post_fields
}

.navigate_form_post_browser_to_url <- function(drv, url) {
  url_json <- jsonlite::toJSON(url, auto_unbox = TRUE)
  drv$run_js(paste0("window.location.href = ", url_json, ";"))
}

.random_browser_token_hex <- function(bytes = 64L) {
  paste0(
    sample(c(0:9, letters[1:6]), as.integer(bytes) * 2L, replace = TRUE),
    collapse = ""
  )
}

.tamper_browser_token_cookie <- function(drv, cookie_name, cookie_value) {
  cookie_name_json <- jsonlite::toJSON(cookie_name, auto_unbox = TRUE)
  cookie_value_json <- jsonlite::toJSON(cookie_value, auto_unbox = TRUE)

  drv$run_js(paste0(
    "document.cookie = ",
    cookie_name_json,
    " + '=' + ",
    cookie_value_json,
    " + '; Path=/; SameSite=Strict';"
  ))
}

.post_form_post_http_callback <- function(
  url,
  body,
  content_type = "application/x-www-form-urlencoded",
  query = NULL
) {
  target_url <- url
  if (keycloak_nonempty_string(query)) {
    target_url <- paste0(url, "?", query)
  }

  httr2::request(target_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_raw(charToRaw(body), type = content_type) |>
    httr2::req_timeout(10) |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_perform()
}

testthat::test_that("direct form_post HTTP envelope attacks do not consume login state", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_HTTP_ENVELOPE",
    "8118"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post HTTP envelope E2E"
    ))
  }

  client <- .make_form_post_browser_client(app_port)
  drv <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client,
      title = "Form post HTTP envelope",
      module_id = "auth"
    ),
    name = sprintf("keycloak-form-post-http-envelope-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$run_js("document.querySelector('#prepare_login_btn').click();")
  prepared <- .wait_for_form_post_auth_url(drv, timeout = 30000)
  .wait_for_form_post_state_store_count(drv, 1L)
  auth_url <- trimws(prepared$auth_url %||% "")
  enc_state <- parse_query_param(auth_url, "state")

  bad_type <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0("code=ok&state=", enc_state),
    content_type = "application/json"
  )
  testthat::expect_identical(httr2::resp_status(bad_type), 415L)
  testthat::expect_match(
    httr2::resp_body_string(bad_type),
    "application/x-www-form-urlencoded",
    fixed = TRUE
  )
  .wait_for_form_post_state_store_count(drv, 1L)

  duplicate <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0("code=ok&code=again&state=", enc_state)
  )
  testthat::expect_identical(httr2::resp_status(duplicate), 400L)
  .wait_for_form_post_state_store_count(drv, 1L)

  oversized_body <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0("code=ok&state=", enc_state, "&pad=", strrep("x", 30000))
  )
  testthat::expect_identical(httr2::resp_status(oversized_body), 413L)
  .wait_for_form_post_state_store_count(drv, 1L)

  oversized_query <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0("code=ok&state=", enc_state),
    query = paste0("pad=", strrep("x", 30000))
  )
  testthat::expect_identical(httr2::resp_status(oversized_query), 400L)
  .wait_for_form_post_state_store_count(drv, 1L)

  valid <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0(
      "code=ok&state=",
      enc_state,
      "&iss=",
      utils::URLencode(
        client@provider@issuer,
        reserved = TRUE
      )
    )
  )
  testthat::expect_identical(httr2::resp_status(valid), 303L)
  testthat::expect_match(
    httr2::resp_header(valid, "location"),
    "shinyOAuth_form_post=",
    fixed = TRUE
  )
  # A valid POST only creates a transient bridge handle. The logical login
  # state is consumed later, after the Shiny browser session proves the
  # browser-bound cookie.
  .wait_for_form_post_state_store_count(drv, 2L)

  replayed_valid <- .post_form_post_http_callback(
    client@redirect_uri,
    body = paste0(
      "code=ok&state=",
      enc_state,
      "&iss=",
      utils::URLencode(
        client@provider@issuer,
        reserved = TRUE
      )
    )
  )
  testthat::expect_identical(httr2::resp_status(replayed_valid), 303L)
  .wait_for_form_post_state_store_count(drv, 3L)
})

testthat::test_that("browser form_post provider error callbacks are surfaced and cleaned", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_ERROR",
    "8110"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post error callback E2E"
    ))
  }

  client <- .make_form_post_browser_client(app_port)
  drv <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client,
      title = "Form post error callback",
      module_id = "auth"
    ),
    name = sprintf("keycloak-form-post-error-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$run_js("document.querySelector('#prepare_login_btn').click();")
  prepared <- .wait_for_form_post_auth_url(drv, timeout = 30000)
  auth_url <- trimws(prepared$auth_url %||% "")
  enc_state <- parse_query_param(auth_url, "state")

  testthat::expect_true(nzchar(auth_url))
  testthat::expect_identical(
    parse_query_param(auth_url, "response_mode", decode = TRUE),
    "form_post"
  )

  .submit_form_post_browser_callback(
    drv,
    action_url = client@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state,
      iss = client@provider@issuer
    )
  )

  auth_state <- .wait_for_form_post_auth_state_transition(
    drv,
    previous_state = prepared$auth_state
  )
  testthat::expect_match(auth_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "error: access_denied", fixed = TRUE)
  testthat::expect_match(
    auth_state,
    "error_description: Denied by Keycloak",
    fixed = TRUE
  )

  cleaned <- .wait_for_form_post_callback_cleanup(drv)
  .wait_for_form_post_state_store_count(drv, 0L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv)$state_store_count,
    0L
  )
})

testthat::test_that("browser form_post issuer mismatches are rejected without consuming state", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_ISS",
    "8111"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post issuer mismatch E2E"
    ))
  }

  client <- .make_form_post_browser_client(app_port)
  drv <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client,
      title = "Form post issuer mismatch",
      module_id = "auth"
    ),
    name = sprintf("keycloak-form-post-iss-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$click("prepare_login_btn")
  prepared <- .wait_for_form_post_auth_url(drv)
  auth_url <- trimws(prepared$auth_url %||% "")
  enc_state <- parse_query_param(auth_url, "state")

  .submit_form_post_browser_callback(
    drv,
    action_url = client@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state,
      iss = paste0(client@provider@issuer, "/attacker")
    )
  )

  attacked_page <- .wait_for_form_post_page_text(
    drv,
    pattern = "Callback iss parameter does not match expected issuer",
    ignore_case = FALSE
  )
  testthat::expect_match(
    attacked_page,
    "Invalid OAuth state",
    fixed = TRUE
  )
  testthat::expect_match(
    attacked_page,
    "Callback iss parameter does not match expected issuer \\(RFC 9207\\)"
  )

  .navigate_form_post_browser_to_url(drv, client@redirect_uri)
  after_mismatch <- .wait_for_form_post_ready(drv)
  .wait_for_form_post_state_store_count(drv, 1L)
  after_mismatch <- .read_form_post_browser_state(drv)
  testthat::expect_identical(after_mismatch$state_store_count, 1L)

  .submit_form_post_browser_callback(
    drv,
    action_url = client@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state,
      iss = client@provider@issuer
    )
  )

  recovered_state <- .wait_for_form_post_auth_state_transition(
    drv,
    previous_state = after_mismatch$auth_state
  )
  testthat::expect_match(recovered_state, "error: access_denied", fixed = TRUE)

  recovered <- .wait_for_form_post_callback_cleanup(drv)
  .wait_for_form_post_state_store_count(drv, 0L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv)$state_store_count,
    0L
  )
})

testthat::test_that("browser form_post callbacks with tampered browser cookies are rejected", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_CSRF",
    "8112"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post cookie tamper E2E"
    ))
  }

  client <- .make_form_post_browser_client(app_port)
  drv <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client,
      title = "Form post cookie tamper",
      module_id = "auth"
    ),
    name = sprintf("keycloak-form-post-csrf-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$click("prepare_login_btn")
  prepared <- .wait_for_form_post_auth_url(drv)
  auth_url <- trimws(prepared$auth_url %||% "")
  enc_state <- parse_query_param(auth_url, "state")

  cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_false(is.null(cookie))

  attacker_cookie <- .random_browser_token_hex()
  testthat::expect_false(identical(
    cookie$value %||% NA_character_,
    attacker_cookie
  ))
  .tamper_browser_token_cookie(drv, cookie$name, attacker_cookie)

  tampered_cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_identical(tampered_cookie$value, attacker_cookie)

  .submit_form_post_browser_callback(
    drv,
    action_url = client@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state,
      iss = client@provider@issuer
    )
  )

  auth_state <- .wait_for_form_post_auth_state_transition(
    drv,
    previous_state = prepared$auth_state
  )
  testthat::expect_match(auth_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_match(
    auth_state,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE
  )

  cleaned <- .wait_for_form_post_callback_cleanup(drv)
  # Browser-token rejection now consumes the pending login state once the
  # callback reaches module-side state handling.
  .wait_for_form_post_state_store_count(drv, 0L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv)$state_store_count,
    0L
  )
})

testthat::test_that("browser form_post code callbacks with tampered browser cookies are rejected", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_CODE_CSRF",
    "8100"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post code cookie tamper E2E"
    ))
  }

  client <- .make_form_post_browser_client(app_port)
  drv <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client,
      title = "Form post code cookie tamper",
      module_id = "auth"
    ),
    name = sprintf("keycloak-form-post-code-csrf-%d", app_port),
    load_timeout = 15000,
    shiny_args = list(port = app_port, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$click("prepare_login_btn")
  prepared <- .wait_for_form_post_auth_url(drv)
  auth_url <- trimws(prepared$auth_url %||% "")
  enc_state <- parse_query_param(auth_url, "state", decode = TRUE)
  fields <- .fetch_form_post_code_callback(auth_url, client@redirect_uri)

  testthat::expect_identical(fields$state, enc_state)

  cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_false(is.null(cookie))

  attacker_cookie <- .random_browser_token_hex()
  testthat::expect_false(identical(
    cookie$value %||% NA_character_,
    attacker_cookie
  ))
  .tamper_browser_token_cookie(drv, cookie$name, attacker_cookie)

  tampered_cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_identical(tampered_cookie$value, attacker_cookie)

  .submit_form_post_browser_callback(
    drv,
    action_url = client@redirect_uri,
    fields = fields
  )

  auth_state <- .wait_for_form_post_auth_state_transition(
    drv,
    previous_state = prepared$auth_state
  )
  testthat::expect_match(auth_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_match(
    auth_state,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE
  )

  .wait_for_form_post_callback_cleanup(drv)
  # Browser-token rejection now consumes the pending login state once the
  # callback reaches module-side state handling.
  .wait_for_form_post_state_store_count(drv, 0L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv)$state_store_count,
    0L
  )
})

testthat::test_that("swapped form_post code callbacks against the wrong app are rejected without consuming rightful callbacks", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")

  port_a <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_CODE_SWAP_A",
    "8100"
  ))
  port_b <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_CODE_SWAP_B",
    "3000"
  ))

  testthat::skip_if(
    identical(port_a, port_b),
    "Form-post code swap E2E requires two distinct app ports"
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
      " already in use; skipping form_post code swap E2E"
    )
  )

  client_a <- .make_form_post_browser_client(port_a)
  client_b <- .make_form_post_browser_client(port_b)

  drv_a <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client_a,
      title = "Form post code swap A",
      module_id = "auth_a"
    ),
    name = sprintf("keycloak-form-post-code-swap-a-%d", port_a),
    load_timeout = 15000,
    shiny_args = list(port = port_a, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_a$stop(), silent = TRUE), add = TRUE)

  drv_b <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client_b,
      title = "Form post code swap B",
      module_id = "auth_b"
    ),
    name = sprintf("keycloak-form-post-code-swap-b-%d", port_b),
    load_timeout = 15000,
    shiny_args = list(port = port_b, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_b$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv_a)
  .wait_for_form_post_ready(drv_b)

  drv_a$run_js("document.querySelector('#prepare_login_btn').click();")
  drv_b$run_js("document.querySelector('#prepare_login_btn').click();")

  prepared_a <- .wait_for_form_post_auth_url(drv_a, timeout = 30000)
  prepared_b <- .wait_for_form_post_auth_url(drv_b, timeout = 30000)
  enc_state_a <- parse_query_param(prepared_a$auth_url, "state")
  fields_b <- .fetch_form_post_code_callback(
    prepared_b$auth_url,
    client_b@redirect_uri
  )

  .submit_form_post_browser_callback(
    drv_a,
    action_url = client_a@redirect_uri,
    fields = fields_b
  )

  attacked_page <- .wait_for_form_post_page_text(
    drv_a,
    pattern = "state token decrypted payload is not valid JSON"
  )
  testthat::expect_match(
    attacked_page,
    "Invalid OAuth state",
    fixed = TRUE
  )
  testthat::expect_match(
    attacked_page,
    "state token decrypted payload is not valid JSON",
    ignore.case = TRUE
  )

  .navigate_form_post_browser_to_url(drv_a, client_a@redirect_uri)
  restored_a <- .wait_for_form_post_ready(drv_a)
  .wait_for_form_post_state_store_count(drv_a, 1L)
  .wait_for_form_post_state_store_count(drv_b, 1L)

  .submit_form_post_browser_callback(
    drv_b,
    action_url = client_b@redirect_uri,
    fields = fields_b
  )
  auth_state_b <- .wait_for_form_post_auth_state_transition(
    drv_b,
    previous_state = prepared_b$auth_state
  )
  testthat::expect_match(auth_state_b, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_match(
    auth_state_b,
    "error_description: <none>",
    fixed = TRUE
  )

  .wait_for_form_post_callback_cleanup(drv_b)
  .wait_for_form_post_state_store_count(drv_b, 0L)

  .submit_form_post_browser_callback(
    drv_a,
    action_url = client_a@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state_a,
      iss = client_a@provider@issuer
    )
  )
  auth_state_a <- .wait_for_form_post_auth_state_transition(
    drv_a,
    previous_state = restored_a$auth_state
  )
  testthat::expect_match(auth_state_a, "error: access_denied", fixed = TRUE)

  .wait_for_form_post_callback_cleanup(drv_a)
  .wait_for_form_post_state_store_count(drv_a, 0L)
})

testthat::test_that("swapped form_post callbacks against the wrong app are rejected without consuming rightful callbacks", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  port_a <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_SWAP_A",
    "8113"
  ))
  port_b <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_SWAP_B",
    "8114"
  ))

  testthat::skip_if(
    identical(port_a, port_b),
    "Form-post swap E2E requires two distinct app ports"
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
      " already in use; skipping form_post swap E2E"
    )
  )

  client_a <- .make_form_post_browser_client(port_a)
  client_b <- .make_form_post_browser_client(port_b)

  drv_a <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client_a,
      title = "Form post swap A",
      module_id = "auth_a"
    ),
    name = sprintf("keycloak-form-post-swap-a-%d", port_a),
    load_timeout = 15000,
    shiny_args = list(port = port_a, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_a$stop(), silent = TRUE), add = TRUE)

  drv_b <- shinytest2::AppDriver$new(
    .make_form_post_browser_app(
      client_b,
      title = "Form post swap B",
      module_id = "auth_b"
    ),
    name = sprintf("keycloak-form-post-swap-b-%d", port_b),
    load_timeout = 15000,
    shiny_args = list(port = port_b, host = "127.0.0.1", test.mode = TRUE),
    wait = FALSE
  )
  on.exit(try(drv_b$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv_a)
  .wait_for_form_post_ready(drv_b)

  drv_a$run_js("document.querySelector('#prepare_login_btn').click();")
  drv_b$run_js("document.querySelector('#prepare_login_btn').click();")

  prepared_a <- .wait_for_form_post_auth_url(drv_a, timeout = 30000)
  prepared_b <- .wait_for_form_post_auth_url(drv_b, timeout = 30000)
  enc_state_a <- parse_query_param(prepared_a$auth_url, "state")
  enc_state_b <- parse_query_param(prepared_b$auth_url, "state")

  .submit_form_post_browser_callback(
    drv_a,
    action_url = client_a@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state_b,
      iss = client_a@provider@issuer
    )
  )

  attacked_page <- .wait_for_form_post_page_text(
    drv_a,
    pattern = "state token decrypted payload is not valid JSON"
  )
  testthat::expect_match(
    attacked_page,
    "Invalid OAuth state",
    fixed = TRUE
  )
  testthat::expect_match(
    attacked_page,
    "state token decrypted payload is not valid JSON",
    ignore.case = TRUE
  )

  .navigate_form_post_browser_to_url(drv_a, client_a@redirect_uri)
  restored_a <- .wait_for_form_post_ready(drv_a)
  restored_b <- .read_form_post_browser_state(drv_b)
  .wait_for_form_post_state_store_count(drv_a, 1L)
  .wait_for_form_post_state_store_count(drv_b, 1L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv_a)$state_store_count,
    1L
  )
  testthat::expect_identical(
    .read_form_post_browser_state(drv_b)$state_store_count,
    1L
  )

  .submit_form_post_browser_callback(
    drv_a,
    action_url = client_a@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state_a,
      iss = client_a@provider@issuer
    )
  )
  auth_state_a <- .wait_for_form_post_auth_state_transition(
    drv_a,
    previous_state = restored_a$auth_state
  )
  testthat::expect_match(auth_state_a, "error: access_denied", fixed = TRUE)

  .submit_form_post_browser_callback(
    drv_b,
    action_url = client_b@redirect_uri,
    fields = list(
      error = "access_denied",
      error_description = "Denied by Keycloak",
      state = enc_state_b,
      iss = client_b@provider@issuer
    )
  )
  auth_state_b <- .wait_for_form_post_auth_state_transition(
    drv_b,
    previous_state = prepared_b$auth_state
  )
  testthat::expect_match(auth_state_b, "error: access_denied", fixed = TRUE)

  final_a <- .wait_for_form_post_callback_cleanup(drv_a)
  final_b <- .wait_for_form_post_callback_cleanup(drv_b)
  .wait_for_form_post_state_store_count(drv_a, 0L)
  .wait_for_form_post_state_store_count(drv_b, 0L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv_a)$state_store_count,
    0L
  )
  testthat::expect_identical(
    .read_form_post_browser_state(drv_b)$state_store_count,
    0L
  )
})

testthat::test_that("browser form_post.jwt callbacks with tampered browser cookies are rejected", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM_CSRF",
    "8125"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post.jwt cookie tamper E2E"
    ))
  }

  repo_root <- .browser_form_post_repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  setup <- .create_form_post_jarm_browser_fixture(
    app_url = app_url,
    prefix = "shiny-form-post-jarm-csrf"
  )
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  app_process <- .start_form_post_jarm_browser_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    title = "Form post JWT cookie tamper",
    client_id = setup$fixture$client_id
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_jarm_browser_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = sprintf("keycloak-form-post-jarm-csrf-%d", app_port),
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$run_js("document.querySelector('#prepare_login_btn').click();")
  prepared <- .wait_for_form_post_auth_url(drv, timeout = 30000)
  auth_url <- trimws(prepared$auth_url %||% "")
  fields <- .fetch_form_post_jarm_callback_fields(auth_url, app_url)

  cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_false(is.null(cookie))

  attacker_cookie <- .random_browser_token_hex()
  testthat::expect_false(identical(
    cookie$value %||% NA_character_,
    attacker_cookie
  ))
  .tamper_browser_token_cookie(drv, cookie$name, attacker_cookie)

  tampered_cookie <- find_browser_token_cookie(drv, id = "auth", timeout = 8)
  testthat::expect_identical(tampered_cookie$value, attacker_cookie)

  .submit_form_post_browser_callback(
    drv,
    action_url = app_url,
    fields = fields
  )

  auth_state <- .wait_for_form_post_auth_state_transition(
    drv,
    previous_state = prepared$auth_state
  )
  testthat::expect_match(auth_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_match(
    auth_state,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE
  )

  .wait_for_form_post_callback_cleanup(drv)
})

testthat::test_that("browser form_post.jwt direct callbacks are rejected before bridging", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM_DIRECT",
    "8128"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping direct form_post.jwt E2E"
    ))
  }

  repo_root <- .browser_form_post_repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  setup <- .create_form_post_jarm_browser_fixture(
    app_url = app_url,
    prefix = "shiny-form-post-jarm-direct"
  )
  on.exit(
    keycloak_delete_client(setup$admin_token, id = setup$fixture$id),
    add = TRUE
  )

  app_process <- .start_form_post_jarm_browser_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    title = "Form post JWT direct callback",
    client_id = setup$fixture$client_id
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_jarm_browser_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = sprintf("keycloak-form-post-jarm-direct-%d", app_port),
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv)
  drv$run_js("document.querySelector('#prepare_login_btn').click();")
  prepared <- .wait_for_form_post_auth_url(drv, timeout = 30000)
  auth_url <- trimws(prepared$auth_url %||% "")
  fields <- .fetch_form_post_jarm_callback_fields(auth_url, app_url)

  .submit_form_post_browser_callback(
    drv,
    action_url = app_url,
    fields = list(
      code = "attacker-code",
      state = fields$state,
      iss = fields$iss
    )
  )

  attacked_page <- .wait_for_form_post_page_text(
    drv,
    pattern = "OAuth form_post JARM callback must include the response parameter"
  )
  testthat::expect_match(
    attacked_page,
    "direct OAuth callback parameters are not accepted",
    fixed = TRUE
  )

  .navigate_form_post_browser_to_url(drv, app_url)
  .wait_for_form_post_ready(drv)
  .wait_for_form_post_state_store_count(drv, 1L)
  testthat::expect_identical(
    .read_form_post_browser_state(drv)$state_store_count,
    1L
  )
})

testthat::test_that("swapped form_post.jwt callbacks are rejected on the wrong app while the rightful target callback still succeeds", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")

  port_a <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM_SWAP_A",
    "8126"
  ))
  port_b <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM_SWAP_B",
    "8127"
  ))

  testthat::skip_if(
    identical(port_a, port_b),
    "Form-post JWT swap E2E requires two distinct app ports"
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
      " already in use; skipping form_post.jwt swap E2E"
    )
  )

  repo_root <- .browser_form_post_repo_root()
  app_url_a <- sprintf("http://127.0.0.1:%d", port_a)
  app_url_b <- sprintf("http://127.0.0.1:%d", port_b)
  setup_a <- .create_form_post_jarm_browser_fixture(
    app_url = app_url_a,
    prefix = "shiny-form-post-jarm-swap-a"
  )
  on.exit(
    keycloak_delete_client(setup_a$admin_token, id = setup_a$fixture$id),
    add = TRUE
  )
  setup_b <- .create_form_post_jarm_browser_fixture(
    app_url = app_url_b,
    prefix = "shiny-form-post-jarm-swap-b"
  )
  on.exit(
    keycloak_delete_client(setup_b$admin_token, id = setup_b$fixture$id),
    add = TRUE
  )

  app_process_a <- .start_form_post_jarm_browser_app(
    repo_root = repo_root,
    app_port = port_a,
    app_url = app_url_a,
    title = "Form post JWT swap A",
    client_id = setup_a$fixture$client_id
  )
  on.exit(try(app_process_a$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_jarm_browser_app(app_process_a, port_a)

  app_process_b <- .start_form_post_jarm_browser_app(
    repo_root = repo_root,
    app_port = port_b,
    app_url = app_url_b,
    title = "Form post JWT swap B",
    client_id = setup_b$fixture$client_id
  )
  on.exit(try(app_process_b$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_jarm_browser_app(app_process_b, port_b)

  drv_a <- shinytest2::AppDriver$new(
    app_url_a,
    name = sprintf("keycloak-form-post-jarm-swap-a-%d", port_a),
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv_a$stop(), silent = TRUE), add = TRUE)

  drv_b <- shinytest2::AppDriver$new(
    app_url_b,
    name = sprintf("keycloak-form-post-jarm-swap-b-%d", port_b),
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv_b$stop(), silent = TRUE), add = TRUE)

  .wait_for_form_post_ready(drv_a)
  .wait_for_form_post_ready(drv_b)

  drv_a$run_js("document.querySelector('#prepare_login_btn').click();")
  drv_b$run_js("document.querySelector('#prepare_login_btn').click();")

  prepared_a <- .wait_for_form_post_auth_url(drv_a, timeout = 30000)
  prepared_b <- .wait_for_form_post_auth_url(drv_b, timeout = 30000)
  fields_a <- .fetch_form_post_jarm_callback_fields(
    prepared_a$auth_url,
    app_url_a
  )
  fields_b <- .fetch_form_post_jarm_callback_fields(
    prepared_b$auth_url,
    app_url_b
  )

  .submit_form_post_browser_callback(
    drv_a,
    action_url = app_url_a,
    fields = fields_b
  )

  attacked_page <- .wait_for_form_post_page_text(
    drv_a,
    pattern = "JARM aud claim does not include client_id"
  )
  testthat::expect_match(attacked_page, "Invalid OAuth state", fixed = TRUE)
  testthat::expect_match(
    attacked_page,
    "JARM aud claim does not include client_id",
    ignore.case = TRUE
  )

  .navigate_form_post_browser_to_url(drv_a, app_url_a)
  restored_a <- .wait_for_form_post_ready(drv_a)

  .submit_form_post_browser_callback(
    drv_b,
    action_url = app_url_b,
    fields = fields_b
  )
  auth_state_b <- .wait_for_form_post_auth_state_transition(
    drv_b,
    previous_state = prepared_b$auth_state
  )
  testthat::expect_match(auth_state_b, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_match(
    auth_state_b,
    "error_description: <none>",
    fixed = TRUE
  )

  .wait_for_form_post_callback_cleanup(drv_b)

  .submit_form_post_browser_callback(
    drv_a,
    action_url = app_url_a,
    fields = fields_a
  )
  auth_state_a <- .wait_for_form_post_auth_state_transition(
    drv_a,
    previous_state = restored_a$auth_state
  )
  testthat::expect_match(auth_state_a, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state_a, "error: invalid_state", fixed = TRUE)
  testthat::expect_match(
    auth_state_a,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE
  )

  .wait_for_form_post_callback_cleanup(drv_a)
})
