## Browser E2E: form_post response mode against a live Keycloak realm

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

.read_form_post_browser_state <- function(drv) {
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

.wait_for_form_post_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var authUrl = document.querySelector('#auth_url');
      return !!(authUrl && authUrl.innerText && authUrl.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  .read_form_post_browser_state(drv)
}

.navigate_form_post_browser_to_url <- function(drv, url) {
  drv$run_js(paste0(
    "window.location.href = ",
    jsonlite::toJSON(url, auto_unbox = TRUE),
    ";"
  ))
}

.repo_root <- function() {
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

.read_log_file <- function(path) {
  if (!file.exists(path)) {
    return("")
  }

  paste(readLines(path, warn = FALSE), collapse = "\n")
}

.start_form_post_app <- function(
  repo_root,
  app_port,
  app_url,
  use_par = FALSE,
  title = "Form Post E2E"
) {
  stdout <- tempfile("form-post-app-stdout-", fileext = ".log")
  stderr <- tempfile("form-post-app-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(repo_root, app_port, app_url, use_par, title) {
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
            "Could not load shinyOAuth for the form_post background app.",
            "Install pkgload or devtools, or install shinyOAuth into this library.",
            sep = " "
          ),
          call. = FALSE
        )
      }
      source("integration/keycloak/helper-keycloak.R")

      provider <- make_provider(use_par = use_par)

      client <- shinyOAuth::oauth_client(
        provider = provider,
        client_id = "shiny-public",
        client_secret = "",
        redirect_uri = app_url,
        scopes = c("openid", "profile", "email"),
        response_mode = "form_post"
      )

      base_ui <- shiny::fluidPage(
        shinyOAuth::use_shinyOAuth(),
        shiny::titlePanel(title),
        shiny::actionButton("prepare_login_btn", "Prepare login"),
        shiny::tags$hr(),
        shiny::verbatimTextOutput("ready_state"),
        shiny::verbatimTextOutput("auth_url"),
        shiny::verbatimTextOutput("auth_state"),
        shiny::verbatimTextOutput("user_info")
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
          auto_redirect = FALSE
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

          jsonlite::toJSON(
            auth$token@userinfo,
            auto_unbox = TRUE,
            null = "null"
          )
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
      use_par = use_par,
      title = title
    ),
    stdout = stdout,
    stderr = stderr,
    supervise = TRUE
  )

  list(process = process, stdout = stdout, stderr = stderr)
}

.wait_for_form_post_app <- function(app_process, app_port, timeout = 20) {
  deadline <- Sys.time() + timeout

  while (Sys.time() < deadline) {
    if (!app_process$process$is_alive()) {
      stop(
        paste(
          "Shiny form_post app exited before it was reachable.",
          .read_log_file(app_process$stderr),
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
      "Timed out waiting for the Shiny form_post app to listen.",
      .read_log_file(app_process$stderr),
      sep = "\n"
    ),
    call. = FALSE
  )
}

testthat::test_that("browser form_post login authenticates through oauth_form_post_ui", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_FORM_POST", "8100"))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post E2E"
    ))
  }

  provider <- make_provider()
  testthat::expect_true(
    "form_post" %in% (provider@response_modes_supported %||% character())
  )
  repo_root <- .repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  app_process <- .start_form_post_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-form-post-e2e",
    load_timeout = 15000,
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

  drv$run_js("document.querySelector('#prepare_login_btn').click();")

  prepared <- .wait_for_form_post_auth_url(drv)
  auth_url <- trimws(prepared$auth_url %||% "")
  testthat::expect_true(nzchar(auth_url))
  testthat::expect_identical(
    parse_query_param(auth_url, "response_mode", decode = TRUE),
    "form_post"
  )

  .navigate_form_post_browser_to_url(drv, auth_url)

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
  }

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_state');
      if (!el) {
        return false;
      }

      var text = el.innerText || '';
      return text.includes('authenticated: TRUE') ||
        !text.includes('error_description: <none>');
    })();
  ",
    timeout = 20000
  )

  auth_state <- keycloak_get_auth_state_robust(drv)
  testthat::expect_true(
    nchar(auth_state) > 0,
    info = "The '#auth_state' content never stabilized"
  )
  testthat::expect_match(auth_state, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_match(auth_state, "error_description: <none>", fixed = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var forbidden = [
        'code=', 'state=', 'iss=', 'error=',
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
    timeout = 5000
  )

  observed <- jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify({
      href: window.location.href || '',
      title: document.title || '',
      user_info: (function () {
        var el = document.querySelector('#user_info');
        return el ? (el.innerText || '{}') : '{}';
      })()
    });
  "
  ))
  forbidden <- c(
    "code=",
    "state=",
    "iss=",
    "error=",
    "shinyOAuth_form_post=",
    "shinyOAuth_form_post_id=",
    "id_token=",
    "access_token="
  )

  for (key in forbidden) {
    testthat::expect_false(
      grepl(key, observed$href, fixed = TRUE),
      info = paste0(
        "Callback key leaked in href: ",
        key,
        " href=",
        observed$href
      )
    )
    testthat::expect_false(
      grepl(key, observed$title, fixed = TRUE),
      info = paste0(
        "Callback key leaked in title: ",
        key,
        " title=",
        observed$title
      )
    )
  }

  user_info <- jsonlite::fromJSON(observed$user_info)
  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})

testthat::test_that("browser form_post login still succeeds when the auth request is pushed with PAR", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_PAR",
    "3000"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post + PAR E2E"
    ))
  }

  provider <- make_provider(use_par = TRUE)
  testthat::expect_true(
    "form_post" %in% (provider@response_modes_supported %||% character())
  )
  testthat::expect_true(
    is.character(provider@par_url) &&
      length(provider@par_url) == 1L &&
      nzchar(provider@par_url)
  )

  repo_root <- .repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  app_process <- .start_form_post_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    use_par = TRUE,
    title = "Form Post PAR E2E"
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-form-post-par-e2e",
    load_timeout = 15000,
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

  drv$run_js("document.querySelector('#prepare_login_btn').click();")

  prepared <- .wait_for_form_post_auth_url(drv)
  auth_url <- trimws(prepared$auth_url %||% "")
  testthat::expect_true(nzchar(auth_url))
  testthat::expect_match(auth_url, "[?&]request_uri=")
  testthat::expect_match(auth_url, "[?&]client_id=shiny-public")
  testthat::expect_false(grepl("[?&]state=", auth_url))
  testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))

  .navigate_form_post_browser_to_url(drv, auth_url)

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
  }

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_state');
      if (!el) {
        return false;
      }

      var text = el.innerText || '';
      return text.includes('authenticated: TRUE') ||
        !text.includes('error_description: <none>');
    })();
  ",
    timeout = 20000
  )

  auth_state <- keycloak_get_auth_state_robust(drv)
  testthat::expect_true(
    nchar(auth_state) > 0,
    info = "The '#auth_state' content never stabilized"
  )
  testthat::expect_match(auth_state, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_match(auth_state, "error_description: <none>", fixed = TRUE)

  drv$wait_for_js(
    "
    (function () {
      var forbidden = [
        'code=', 'state=', 'iss=', 'error=',
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
    timeout = 5000
  )

  observed <- jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify({
      href: window.location.href || '',
      title: document.title || '',
      user_info: (function () {
        var el = document.querySelector('#user_info');
        return el ? (el.innerText || '{}') : '{}';
      })()
    });
  "
  ))
  forbidden <- c(
    "code=",
    "state=",
    "iss=",
    "error=",
    "shinyOAuth_form_post=",
    "shinyOAuth_form_post_id=",
    "id_token=",
    "access_token="
  )

  for (key in forbidden) {
    testthat::expect_false(
      grepl(key, observed$href, fixed = TRUE),
      info = paste0(
        "Callback key leaked in href: ",
        key,
        " href=",
        observed$href
      )
    )
    testthat::expect_false(
      grepl(key, observed$title, fixed = TRUE),
      info = paste0(
        "Callback key leaked in title: ",
        key,
        " title=",
        observed$title
      )
    )
  }

  user_info <- jsonlite::fromJSON(observed$user_info)
  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})
