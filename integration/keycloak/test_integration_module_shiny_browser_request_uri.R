## Integration test: Browser E2E request_uri flow against Keycloak

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

.wait_for_login_or_auth_result <- function(
  drv,
  timeout = 10000,
  interval = 0.25
) {
  deadline <- Sys.time() + (timeout / 1000)

  while (Sys.time() < deadline) {
    state <- drv$get_js(
      "(function () {
        if (document.querySelector('#kc-login')) {
          return 'login';
        }

        var el = document.querySelector('#auth_state');
        if (!el) {
          return '';
        }

        var text = el.innerText || '';
        if (text.includes('authenticated: TRUE')) {
          return 'done';
        }

        if (
          (text.includes('error_description:') &&
            !text.includes('error_description: <none>')) ||
          (text.includes('error_desc:') &&
            !text.includes('error_desc: <none>'))
        ) {
          return 'done';
        }

        return '';
      })()"
    )

    if (identical(state, "login") || identical(state, "done")) {
      return(state)
    }

    Sys.sleep(interval)
  }

  stop(
    "Timed out waiting for a Keycloak login form or auth result",
    call. = FALSE
  )
}

.submit_keycloak_login <- function(drv) {
  drv$wait_for_js(
    "
    (function () {
      var authState = document.querySelector('#auth_state');
      var login = document.querySelector('#kc-login');
      var username = document.querySelector('#username');
      var password = document.querySelector('#password');
      var form = document.forms.length > 0 ? document.forms[0] : null;
      var onLoginForm = !!(
        login &&
        username &&
        password &&
        form &&
        form.action &&
        form.action.indexOf('/login-actions/authenticate') !== -1
      );
      var alreadyAuthenticated = !!(
        authState &&
        authState.innerText.indexOf('authenticated: TRUE') !== -1
      );
      return onLoginForm || alreadyAuthenticated;
    })();
  ",
    timeout = 20000
  )
  Sys.sleep(1)

  drv$run_js(
    "
    (function () {
      var authState = document.querySelector('#auth_state');
      if (
        authState &&
        authState.innerText.indexOf('authenticated: TRUE') !== -1
      ) {
        return 'already-authenticated';
      }

      var username = document.querySelector('#username');
      var password = document.querySelector('#password');
      var login = document.querySelector('#kc-login');
      var form = (login && login.form) || document.forms[0];

      if (!(username && password && form)) {
        return 'login-form-missing';
      }

      username.value = 'alice';
      password.value = 'alice';
      username.dispatchEvent(new Event('input', { bubbles: true }));
      password.dispatchEvent(new Event('input', { bubbles: true }));
      username.dispatchEvent(new Event('change', { bubbles: true }));
      password.dispatchEvent(new Event('change', { bubbles: true }));

      HTMLFormElement.prototype.submit.call(form);
      return 'submitted';
    })();
  "
  )
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

.request_uri_public_base_url <- function(app_port) {
  override <- Sys.getenv("SHINYOAUTH_E2E_REQUEST_URI_BASE_URL", "")
  if (nzchar(override)) {
    return(override)
  }

  sprintf("http://host.docker.internal:%d", app_port)
}

.allow_request_uri_public_host <- function(
  base_url,
  .local_envir = parent.frame()
) {
  parsed <- httr2::url_parse(base_url)
  scheme <- tolower(as.character(parsed$scheme %||% ""))
  host <- tolower(as.character(parsed$hostname %||% ""))

  if (!identical(scheme, "http") || !nzchar(host)) {
    return(invisible(base_url))
  }

  default_non_https_hosts <- getOption(
    "shinyOAuth.allowed_non_https_hosts",
    default = c("localhost", "127.0.0.1", "::1", "[::1]")
  )

  withr::local_options(
    list(
      shinyOAuth.allowed_non_https_hosts = unique(c(
        default_non_https_hosts,
        host
      ))
    ),
    .local_envir = .local_envir
  )

  invisible(base_url)
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

.start_request_uri_app <- function(
  repo_root,
  app_port,
  public_base_url,
  app_url,
  encrypted_request_object = FALSE
) {
  stdout <- tempfile("request-uri-app-stdout-", fileext = ".log")
  stderr <- tempfile("request-uri-app-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(
      repo_root,
      app_port,
      public_base_url,
      app_url,
      encrypted_request_object
    ) {
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
            "Could not load shinyOAuth for the request_uri background app.",
            "Install pkgload or devtools, or install shinyOAuth into this library.",
            sep = " "
          ),
          call. = FALSE
        )
      }
      source("integration/keycloak/helper-keycloak.R")

      published_request_object <- new.env(parent = emptyenv())
      published_request_object$value <- NA_character_

      shinyoauth_ns <- asNamespace("shinyOAuth")
      original_publish_request_object <- get(
        "publish_shiny_request_object",
        envir = shinyoauth_ns,
        inherits = FALSE
      )
      unlockBinding("publish_shiny_request_object", shinyoauth_ns)
      assign(
        "publish_shiny_request_object",
        function(
          session,
          request_object,
          request_handle_id = NULL,
          expires_at = NULL,
          base_url = NULL
        ) {
          published_request_object$value <- request_object
          original_publish_request_object(
            session = session,
            request_object = request_object,
            request_handle_id = request_handle_id,
            expires_at = expires_at,
            base_url = base_url
          )
        },
        envir = shinyoauth_ns
      )
      lockBinding("publish_shiny_request_object", shinyoauth_ns)

      parsed_public_base <- httr2::url_parse(public_base_url)
      public_scheme <- tolower(as.character(parsed_public_base$scheme %||% ""))
      public_host <- tolower(as.character(parsed_public_base$hostname %||% ""))
      if (identical(public_scheme, "http") && nzchar(public_host)) {
        default_non_https_hosts <- getOption(
          "shinyOAuth.allowed_non_https_hosts",
          default = c("localhost", "127.0.0.1", "::1", "[::1]")
        )
        options(
          shinyOAuth.allowed_non_https_hosts = unique(c(
            default_non_https_hosts,
            public_host
          ))
        )
      }

      provider_args <- list(token_auth_style = "private_key_jwt")
      if (isTRUE(encrypted_request_object)) {
        provider_args$request_object_encryption_alg_values_supported <- c(
          "RSA-OAEP"
        )
        provider_args$request_object_encryption_enc_values_supported <- c(
          "A256CBC-HS512"
        )
      }

      provider <- do.call(make_provider, provider_args)
      client <- if (isTRUE(encrypted_request_object)) {
        make_private_key_jar_jwe_client(provider)
      } else {
        make_private_key_jar_client(provider)
      }
      if (is.null(client)) {
        stop("private_key_jwt test key not available", call. = FALSE)
      }

      client@redirect_uri <- app_url
      client@authorization_request_mode <- "request_uri"

      published_request_uri <- new.env(parent = emptyenv())
      published_request_uri$value <- NA_character_

      ui <- shiny::fluidPage(
        shinyOAuth::use_shinyOAuth(),
        shiny::h3(paste(
          "shinyOAuth + Keycloak",
          if (isTRUE(encrypted_request_object)) {
            "encrypted request_uri"
          } else {
            "request_uri"
          },
          "(E2E)"
        )),
        shiny::actionButton("login_btn", "Login"),
        shiny::tags$hr(),
        shiny::h4("Ready state"),
        shiny::verbatimTextOutput("ready_state"),
        shiny::h4("Auth state"),
        shiny::verbatimTextOutput("auth_state"),
        shiny::h4("Published request_uri"),
        shiny::verbatimTextOutput("request_uri_url"),
        shiny::h4("Published request object metadata"),
        shiny::verbatimTextOutput("request_object_meta"),
        shiny::h4("User info"),
        shiny::verbatimTextOutput("user_info")
      )

      server <- function(input, output, session) {
        auth <- shinyOAuth::oauth_module_server(
          "auth",
          client,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          request_uri_base_url = public_base_url
        )

        shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
          url <- auth$build_auth_url()
          published_request_uri$value <- parse_query_param(
            url,
            "request_uri",
            decode = TRUE
          )

          if (
            is.character(url) &&
              length(url) == 1L &&
              !is.na(url) &&
              nzchar(url)
          ) {
            shinyOAuth:::send_oauth_module_redirect(session, url)
          }
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

        output$request_uri_url <- shiny::renderText({
          request_uri <- published_request_uri$value %||% NA_character_
          if (
            !is.character(request_uri) ||
              length(request_uri) != 1L ||
              is.na(request_uri) ||
              !nzchar(request_uri)
          ) {
            return("<none>")
          }

          request_uri
        })

        output$request_object_meta <- shiny::renderText({
          request_object <- published_request_object$value %||% NA_character_
          if (
            !is.character(request_object) ||
              length(request_object) != 1L ||
              is.na(request_object) ||
              !nzchar(request_object)
          ) {
            return("{}")
          }

          segments <- strsplit(request_object, ".", fixed = TRUE)[[1]]
          header <- if (identical(length(segments), 5L)) {
            shinyOAuth:::jwe_compact_parts(request_object)$protected_header
          } else {
            shinyOAuth:::parse_jwt_header(request_object)
          }

          jsonlite::toJSON(
            list(
              segment_count = length(segments),
              header = header
            ),
            auto_unbox = TRUE,
            null = "null"
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
        shiny::shinyApp(ui, server),
        port = app_port,
        host = "0.0.0.0",
        launch.browser = FALSE
      )
    },
    args = list(
      repo_root = repo_root,
      app_port = app_port,
      public_base_url = public_base_url,
      app_url = app_url,
      encrypted_request_object = encrypted_request_object
    ),
    stdout = stdout,
    stderr = stderr,
    supervise = TRUE
  )

  list(process = process, stdout = stdout, stderr = stderr)
}

.wait_for_request_uri_app <- function(app_process, app_port, timeout = 20) {
  deadline <- Sys.time() + timeout

  while (Sys.time() < deadline) {
    if (!app_process$process$is_alive()) {
      stop(
        paste(
          "Shiny request_uri app exited before it was reachable.",
          .read_log_file(app_process$stderr),
          sep = "\n"
        ),
        call. = FALSE
      )
    }

    if (.is_port_in_use(app_port)) {
      return(invisible(app_process))
    }

    Sys.sleep(0.25)
  }

  stop(
    paste(
      "Timed out waiting for the Shiny request_uri app to listen.",
      .read_log_file(app_process$stderr),
      sep = "\n"
    ),
    call. = FALSE
  )
}

testthat::test_that("Shiny module E2E request_uri flow succeeds with public base override", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (.is_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping shinytest2 E2E"
    ))
  }

  public_base_url <- .request_uri_public_base_url(app_port)
  .allow_request_uri_public_host(public_base_url)
  public_base_url <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url,
    arg = "request_uri_base_url"
  )
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  provider <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(provider)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  app_process <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = app_port,
    public_base_url = public_base_url,
    app_url = app_url
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-e2e-request-uri",
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

  drv$run_js("document.querySelector('#login_btn').click();")

  login_state <- .wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    .submit_keycloak_login(drv)
  }

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
  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("Login failed. auth_state:\n", auth_state)
  )
  testthat::expect_true(
    grepl("error_description: <none>", auth_state, fixed = TRUE),
    info = paste0("Login had error_description. auth_state:\n", auth_state)
  )

  request_uri_url <- trimws(drv$get_js(
    "(function(){var el=document.querySelector('#request_uri_url');return el?el.innerText:'';})()"
  ))

  testthat::expect_true(nzchar(request_uri_url))
  testthat::expect_false(identical(request_uri_url, "<none>"))
  testthat::expect_true(
    startsWith(request_uri_url, public_base_url),
    info = paste0(
      "Expected published request_uri to use the override base URL. Got: ",
      request_uri_url,
      " ; expected prefix: ",
      public_base_url
    )
  )
  testthat::expect_match(request_uri_url, "/session/")

  user_info <- drv$get_js(
    "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
  ) |>
    jsonlite::fromJSON()

  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})

testthat::test_that("Shiny module E2E encrypted request_uri flow succeeds with public base override", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (.is_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping shinytest2 E2E"
    ))
  }

  public_base_url <- .request_uri_public_base_url(app_port)
  .allow_request_uri_public_host(public_base_url)
  public_base_url <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url,
    arg = "request_uri_base_url"
  )
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  provider <- make_provider(
    token_auth_style = "private_key_jwt",
    request_object_encryption_alg_values_supported = c("RSA-OAEP"),
    request_object_encryption_enc_values_supported = c("A256CBC-HS512")
  )
  client <- make_private_key_jar_jwe_client(provider)
  testthat::skip_if(
    is.null(client),
    "private_key_jwt test key not available"
  )

  app_process <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = app_port,
    public_base_url = public_base_url,
    app_url = app_url,
    encrypted_request_object = TRUE
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-e2e-request-uri-jwe",
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

  drv$run_js("document.querySelector('#login_btn').click();")

  login_state <- .wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    .submit_keycloak_login(drv)
  }

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
  testthat::expect_true(
    grepl("authenticated: TRUE", auth_state, fixed = TRUE),
    info = paste0("Login failed. auth_state:\n", auth_state)
  )
  testthat::expect_true(
    grepl("error_description: <none>", auth_state, fixed = TRUE),
    info = paste0("Login had error_description. auth_state:\n", auth_state)
  )

  request_uri_url <- trimws(drv$get_js(
    "(function(){var el=document.querySelector('#request_uri_url');return el?el.innerText:'';})()"
  ))

  testthat::expect_true(nzchar(request_uri_url))
  testthat::expect_false(identical(request_uri_url, "<none>"))
  testthat::expect_true(
    startsWith(request_uri_url, public_base_url),
    info = paste0(
      "Expected published request_uri to use the override base URL. Got: ",
      request_uri_url,
      " ; expected prefix: ",
      public_base_url
    )
  )
  testthat::expect_match(request_uri_url, "/session/")

  request_object_meta <- drv$get_js(
    "(function(){var el=document.querySelector('#request_object_meta');return el?el.innerText:'';})()"
  ) |>
    trimws() |>
    jsonlite::fromJSON()

  testthat::expect_identical(request_object_meta$segment_count, 5L)
  testthat::expect_identical(
    request_object_meta$header$typ,
    "oauth-authz-req+jwt"
  )
  testthat::expect_identical(request_object_meta$header$cty, "JWT")
  testthat::expect_identical(request_object_meta$header$alg, "RSA-OAEP")
  testthat::expect_identical(
    request_object_meta$header$enc,
    "A256CBC-HS512"
  )

  user_info <- drv$get_js(
    "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
  ) |>
    jsonlite::fromJSON()

  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})
