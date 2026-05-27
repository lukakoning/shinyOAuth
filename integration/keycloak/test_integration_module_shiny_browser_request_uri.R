## Integration test: Browser E2E request_uri flow against Keycloak

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
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

.create_request_uri_client_fixture <- function(
  public_base_url,
  encrypted_request_object = FALSE
) {
  admin_token <- keycloak_admin_token()
  template_client_id <- if (isTRUE(encrypted_request_object)) {
    "shiny-jar-pjwt-jwe"
  } else {
    "shiny-jar-pjwt"
  }
  template <- keycloak_find_client(admin_token, template_client_id)
  if (is.null(template)) {
    testthat::skip("request_uri private_key_jwt fixture not available")
  }

  template$clientId <- keycloak_temp_client_id(
    if (isTRUE(encrypted_request_object)) {
      "shiny-request-uri-pjwt-jwe"
    } else {
      "shiny-request-uri-pjwt"
    }
  )
  template$redirectUris <- keycloak_default_redirect_uris()
  template$attributes <- template$attributes %||% list()
  template$attributes[["request.uris"]] <- paste0(
    sub("/+$", "", public_base_url),
    "/session/*"
  )
  template$id <- NULL
  template$secret <- NULL
  template$registrationAccessToken <- NULL
  template$access <- NULL

  fixture <- keycloak_create_client(
    token = admin_token,
    body = template
  )

  list(admin_token = admin_token, fixture = fixture)
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
  encrypted_request_object = FALSE,
  prepare_only = FALSE,
  client_id = NULL,
  module_id = "auth",
  request_object_ttl = NULL
) {
  stdout <- tempfile("request-uri-app-stdout-", fileext = ".log")
  stderr <- tempfile("request-uri-app-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(
      repo_root,
      app_port,
      public_base_url,
      app_url,
      encrypted_request_object,
      prepare_only,
      client_id,
      module_id,
      request_object_ttl
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

      published_auth_urls <- shiny::reactiveValues()
      published_request_uris <- shiny::reactiveValues()
      published_request_objects <- shiny::reactiveValues()
      session_browser_tokens <- shiny::reactiveValues()

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
          session_token <- session$token %||% NA_character_
          browser_token <- if (
            is.character(session_token) &&
              length(session_token) == 1L &&
              !is.na(session_token) &&
              nzchar(session_token)
          ) {
            session_browser_tokens[[session_token]] %||% NA_character_
          } else {
            NA_character_
          }

          if (keycloak_nonempty_string(browser_token)) {
            published_request_objects[[browser_token]] <- request_object
          }

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
        make_private_key_jar_jwe_client(
          provider,
          client_id = client_id %||% "shiny-jar-pjwt-jwe",
          redirect_uri = app_url
        )
      } else {
        make_private_key_jar_client(
          provider,
          client_id = client_id %||% "shiny-jar-pjwt",
          redirect_uri = app_url
        )
      }
      if (is.null(client)) {
        stop("private_key_jwt test key not available", call. = FALSE)
      }

      client@request_object_mode <- "request_uri"
      if (!is.null(request_object_ttl)) {
        client@request_object_ttl <- as.numeric(
          request_object_ttl
        )
      }
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
        shiny::actionButton(
          if (isTRUE(prepare_only)) "prepare_login_btn" else "login_btn",
          if (isTRUE(prepare_only)) "Prepare login" else "Login"
        ),
        shiny::tags$hr(),
        shiny::h4("Ready state"),
        shiny::verbatimTextOutput("ready_state"),
        shiny::h4("Auth state"),
        shiny::verbatimTextOutput("auth_state"),
        shiny::h4("State store count"),
        shiny::verbatimTextOutput("state_store_count"),
        shiny::h4("Published auth URL"),
        shiny::verbatimTextOutput("auth_url"),
        shiny::h4("Published request_uri"),
        shiny::verbatimTextOutput("request_uri_url"),
        shiny::h4("Published request object metadata"),
        shiny::verbatimTextOutput("request_object_meta"),
        shiny::h4("User info"),
        shiny::verbatimTextOutput("user_info")
      )

      server <- function(input, output, session) {
        session$onSessionEnded(function() {
          session_browser_tokens[[session$token]] <- NULL
        })

        auth <- shinyOAuth::oauth_module_server(
          module_id,
          client,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          request_uri_base_url = public_base_url
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
            published_request_uris[[browser_token]] <- parse_query_param(
              url,
              "request_uri",
              decode = TRUE
            )
          }

          url
        }

        shiny::observeEvent(input$login_btn, ignoreInit = TRUE, {
          url <- build_and_capture_auth_url()

          if (
            is.character(url) &&
              length(url) == 1L &&
              !is.na(url) &&
              nzchar(url)
          ) {
            shinyOAuth:::send_oauth_module_redirect(session, url)
          }
        })

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
            if (!is.null(auth$error)) auth$error else "<none>",
            "error_description:",
            if (!is.null(auth$error_description)) {
              auth$error_description
            } else {
              "<none>"
            }
          )
        })

        output$state_store_count <- shiny::renderText({
          as.character(length(client@state_store$keys()))
        })

        output$auth_url <- shiny::renderText({
          browser_token <- auth$browser_token %||% NA_character_
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

        output$request_uri_url <- shiny::renderText({
          browser_token <- auth$browser_token %||% NA_character_
          request_uri <- if (keycloak_nonempty_string(browser_token)) {
            published_request_uris[[browser_token]] %||% NA_character_
          } else {
            NA_character_
          }
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
          browser_token <- auth$browser_token %||% NA_character_
          request_object <- if (keycloak_nonempty_string(browser_token)) {
            published_request_objects[[browser_token]] %||% NA_character_
          } else {
            NA_character_
          }
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
      encrypted_request_object = encrypted_request_object,
      prepare_only = prepare_only,
      client_id = client_id,
      module_id = module_id,
      request_object_ttl = request_object_ttl
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

    if (keycloak_browser_port_in_use(app_port)) {
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

.read_request_uri_browser_state <- function(drv) {
  jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify((function () {
      var ready = document.querySelector('#ready_state');
      var auth = document.querySelector('#auth_state');
      var stateCount = document.querySelector('#state_store_count');
      var authUrl = document.querySelector('#auth_url');
      var requestUri = document.querySelector('#request_uri_url');
      var userInfo = document.querySelector('#user_info');
      return {
        ready_state: ready ? (ready.innerText || '') : '',
        auth_state: auth ? (auth.innerText || '') : '',
        state_store_count: stateCount ? (stateCount.innerText || '') : '',
        auth_url: authUrl ? (authUrl.innerText || '') : '',
        request_uri_url: requestUri ? (requestUri.innerText || '') : '',
        user_info: userInfo ? (userInfo.innerText || '') : '{}'
      };
    })())
  "
  ))
}

.read_request_uri_page_text <- function(drv) {
  drv$get_js(
    "(function(){return document.body ? (document.body.innerText || '') : '';})()"
  )
}

.wait_for_request_uri_auth_url <- function(drv, timeout = 15000) {
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_url');
      return !!(el && el.innerText && el.innerText !== '<none>');
    })();
  ",
    timeout = timeout
  )

  .read_request_uri_browser_state(drv)
}

.wait_for_request_uri_capture <- function(
  drv,
  timeout = 20000,
  require_request_object = FALSE
) {
  drv$wait_for_js(
    if (isTRUE(require_request_object)) {
      "
      (function () {
        var requestUri = document.querySelector('#request_uri_url');
        var requestObject = document.querySelector('#request_object_meta');
        return !!(
          requestUri && requestUri.innerText && requestUri.innerText !== '<none>' &&
          requestObject && requestObject.innerText && requestObject.innerText !== '{}'
        );
      })();
    "
    } else {
      "
      (function () {
        var requestUri = document.querySelector('#request_uri_url');
        return !!(
          requestUri && requestUri.innerText && requestUri.innerText !== '<none>'
        );
      })();
    "
    },
    timeout = timeout
  )

  .read_request_uri_browser_state(drv)
}

.navigate_browser_to_url <- function(drv, url) {
  url_json <- jsonlite::toJSON(url, auto_unbox = TRUE)
  drv$run_js(paste0("window.location.href = ", url_json, ";"))
}

.replace_callback_base_url <- function(callback_url, new_base_url) {
  query <- sub("^[^?]*", "", callback_url)
  paste0(sub("/+$", "", new_base_url), query)
}

.read_request_uri_user_info <- function(drv) {
  raw <- .read_request_uri_browser_state(drv)$user_info %||% "{}"
  if (!is.character(raw) || length(raw) != 1L || !nzchar(raw)) {
    raw <- "{}"
  }

  jsonlite::fromJSON(raw)
}

.wait_for_request_uri_auth_state_transition <- function(
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
      .read_request_uri_browser_state(drv)$auth_state %||% ""
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

.read_request_uri_csrf_payload <- function(drv) {
  payload <- .read_request_uri_browser_state(drv)
  cookies <- jsonlite::fromJSON(drv$get_js(
    "
    JSON.stringify((function () {
      var cookie = document.cookie || '';
      var parts = cookie ? cookie.split('; ') : [];
      var cookiePrefixes = ['shinyOAuth_sid-auth-', '__Host-shinyOAuth_sid-auth-'];
      var cookieName = '';
      var cookieValue = '';

      for (var i = 0; i < parts.length; i++) {
        for (var j = 0; j < cookiePrefixes.length; j++) {
          if (parts[i].lastIndexOf(cookiePrefixes[j], 0) === 0) {
            var eq = parts[i].indexOf('=');
            if (eq !== -1) {
              cookieName = parts[i].substring(0, eq);
              cookieValue = parts[i].substring(eq + 1);
              break;
            }
          }
        }
        if (cookieName) { break; }
      }

      return {
        cookie_name: cookieName,
        cookie_value: cookieValue
      };
    })())
  "
  ))

  c(payload, cookies)
}

.tamper_browser_token_cookie <- function(drv, cookie_name, cookie_value) {
  cookie_name_json <- jsonlite::toJSON(cookie_name, auto_unbox = TRUE)
  cookie_value_json <- jsonlite::toJSON(cookie_value, auto_unbox = TRUE)

  jsonlite::fromJSON(drv$get_js(
    paste0(
      "JSON.stringify((function () {",
      "  var cookieName = ",
      cookie_name_json,
      ";",
      "  var cookieValue = ",
      cookie_value_json,
      ";",
      "  document.cookie = cookieName + '=' + cookieValue + '; Path=/; SameSite=Strict';",
      "  var parts = document.cookie ? document.cookie.split('; ') : [];",
      "  var currentValue = '';",
      "  for (var i = 0; i < parts.length; i++) {",
      "    if (parts[i].lastIndexOf(cookieName + '=', 0) === 0) {",
      "      currentValue = parts[i].substring(cookieName.length + 1);",
      "      break;",
      "    }",
      "  }",
      "  return { current_value: currentValue };",
      "})())"
    )
  ))
}

testthat::test_that("Shiny module E2E request_uri flow succeeds with public base override", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (keycloak_browser_port_in_use(app_port)) {
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
    app_url = app_url,
    prepare_only = TRUE
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

  drv$run_js("document.querySelector('#prepare_login_btn').click();")

  state <- .wait_for_request_uri_auth_url(drv)
  capture_state <- .wait_for_request_uri_capture(drv)

  request_uri_url <- trimws(capture_state$request_uri_url %||% "")

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

  .navigate_browser_to_url(drv, state$auth_url)

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
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

  auth_state <- keycloak_get_auth_state_robust(drv)
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

  user_info <- drv$get_js(
    "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
  ) |>
    jsonlite::fromJSON()

  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})

testthat::test_that("Shiny module E2E request_uri replay does not leak stale state into a fresh session", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_REQUEST_URI_REPLAY",
    "8100"
  ))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping request_uri replay E2E"
    ))
  }

  public_base_url <- .request_uri_public_base_url(app_port)
  .allow_request_uri_public_host(public_base_url)
  public_base_url <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url,
    arg = "request_uri_base_url"
  )
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  app_process <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = app_port,
    public_base_url = public_base_url,
    app_url = app_url,
    prepare_only = TRUE
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-e2e-request-uri-replay",
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

  prepared <- .wait_for_request_uri_auth_url(drv)
  .wait_for_request_uri_capture(drv)

  .navigate_browser_to_url(drv, prepared$auth_url)

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
  }

  auth_state <- .wait_for_request_uri_auth_state_transition(
    drv,
    previous_state = prepared$auth_state
  )
  testthat::expect_match(auth_state, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_match(auth_state, "error_description: <none>", fixed = TRUE)

  .navigate_browser_to_url(drv, prepared$auth_url)
  drv$wait_for_js(
    "
    (function () {
      var text = document.body ? (document.body.innerText || '') : '';
      return /Invalid Request|already used|Request Object already used/i.test(text);
    })();
  ",
    timeout = 20000
  )

  replay_text <- .read_request_uri_page_text(drv)
  testthat::expect_match(
    replay_text,
    "Invalid Request|already used|Request Object already used",
    ignore.case = TRUE
  )

  .navigate_browser_to_url(drv, app_url)
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  final_state <- .read_request_uri_browser_state(drv)
  testthat::expect_match(
    final_state$auth_state %||% "",
    "authenticated: FALSE",
    fixed = TRUE
  )
  testthat::expect_match(
    final_state$auth_state %||% "",
    "has_token: FALSE",
    fixed = TRUE
  )
  testthat::expect_match(
    final_state$auth_state %||% "",
    "error_description: <none>",
    fixed = TRUE
  )
  testthat::expect_identical(trimws(final_state$state_store_count %||% ""), "0")

  user_info <- .read_request_uri_user_info(drv)
  testthat::expect_null(user_info$preferred_username)
})

testthat::test_that("Shiny module E2E request_uri expiry is rejected before callback and leaves pending state untouched", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_REQUEST_URI_EXPIRED",
    "8100"
  ))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping request_uri expiry E2E"
    ))
  }

  public_base_url <- .request_uri_public_base_url(app_port)
  .allow_request_uri_public_host(public_base_url)
  public_base_url <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url,
    arg = "request_uri_base_url"
  )
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  app_process <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = app_port,
    public_base_url = public_base_url,
    app_url = app_url,
    prepare_only = TRUE,
    request_object_ttl = 1
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-e2e-request-uri-expired",
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

  prepared <- .wait_for_request_uri_auth_url(drv)
  .wait_for_request_uri_capture(drv)

  Sys.sleep(2)

  .navigate_browser_to_url(drv, prepared$auth_url)
  drv$wait_for_js(
    "
    (function () {
      var text = document.body ? (document.body.innerText || '') : '';
      return /Invalid Request|expired|Request Object expired/i.test(text);
    })();
  ",
    timeout = 20000
  )

  expired_text <- .read_request_uri_page_text(drv)
  testthat::expect_match(
    expired_text,
    "Invalid Request|expired|Request Object expired",
    ignore.case = TRUE
  )

  .navigate_browser_to_url(drv, app_url)
  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#ready_state');
      return !!(el && el.innerText.indexOf('browser_ready: TRUE') !== -1);
    })();
  ",
    timeout = 15000
  )

  browser_state <- .read_request_uri_browser_state(drv)
  testthat::expect_match(
    browser_state$auth_state %||% "",
    "authenticated: FALSE",
    fixed = TRUE
  )
  testthat::expect_match(
    browser_state$auth_state %||% "",
    "has_token: FALSE",
    fixed = TRUE
  )
  testthat::expect_match(
    browser_state$auth_state %||% "",
    "error_description: <none>",
    fixed = TRUE
  )
  testthat::expect_identical(
    trimws(browser_state$state_store_count %||% ""),
    "1"
  )
})

testthat::test_that("Shiny module E2E encrypted request_uri flow succeeds with public base override", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT", "8100"))
  withr::local_envvar(c(SHINYOAUTH_APP_PORT = as.character(app_port)))

  if (keycloak_browser_port_in_use(app_port)) {
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
    encrypted_request_object = TRUE,
    prepare_only = TRUE
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

  drv$run_js("document.querySelector('#prepare_login_btn').click();")

  state <- .wait_for_request_uri_auth_url(drv)
  capture_state <- .wait_for_request_uri_capture(
    drv,
    require_request_object = TRUE
  )

  request_uri_url <- trimws(capture_state$request_uri_url %||% "")

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

  .navigate_browser_to_url(drv, state$auth_url)

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 10000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
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

  auth_state <- keycloak_get_auth_state_robust(drv)
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

  user_info <- drv$get_js(
    "(function(){var el=document.querySelector('#user_info');return el?el.innerText:'';})()"
  ) |>
    jsonlite::fromJSON()

  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")
})

testthat::test_that("Shiny module E2E request_uri callback with tampered cookie is rejected", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_REQUEST_URI_PORT_CSRF",
    "8100"
  ))

  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping request_uri browser-token CSRF E2E"
    ))
  }

  public_base_url <- .request_uri_public_base_url(app_port)
  .allow_request_uri_public_host(public_base_url)
  public_base_url <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url,
    arg = "request_uri_base_url"
  )
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  app_process <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = app_port,
    public_base_url = public_base_url,
    app_url = app_url,
    prepare_only = TRUE
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-e2e-request-uri-csrf",
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
  payload <- .wait_for_request_uri_auth_url(drv)
  payload <- c(payload, .read_request_uri_csrf_payload(drv))

  testthat::expect_true(nzchar(payload[["cookie_name"]] %||% ""))
  testthat::expect_true(nzchar(payload[["cookie_value"]] %||% ""))
  testthat::expect_true(nzchar(payload[["auth_url"]] %||% ""))

  attacker_cookie <- paste0(
    sample(c(0:9, letters[1:6]), 128, replace = TRUE),
    collapse = ""
  )
  testthat::expect_false(identical(attacker_cookie, payload[["cookie_value"]]))

  tampered <- .tamper_browser_token_cookie(
    drv,
    cookie_name = payload[["cookie_name"]],
    cookie_value = attacker_cookie
  )
  testthat::expect_identical(tampered$current_value, attacker_cookie)

  .navigate_browser_to_url(drv, payload[["auth_url"]])

  login_state <- keycloak_wait_for_login_or_auth_result(drv, timeout = 20000)
  if (identical(login_state, "login")) {
    keycloak_submit_browser_login(drv)
  }

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_state');
      if (!el) return false;
      var text = el.innerText || '';
      return text.indexOf('authenticated: TRUE') !== -1 ||
        text.indexOf('error_description: <none>') === -1;
    })();
  ",
    timeout = 20000
  )

  auth_state <- keycloak_get_auth_state_robust(drv)
  testthat::expect_match(auth_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "has_token: FALSE", fixed = TRUE)
  testthat::expect_match(auth_state, "error: invalid_state", fixed = TRUE)
  testthat::expect_match(
    auth_state,
    "browser.token|browser token|invalid browser token|mismatch",
    perl = TRUE,
    ignore.case = TRUE
  )
})

testthat::test_that("Shiny module E2E request_uri swapped callbacks are rejected without consuming the rightful callbacks", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  port_a <- as.integer(Sys.getenv("SHINYOAUTH_E2E_REQUEST_URI_SWAP_A", "8100"))
  port_b <- as.integer(Sys.getenv("SHINYOAUTH_E2E_REQUEST_URI_SWAP_B", "3000"))
  host_a <- "127.0.0.1"
  host_b <- "127.0.0.1"
  module_id_a <- "auth_a"
  module_id_b <- "auth_b"

  testthat::skip_if(
    identical(port_a, port_b),
    "request_uri callback-swap E2E requires two distinct app ports"
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
      " already in use; skipping request_uri callback-swap E2E"
    )
  )

  public_base_url_a <- .request_uri_public_base_url(port_a)
  public_base_url_b <- .request_uri_public_base_url(port_b)
  .allow_request_uri_public_host(public_base_url_a)
  .allow_request_uri_public_host(public_base_url_b)
  public_base_url_a <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url_a,
    arg = "request_uri_base_url"
  )
  public_base_url_b <- shinyOAuth:::normalize_request_uri_base_url(
    public_base_url_b,
    arg = "request_uri_base_url"
  )

  app_url_a <- sprintf("http://%s:%d", host_a, port_a)
  app_url_b <- sprintf("http://%s:%d", host_b, port_b)

  fixture_b <- .create_request_uri_client_fixture(public_base_url_b)
  on.exit(
    keycloak_delete_client(
      fixture_b$admin_token,
      id = fixture_b$fixture$id
    ),
    add = TRUE
  )

  app_process_a <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = port_a,
    public_base_url = public_base_url_a,
    app_url = app_url_a,
    prepare_only = TRUE,
    module_id = module_id_a
  )
  on.exit(try(app_process_a$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process_a, port_a)

  app_process_b <- .start_request_uri_app(
    repo_root = .repo_root(),
    app_port = port_b,
    public_base_url = public_base_url_b,
    app_url = app_url_b,
    prepare_only = TRUE,
    client_id = fixture_b$fixture$client_id,
    module_id = module_id_b
  )
  on.exit(try(app_process_b$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_request_uri_app(app_process_b, port_b)

  drv_a <- shinytest2::AppDriver$new(
    app_url_a,
    name = sprintf("keycloak-request-uri-swap-a-%d", port_a),
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv_a$stop(), silent = TRUE), add = TRUE)

  drv_b <- shinytest2::AppDriver$new(
    app_url_b,
    name = sprintf("keycloak-request-uri-swap-b-%d", port_b),
    load_timeout = 15000,
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

  drv_a$run_js("document.querySelector('#prepare_login_btn').click();")
  drv_b$run_js("document.querySelector('#prepare_login_btn').click();")

  state_a <- .wait_for_request_uri_auth_url(drv_a)
  state_b <- .wait_for_request_uri_auth_url(drv_b)

  login_a <- perform_login_form_as(
    state_a$auth_url,
    username = "alice",
    password = "alice",
    redirect_uri = app_url_a
  )
  login_b <- perform_login_form_as(
    state_b$auth_url,
    username = "bob",
    password = "bob",
    redirect_uri = app_url_b
  )

  swapped_for_a <- .replace_callback_base_url(login_b$callback_url, app_url_a)
  legit_for_a <- .replace_callback_base_url(login_a$callback_url, app_url_a)
  legit_for_b <- .replace_callback_base_url(login_b$callback_url, app_url_b)

  .navigate_browser_to_url(drv_a, swapped_for_a)
  attacked_state <- keycloak_get_auth_state_robust(drv_a)
  testthat::expect_match(attacked_state, "authenticated: FALSE", fixed = TRUE)
  testthat::expect_match(
    attacked_state,
    "invalid_state|state",
    ignore.case = TRUE
  )

  .navigate_browser_to_url(drv_b, legit_for_b)
  auth_state_b <- .wait_for_request_uri_auth_state_transition(
    drv_b,
    previous_state = state_b$auth_state,
    timeout = 20000
  )
  user_b <- .read_request_uri_user_info(drv_b)
  testthat::expect_match(auth_state_b, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_identical(user_b$preferred_username, "bob")

  .navigate_browser_to_url(drv_a, legit_for_a)
  recovered_state_a <- .wait_for_request_uri_auth_state_transition(
    drv_a,
    previous_state = attacked_state,
    timeout = 20000
  )
  user_a <- .read_request_uri_user_info(drv_a)
  testthat::expect_match(recovered_state_a, "authenticated: TRUE", fixed = TRUE)
  testthat::expect_identical(user_a$preferred_username, "alice")
})
