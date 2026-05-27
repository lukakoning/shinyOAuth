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

.form_post_jarm_jwks_public_base_url <- function(port) {
  override <- Sys.getenv("SHINYOAUTH_E2E_JARM_JWKS_BASE_URL", "")
  if (nzchar(override)) {
    return(override)
  }

  sprintf("http://host.docker.internal:%d", port)
}

.start_form_post_jarm_jwks_server <- function(
  key,
  port,
  public_base_url,
  .local_envir = parent.frame()
) {
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("webfakes")

  jwk <- jsonlite::fromJSON(jose::write_jwk(key$pubkey), simplifyVector = FALSE)
  jwk$kid <- "form-post-jarm-enc-1"
  jwk$use <- "enc"
  jwk$alg <- "RSA-OAEP"
  jwks_json <- jsonlite::toJSON(
    list(keys = list(jwk)),
    auto_unbox = TRUE,
    null = "null"
  )

  app <- webfakes::new_app()
  app$get("/jwks", function(req, res) {
    res$set_type("application/json")
    res$send(jwks_json)
  })

  process <- webfakes::new_app_process(
    app = app,
    port = as.integer(port),
    opts = webfakes::server_opts(interfaces = "0.0.0.0"),
    start = TRUE,
    auto_start = FALSE
  )
  stdout <- process$.access_log %||% NA_character_
  stderr <- process$.error_log %||% NA_character_

  local_jwks_url <- paste0("http://127.0.0.1:", as.integer(port), "/jwks")
  deadline <- Sys.time() + 5
  repeat {
    if (!identical(process$get_state(), "live")) {
      stop(
        paste(
          "form_post JARM JWKS server exited before it was reachable.",
          paste(readLines(stderr, warn = FALSE), collapse = "\n"),
          sep = "\n"
        ),
        call. = FALSE
      )
    }

    ready <- tryCatch(
      {
        resp <- httr2::request(local_jwks_url) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_perform()
        identical(httr2::resp_status(resp), 200L)
      },
      error = function(...) FALSE
    )
    if (isTRUE(ready)) {
      break
    }
    if (Sys.time() > deadline) {
      stop(
        paste(
          "form_post JARM JWKS server did not start in time",
          paste(readLines(stderr, warn = FALSE), collapse = "\n"),
          sep = "\n"
        ),
        call. = FALSE
      )
    }
    Sys.sleep(0.1)
  }

  list(
    process = process,
    stop = function() process$stop(),
    stdout = stdout,
    stderr = stderr,
    jwks_url = paste0(sub("/+$", "", public_base_url), "/jwks")
  )
}

.start_form_post_app <- function(
  repo_root,
  app_port,
  app_url,
  redirect_path = "",
  use_par = FALSE,
  title = "Form Post E2E",
  client_id = "shiny-public",
  response_mode = "form_post",
  authorization_signed_response_alg = NULL,
  authorization_encrypted_response_alg = NULL,
  authorization_encrypted_response_enc = NULL,
  authorization_response_decryption_private_key = NULL
) {
  stdout <- tempfile("form-post-app-stdout-", fileext = ".log")
  stderr <- tempfile("form-post-app-stderr-", fileext = ".log")

  process <- callr::r_bg(
    func = function(
      repo_root,
      app_port,
      app_url,
      redirect_path,
      use_par,
      title,
      client_id,
      response_mode,
      authorization_signed_response_alg,
      authorization_encrypted_response_alg,
      authorization_encrypted_response_enc,
      authorization_response_decryption_private_key
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
            "Could not load shinyOAuth for the form_post background app.",
            "Install pkgload or devtools, or install shinyOAuth into this library.",
            sep = " "
          ),
          call. = FALSE
        )
      }
      source("integration/keycloak/helper-keycloak.R")

      if (
        !is.character(redirect_path) ||
          length(redirect_path) != 1L ||
          is.na(redirect_path)
      ) {
        stop("redirect_path must be a single string", call. = FALSE)
      }
      if (nzchar(redirect_path) && !startsWith(redirect_path, "/")) {
        stop("redirect_path must be empty or start with '/'", call. = FALSE)
      }
      if (
        !is.character(client_id) ||
          length(client_id) != 1L ||
          is.na(client_id) ||
          !nzchar(client_id)
      ) {
        stop("client_id must be a single non-empty string", call. = FALSE)
      }
      if (
        !is.character(response_mode) ||
          length(response_mode) != 1L ||
          is.na(response_mode) ||
          !nzchar(response_mode)
      ) {
        stop("response_mode must be a single non-empty string", call. = FALSE)
      }
      if (
        !is.null(authorization_signed_response_alg) &&
          (!is.character(authorization_signed_response_alg) ||
            length(authorization_signed_response_alg) != 1L ||
            is.na(authorization_signed_response_alg) ||
            !nzchar(authorization_signed_response_alg))
      ) {
        stop(
          paste(
            "authorization_signed_response_alg must be NULL or a",
            "single non-empty string"
          ),
          call. = FALSE
        )
      }
      if (
        !is.null(authorization_encrypted_response_alg) &&
          (!is.character(authorization_encrypted_response_alg) ||
            length(authorization_encrypted_response_alg) != 1L ||
            is.na(authorization_encrypted_response_alg) ||
            !nzchar(authorization_encrypted_response_alg))
      ) {
        stop(
          paste(
            "authorization_encrypted_response_alg must be NULL or a",
            "single non-empty string"
          ),
          call. = FALSE
        )
      }
      if (
        !is.null(authorization_encrypted_response_enc) &&
          (!is.character(authorization_encrypted_response_enc) ||
            length(authorization_encrypted_response_enc) != 1L ||
            is.na(authorization_encrypted_response_enc) ||
            !nzchar(authorization_encrypted_response_enc))
      ) {
        stop(
          paste(
            "authorization_encrypted_response_enc must be NULL or a",
            "single non-empty string"
          ),
          call. = FALSE
        )
      }
      if (
        !is.null(authorization_response_decryption_private_key) &&
          (!is.character(authorization_response_decryption_private_key) ||
            length(authorization_response_decryption_private_key) != 1L ||
            is.na(authorization_response_decryption_private_key) ||
            !nzchar(authorization_response_decryption_private_key))
      ) {
        stop(
          paste(
            "authorization_response_decryption_private_key must be NULL or a",
            "single non-empty PEM string"
          ),
          call. = FALSE
        )
      }

      provider <- make_provider(use_par = use_par)
      redirect_uri <- paste0(app_url, redirect_path)

      client_args <- list(
        provider = provider,
        client_id = client_id,
        client_secret = "",
        redirect_uri = redirect_uri,
        scopes = c("openid", "profile", "email"),
        response_mode = response_mode
      )
      if (keycloak_nonempty_string(authorization_signed_response_alg)) {
        client_args$authorization_signed_response_alg <-
          authorization_signed_response_alg
      }
      if (keycloak_nonempty_string(authorization_encrypted_response_alg)) {
        client_args$authorization_encrypted_response_alg <-
          authorization_encrypted_response_alg
      }
      if (keycloak_nonempty_string(authorization_encrypted_response_enc)) {
        client_args$authorization_encrypted_response_enc <-
          authorization_encrypted_response_enc
      }
      if (
        keycloak_nonempty_string(
          authorization_response_decryption_private_key
        )
      ) {
        client_args$authorization_response_decryption_private_key <-
          authorization_response_decryption_private_key
      }

      client <- do.call(shinyOAuth::oauth_client, client_args)

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
      redirect_path = redirect_path,
      use_par = use_par,
      title = title,
      client_id = client_id,
      response_mode = response_mode,
      authorization_signed_response_alg = authorization_signed_response_alg,
      authorization_encrypted_response_alg = authorization_encrypted_response_alg,
      authorization_encrypted_response_enc = authorization_encrypted_response_enc,
      authorization_response_decryption_private_key = authorization_response_decryption_private_key
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

.expect_successful_form_post_browser_flow <- function(
  drv,
  validate_auth_url,
  final_href_pattern = NULL
) {
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
  validate_auth_url(auth_url)

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
        'code=', 'state=', 'iss=', 'error=', 'response=',
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
    "response=",
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

  if (!is.null(final_href_pattern)) {
    testthat::expect_match(observed$href, final_href_pattern)
  }

  user_info <- jsonlite::fromJSON(observed$user_info)
  testthat::expect_identical(user_info$preferred_username, "alice")
  testthat::expect_identical(user_info$name, "Alice Test")
  testthat::expect_identical(user_info$email, "alice@example.com")

  invisible(list(
    auth_url = auth_url,
    auth_state = auth_state,
    observed = observed,
    user_info = user_info
  ))
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

  .expect_successful_form_post_browser_flow(
    drv,
    validate_auth_url = function(auth_url) {
      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "form_post"
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "redirect_uri", decode = TRUE),
        app_url
      )
    }
  )
})

testthat::test_that("browser form_post.jwt login authenticates through oauth_form_post_ui", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM",
    "8120"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post.jwt E2E"
    ))
  }

  repo_root <- .repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)

  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id("shiny-form-post-jarm"),
      public_client = TRUE,
      redirect_uris = list(app_url, paste0(app_url, "/*")),
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "authorization.signed.response.alg" = "RS256"
      )
    )
  )
  on.exit(
    keycloak_delete_client(admin_token, id = fixture$id),
    add = TRUE
  )

  provider <- make_provider()
  testthat::expect_true(
    "form_post.jwt" %in% (provider@response_modes_supported %||% character())
  )
  testthat::expect_true(
    "RS256" %in%
      (provider@authorization_signing_alg_values_supported %||% character())
  )

  app_process <- .start_form_post_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    title = "Form Post JWT E2E",
    client_id = fixture$client_id,
    response_mode = "form_post.jwt",
    authorization_signed_response_alg = "RS256"
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-form-post-jarm-e2e",
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .expect_successful_form_post_browser_flow(
    drv,
    validate_auth_url = function(auth_url) {
      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "form_post.jwt"
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "client_id", decode = TRUE),
        fixture$client_id
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "redirect_uri", decode = TRUE),
        app_url
      )
    }
  )
})

testthat::test_that("browser encrypted form_post.jwt login authenticates through oauth_form_post_ui", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")
  testthat::skip_if_not_installed("webfakes")

  private_key <- get_pjwt_key()
  testthat::skip_if(
    is.null(private_key),
    "private_key_jwt test key not available"
  )

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_JARM_ENC",
    "8126"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping encrypted form_post.jwt E2E"
    ))
  }

  jwks_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_FORM_POST_JARM_JWKS_PORT",
    "8127"
  ))
  if (keycloak_browser_port_in_use(jwks_port)) {
    testthat::skip(paste0(
      "Port ",
      jwks_port,
      " is already in use; skipping encrypted form_post.jwt JWKS server"
    ))
  }

  repo_root <- .repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  public_base_url <- .form_post_jarm_jwks_public_base_url(jwks_port)
  jwks_server <- .start_form_post_jarm_jwks_server(
    key = private_key,
    port = jwks_port,
    public_base_url = public_base_url
  )
  on.exit(try(jwks_server$stop(), silent = TRUE), add = TRUE)

  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_client(
    token = admin_token,
    body = keycloak_oidc_client_body(
      client_id = keycloak_temp_client_id("shiny-form-post-jarm-enc"),
      public_client = TRUE,
      redirect_uris = list(app_url, paste0(app_url, "/*")),
      attributes = list(
        "pkce.code.challenge.method" = "S256",
        "use.jwks.url" = "true",
        "jwks.url" = jwks_server$jwks_url,
        "authorization.signed.response.alg" = "RS256",
        "authorization.encrypted.response.alg" = "RSA-OAEP",
        "authorization.encrypted.response.enc" = "A256CBC-HS512"
      )
    )
  )
  on.exit(
    keycloak_delete_client(admin_token, id = fixture$id),
    add = TRUE
  )

  provider <- make_provider()
  testthat::expect_true(
    "form_post.jwt" %in% (provider@response_modes_supported %||% character())
  )
  testthat::expect_true(
    "RS256" %in%
      (provider@authorization_signing_alg_values_supported %||% character())
  )
  testthat::expect_true(
    "RSA-OAEP" %in%
      (provider@authorization_encryption_alg_values_supported %||% character())
  )
  testthat::expect_true(
    "A256CBC-HS512" %in%
      (provider@authorization_encryption_enc_values_supported %||% character())
  )

  decryption_key_pem <- openssl::write_pem(private_key)
  app_process <- .start_form_post_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    title = "Encrypted Form Post JWT E2E",
    client_id = fixture$client_id,
    response_mode = "form_post.jwt",
    authorization_signed_response_alg = "RS256",
    authorization_encrypted_response_alg = "RSA-OAEP",
    authorization_encrypted_response_enc = "A256CBC-HS512",
    authorization_response_decryption_private_key = decryption_key_pem
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-form-post-jarm-enc-e2e",
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .expect_successful_form_post_browser_flow(
    drv,
    validate_auth_url = function(auth_url) {
      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "form_post.jwt"
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "client_id", decode = TRUE),
        fixture$client_id
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "redirect_uri", decode = TRUE),
        app_url
      )
    }
  )
})

testthat::test_that("browser form_post login authenticates on a callback subroute", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
  testthat::skip_if_not_installed("callr")

  app_port <- as.integer(Sys.getenv(
    "SHINYOAUTH_E2E_PORT_FORM_POST_CALLBACK",
    "8100"
  ))
  if (keycloak_browser_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping form_post callback subroute E2E"
    ))
  }

  provider <- make_provider()
  testthat::expect_true(
    "form_post" %in% (provider@response_modes_supported %||% character())
  )
  repo_root <- .repo_root()
  app_url <- sprintf("http://127.0.0.1:%d", app_port)
  callback_path <- "/callback"
  redirect_uri <- paste0(app_url, callback_path)

  app_process <- .start_form_post_app(
    repo_root = repo_root,
    app_port = app_port,
    app_url = app_url,
    redirect_path = callback_path,
    title = "Form Post Callback Path E2E"
  )
  on.exit(try(app_process$process$kill(), silent = TRUE), add = TRUE)
  .wait_for_form_post_app(app_process, app_port)

  drv <- shinytest2::AppDriver$new(
    app_url,
    name = "keycloak-form-post-callback-e2e",
    load_timeout = 15000,
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  .expect_successful_form_post_browser_flow(
    drv,
    validate_auth_url = function(auth_url) {
      testthat::expect_identical(
        parse_query_param(auth_url, "response_mode", decode = TRUE),
        "form_post"
      )
      testthat::expect_identical(
        parse_query_param(auth_url, "redirect_uri", decode = TRUE),
        redirect_uri
      )
    },
    final_href_pattern = "/callback(?:$|[?#])"
  )
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

  .expect_successful_form_post_browser_flow(
    drv,
    validate_auth_url = function(auth_url) {
      testthat::expect_match(auth_url, "[?&]request_uri=")
      testthat::expect_match(auth_url, "[?&]client_id=shiny-public")
      testthat::expect_false(grepl("[?&]state=", auth_url))
      testthat::expect_false(grepl("[?&]redirect_uri=", auth_url))
      testthat::expect_false(grepl("[?&]response_mode=", auth_url))
    }
  )
})
