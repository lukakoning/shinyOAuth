# Public wrapper fixtures for the same browser attacks under both lifecycles.
keycloak_wrapper_attack_app <- function(client, retained) {
  origin <- sub("/callback$", "", client@redirect_uri)
  manager <- if (retained) {
    shinyOAuth::oauth_connections(
      list(account = client),
      origin,
      retention = "browser",
      owner = shinyOAuth::oauth_browser_owner(allow_http_loopback = TRUE),
      store = shinyOAuth::oauth_connection_store_memory(),
      keys = list(
        credentials = openssl::rand_bytes(32),
        owner = openssl::rand_bytes(32)
      )
    )
  } else {
    NULL
  }
  base <- shiny::fluidPage(
    shiny::actionButton("connect", "Connect"),
    shiny::verbatimTextOutput("snapshot"),
    shiny::tags[["script"]]("window.appCallbackQuery = location.search;")
  )
  ui <- if (retained) {
    shinyOAuth::oauth_connections_ui(base, "health", manager)
  } else {
    shinyOAuth::oauth_ui(base, "auth", client)
  }
  server <- function(input, output, session) {
    if (retained) {
      auth <- shinyOAuth::oauth_connections_server("health", manager)
      shiny::observeEvent(input[["connect"]], auth[["connect"]]("account"))
      snapshot <- shiny::reactive({
        rows <- auth[["connections"]]()
        identity <- if (length(rows)) {
          auth[["connection"]](rows[[1]][["connection_id"]])[["identity"]](
            claims = "sub",
            userinfo = c("sub", "preferred_username")
          )
        } else {
          list()
        }
        list(
          ready = TRUE,
          count = length(rows),
          errors = auth[["errors"]](),
          identity = identity
        )
      })
    } else {
      auth <- shinyOAuth::oauth_module_server(
        "auth",
        client,
        auto_redirect = FALSE
      )
      shiny::observeEvent(input[["connect"]], auth[["request_login"]]())
      snapshot <- shiny::reactive({
        token <- auth[["token"]]
        identity <- if (!is.null(token)) {
          list(
            id_token_claims = token@id_token_claims["sub"],
            userinfo = token@userinfo[c("sub", "preferred_username")]
          )
        } else {
          list()
        }
        list(
          ready = isTRUE(auth[["has_browser_token"]]()),
          count = as.integer(isTRUE(auth[["authenticated"]])),
          errors = if (is.null(auth[["error"]])) {
            list()
          } else {
            list(auth[["error"]])
          },
          identity = identity
        )
      })
    }
    output[["snapshot"]] <- shiny::renderText(jsonlite::toJSON(
      snapshot(),
      auto_unbox = TRUE,
      null = "null"
    ))
  }
  shiny::runApp(
    shiny::shinyApp(ui, server, uiPattern = ".*"),
    host = "127.0.0.1",
    port = as.integer(httr2::url_parse(origin)[["port"]]),
    launch.browser = FALSE,
    quiet = TRUE
  )
}

keycloak_wrapper_attack_setup <- function(retained, .env = parent.frame()) {
  origin <- "http://127.0.0.1:8100"
  if (keycloak_browser_port_in_use(8100L)) {
    stop("Wrapper attack fixture port 8100 is occupied")
  }
  provider <- shinyOAuth::oauth_provider_keycloak(
    "http://localhost:8080",
    "shinyoauth"
  )
  provider@par_url <- NA_character_
  client <- make_public_client(
    provider,
    redirect_uri = paste0(origin, "/callback"),
    scopes = c("openid", "profile", "email")
  )
  client@resource_bases <- c(userinfo = provider@userinfo_url)
  script <- normalizePath(testthat::test_path("helper-wrapper-browser.R"))
  process <- callr::r_bg(
    function(script, client, retained) {
      Sys.setenv(CURL_SSL_BACKEND = "openssl")
      options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)
      source(script)
      keycloak_wrapper_attack_app(client, retained)
    },
    args = list(script, client, retained),
    libpath = .libPaths(),
    supervise = TRUE,
    stdout = "|",
    stderr = "|"
  )
  withr::defer(process[["kill"]](), envir = .env)
  deadline <- Sys.time() + 30
  repeat {
    ready <- tryCatch(
      curl::curl_fetch_memory(origin)[["status_code"]] == 200L,
      error = function(...) FALSE
    )
    if (ready) {
      break
    }
    if (!process[["is_alive"]]() || Sys.time() > deadline) {
      stop(
        "Wrapper fixture failed: ",
        paste(process[["read_error_lines"]](), collapse = "\n")
      )
    }
    Sys.sleep(0.1)
  }
  chrome <- chromote::Chromote[["new"]]()
  withr::defer(chrome[["close"]](), envir = .env)
  new_browser <- function() {
    context <- chrome[["Target"]][["createBrowserContext"]]()[[
      "browserContextId"
    ]]
    target <- chrome[["Target"]][["createTarget"]](
      "about:blank",
      browserContextId = context
    )[["targetId"]]
    browser <- chromote::ChromoteSession[["new"]](
      parent = chrome,
      targetId = target
    )
    withr::defer(browser[["close"]](), envir = .env)
    browser[["go_to"]](origin)
    keycloak_wrapper_wait(browser, function(x) isTRUE(x[["ready"]]))
    browser
  }
  list(origin = origin, client = client, new_browser = new_browser)
}

keycloak_wrapper_value <- function(browser, script) {
  browser[["Runtime"]][["evaluate"]](script, returnByValue = TRUE)[["result"]][[
    "value"
  ]]
}

keycloak_wrapper_wait <- function(browser, predicate, timeout = 25) {
  deadline <- Sys.time() + timeout
  repeat {
    snapshot <- tryCatch(
      keycloak_wrapper_value(
        browser,
        "(() => { try { return JSON.parse(document.querySelector('#snapshot').textContent); } catch (_) { return {}; } })()"
      ),
      error = function(...) list()
    )
    if (isTRUE(predicate(snapshot))) {
      return(snapshot)
    }
    if (Sys.time() > deadline) {
      stop(
        "Wrapper browser assertion timed out: ",
        jsonlite::toJSON(snapshot, auto_unbox = TRUE)
      )
    }
    Sys.sleep(0.1)
  }
}

keycloak_wrapper_start_login <- function(browser) {
  keycloak_wrapper_value(browser, "document.querySelector('#connect').click()")
  deadline <- Sys.time() + 25
  repeat {
    url <- tryCatch(
      keycloak_wrapper_value(browser, "location.href"),
      error = function(...) ""
    )
    if (is.character(url) && startsWith(url, "http://localhost:8080/")) {
      return(url)
    }
    if (Sys.time() > deadline) {
      stop("Wrapper did not navigate to Keycloak")
    }
    Sys.sleep(0.1)
  }
}
