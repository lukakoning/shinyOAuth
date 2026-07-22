# Integration tests for browser cookie handling using chromote via shinytest2

# These tests require a headless Chrome session (chromote) and will be skipped
# when dependencies are missing or on CRAN. They validate that:
# - The module sets a browser token cookie on first load
# - The cookie can be cleared via the exposed helper
# - After clearing, re-setting generates a fresh random value
#
# Notes:
# - We avoid triggering any provider redirects by setting auto_redirect = FALSE
# - We use a minimal, inert OAuthProvider and OAuthClient; no network calls occur
# - document.cookie only exposes name=value; we validate presence and value shape

local_skip_env <- function() {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")
}

make_test_app <- function(samesite = "Strict", path = NULL, id = "auth") {
  stopifnot(samesite %in% c("Strict", "Lax", "None"))

  # Minimal inert provider/client: hosts must pass is_ok_host(), but no calls occur
  prov <- shinyOAuth::oauth_provider(
    name = "dummy",
    auth_url = "http://127.0.0.1:1/authorize",
    token_url = "http://127.0.0.1:1/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_
  )

  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "test-secret-32-bytes-minimum-padding",
    redirect_uri = "http://127.0.0.1:1/callback",
    scopes = character(),
    state_store = cachem::cache_mem(max_age = 60) # short TTL for test
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::tags$h3("Cookie test app"),
    shiny::actionButton("set", "Set cookie"),
    shiny::actionButton("clear", "Clear cookie"),
    shiny::actionButton("set_zero", "Set cookie (0 ms)")
  )

  server <- function(input, output, session) {
    mod <- shinyOAuth::oauth_module_server(
      id = id,
      client = cli,
      auto_redirect = FALSE,
      browser_cookie_samesite = samesite,
      browser_cookie_path = path
    )

    # Wire buttons to the module's helpers
    shiny::observeEvent(input$set, {
      mod$set_browser_token()
    })
    shiny::observeEvent(input$clear, {
      mod$clear_browser_token()
    })

    # Special: directly invoke the client message with maxAgeMs = 0 to
    # verify zero TTL is honored by the browser helper (nullish coalescing fix)
    shiny::observeEvent(input$set_zero, {
      # Build the instance suffix similar to the module's logic
      ns_prefix <- tryCatch(session$ns(""), error = function(...) id)
      instance <- sub("-$", "", ns_prefix)

      ns_hash <- substr(as.character(openssl::sha256(ns_prefix)), 1, 8)

      instance <- gsub("[^A-Za-z0-9_\\-]", "-", instance)
      instance <- paste0(instance, "-", ns_hash)

      session$sendCustomMessage(
        type = "shinyOAuth:setBrowserToken",
        message = list(
          instance = instance,
          maxAgeMs = 0,
          sameSite = samesite,
          path = NULL,
          # Use throwaway input ids; we don't need server reflection for this check
          inputId = session$ns("sid_zero"),
          errorInputId = session$ns("err_zero")
        )
      )
    })
  }

  shiny::shinyApp(ui, server)
}

cookie_value_js <- function(name) {
  sprintf(
    "(function(){var m=document.cookie.match('(?:^|; )'+%s+'=([^;]*)'); return m?decodeURIComponent(m[1]):null;})()",
    jsonlite::toJSON(name, auto_unbox = TRUE)
  )
}

browser_cookie_instance <- function(id) {
  ns_hash <- substr(as.character(openssl::sha256(paste0(id, "-"))), 1, 8)
  paste0(id, "-", ns_hash)
}

browser_cookie_name <- function(id, prefix = "shinyOAuth_sid") {
  paste0(prefix, "-", browser_cookie_instance(id))
}

get_browser_cookie <- function(app, name) {
  cookies <- app$get_chromote_session()$Network$getAllCookies()$cookies
  matches <- Filter(function(cookie) identical(cookie$name, name), cookies)
  if (length(matches) == 0) {
    return(NULL)
  }

  testthat::expect_length(matches, 1L)
  matches[[1]]
}

wait_for_browser_cookie <- function(app, name, timeout = 8) {
  deadline <- Sys.time() + timeout
  repeat {
    cookie <- get_browser_cookie(app, name)
    if (!is.null(cookie)) {
      return(cookie)
    }
    if (Sys.time() > deadline) {
      return(NULL)
    }
    app$wait_for_idle(200)
  }
}

capture_set_cookie_writes <- function(
  protocol = "https:",
  path = "/",
  same_site = "Strict",
  max_age_ms = 60000,
  instance = "securetest"
) {
  js_source <- paste(
    readLines(
      system.file("www", "shinyOAuth.js", package = "shinyOAuth"),
      warn = FALSE
    ),
    collapse = "\n"
  )
  payload <- list(
    instance = instance,
    maxAgeMs = max_age_ms,
    sameSite = same_site,
    path = path,
    inputId = "sid",
    errorInputId = "err"
  )

  browser <- chromote::ChromoteSession$new()
  on.exit(try(browser$close(), silent = TRUE), add = TRUE)
  browser$go_to("about:blank")

  expression <- paste0(
    "(function(source, payload, protocol) {",
    "  var writes = [];",
    "  var fakeDocument = { title: '', body: { textContent: '' } };",
    "  Object.defineProperty(fakeDocument, 'cookie', {",
    "    get: function() { return ''; },",
    "    set: function(value) { writes.push(String(value)); }",
    "  });",
    "  var fakeWindow = {",
    "    location: { protocol: protocol, pathname: '/' },",
    "    history: { replaceState: function() {} },",
    "    crypto: window.crypto,",
    "    console: window.console,",
    "    Shiny: {",
    "      handlers: {},",
    "      addCustomMessageHandler: function(name, fn) { this.handlers[name] = fn; },",
    "      setInputValue: function() {}",
    "    }",
    "  };",
    "  (function() {",
    "    var window = fakeWindow;",
    "    var document = fakeDocument;",
    "    var Shiny = fakeWindow.Shiny;",
    "    var console = fakeWindow.console;",
    "    eval(source);",
    "    fakeWindow.Shiny.handlers['shinyOAuth:setBrowserToken'](payload);",
    "  })();",
    "  return writes;",
    "})(",
    jsonlite::toJSON(js_source, auto_unbox = TRUE),
    ",",
    jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null"),
    ",",
    jsonlite::toJSON(protocol, auto_unbox = TRUE),
    ")"
  )

  browser$Runtime$evaluate(
    expression = expression,
    returnByValue = TRUE
  )$result[["value"]]
}

capture_clear_query_url <- function(
  href,
  clean_title = FALSE,
  drop_response = FALSE
) {
  js_source <- paste(
    readLines(
      system.file("www", "shinyOAuth.js", package = "shinyOAuth"),
      warn = FALSE
    ),
    collapse = "\n"
  )

  browser <- chromote::ChromoteSession$new()
  on.exit(try(browser$close(), silent = TRUE), add = TRUE)
  browser$go_to("about:blank")

  expression <- paste0(
    "(function(source, href, cleanTitle, dropResponse) {",
    "  var replaced = null;",
    "  var parsed = new URL(href);",
    "  var fakeDocument = { title: '', body: { textContent: '' } };",
    "  var fakeWindow = {",
    "    location: {",
    "      href: href,",
    "      host: parsed.host,",
    "      pathname: parsed.pathname,",
    "      hash: parsed.hash",
    "    },",
    "    history: { replaceState: function(_s, _t, url) { replaced = String(url); } },",
    "    console: window.console,",
    "    Shiny: {",
    "      handlers: {},",
    "      addCustomMessageHandler: function(name, fn) { this.handlers[name] = fn; },",
    "      setInputValue: function() {}",
    "    }",
    "  };",
    "  (function() {",
    "    var window = fakeWindow;",
    "    var document = fakeDocument;",
    "    var Shiny = fakeWindow.Shiny;",
    "    var console = fakeWindow.console;",
    "    eval(source);",
    paste(
      "    fakeWindow.Shiny.handlers['shinyOAuth:clearQueryAndFixTitle'](",
      "{ cleanTitle: cleanTitle, dropResponse: dropResponse }",
      ");"
    ),
    "  })();",
    "  return replaced;",
    "})(",
    jsonlite::toJSON(js_source, auto_unbox = TRUE),
    ",",
    jsonlite::toJSON(href, auto_unbox = TRUE),
    ",",
    jsonlite::toJSON(clean_title, auto_unbox = TRUE),
    ",",
    jsonlite::toJSON(drop_response, auto_unbox = TRUE),
    ")"
  )

  browser$Runtime$evaluate(
    expression = expression,
    returnByValue = TRUE
  )$result[["value"]]
}

# Basic cookie set/clear lifecycle

testthat::test_that("browser token cookie is set, cleared, and re-set with new value", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = make_test_app(samesite = "Strict", id = "auth"),
    name = "cookie-basic",
    load_timeout = 10000
  )
  on.exit(stop_test_app_driver(app), add = TRUE)

  cookie_name <- browser_cookie_name("auth")

  # Wait until the JS dependency is loaded and the module had a chance to set the cookie
  app$wait_for_js(cookie_value_js(cookie_name), timeout = 8000)

  v1 <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_type(v1, "character")
  testthat::expect_true(nchar(v1) == 128)
  testthat::expect_true(grepl("^[a-f0-9]{128}$", v1))

  cookie <- wait_for_browser_cookie(app, cookie_name)
  testthat::expect_false(is.null(cookie))
  testthat::expect_identical(cookie$path, "/")
  testthat::expect_identical(cookie$sameSite, "Strict")
  testthat::expect_false(cookie$secure)
  testthat::expect_false(cookie$session)
  testthat::expect_false(startsWith(cookie$name, "__Host-"))
  remaining_lifetime <- cookie$expires - as.numeric(Sys.time())
  testthat::expect_gte(remaining_lifetime, 30)
  testthat::expect_lte(remaining_lifetime, 120)

  # Clear the cookie via UI and wait until it disappears
  app$click("clear")
  app$wait_for_js(
    sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)),
    timeout = 8000
  )
  v_cleared <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_true(is.null(v_cleared))

  # Re-set the cookie and wait for it to appear with a fresh value
  app$click("set")
  app$wait_for_js(cookie_value_js(cookie_name), timeout = 8000)
  v2 <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_type(v2, "character")
  testthat::expect_true(nchar(v2) == 128)
  testthat::expect_true(grepl("^[a-f0-9]{128}$", v2))
  testthat::expect_false(identical(v1, v2))
})

testthat::test_that("browser token cookie honors custom path and SameSite metadata", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = shiny::shinyApp(
      ui = shiny::fluidPage(
        shinyOAuth::use_shinyOAuth(),
        shiny::actionButton("set", "Set cookie")
      ),
      server = function(input, output, session) {
        shiny::observeEvent(input$set, {
          session$sendCustomMessage(
            type = "shinyOAuth:setBrowserToken",
            message = list(
              instance = browser_cookie_instance("authpath"),
              maxAgeMs = 60000,
              sameSite = "Lax",
              path = "/foo",
              inputId = session$ns("sid"),
              errorInputId = session$ns("err")
            )
          )
        })
      }
    ),
    name = "cookie-path-metadata",
    load_timeout = 10000
  )
  on.exit(stop_test_app_driver(app), add = TRUE)

  cookie_name <- browser_cookie_name("authpath")

  app$click("set")
  cookie <- wait_for_browser_cookie(app, cookie_name)

  testthat::expect_false(is.null(cookie))
  testthat::expect_identical(cookie$path, "/foo")
  testthat::expect_identical(cookie$sameSite, "Lax")
  testthat::expect_false(cookie$secure)
  testthat::expect_false(startsWith(cookie$name, "__Host-"))
})

testthat::test_that("setBrowserToken writes __Host- cookie attributes for HTTPS root paths", {
  local_skip_env()

  writes <- capture_set_cookie_writes(
    protocol = "https:",
    path = "/",
    same_site = "Strict",
    max_age_ms = 60000,
    instance = "securetest"
  )

  testthat::expect_length(writes, 1L)
  testthat::expect_match(writes[[1]], "^__Host-shinyOAuth_sid-securetest=")
  testthat::expect_match(writes[[1]], "; Expires=")
  testthat::expect_match(writes[[1]], "; Max-Age=60;")
  testthat::expect_match(writes[[1]], "; Path=/; SameSite=Strict; Secure$")
})

testthat::test_that("browser cleanup preserves ordinary response params", {
  local_skip_env()

  testthat::expect_identical(
    capture_clear_query_url("https://example.com/cb?response=ok&foo=1"),
    "/cb?response=ok&foo=1"
  )
  testthat::expect_identical(
    capture_clear_query_url("https://example.com/cb#/route?response=ok&foo=1"),
    "/cb#/route?response=ok&foo=1"
  )
})

testthat::test_that("browser cleanup preserves compact response params unless flagged", {
  local_skip_env()

  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb?response=header.payload.signature&foo=1"
    ),
    "/cb?response=header.payload.signature&foo=1"
  )
  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb#/route?response=header.payload.signature&foo=1"
    ),
    "/cb#/route?response=header.payload.signature&foo=1"
  )
})

testthat::test_that("browser cleanup drops flagged response params", {
  local_skip_env()

  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb?response=header.payload.signature&foo=1",
      drop_response = TRUE
    ),
    "/cb?foo=1"
  )
  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb#/route?response=header.payload.signature&foo=1",
      drop_response = TRUE
    ),
    "/cb#/route?foo=1"
  )
  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb?response=not-a-compact-jwt&foo=1",
      drop_response = TRUE
    ),
    "/cb?foo=1"
  )
  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb#/route?response=not-a-compact-jwt&foo=1",
      drop_response = TRUE
    ),
    "/cb#/route?foo=1"
  )
})

testthat::test_that("browser fragment cleanup handles values containing equals", {
  local_skip_env()

  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb#/route?code=part=tail&keep=a=b"
    ),
    "/cb#/route?keep=a=b"
  )
  testthat::expect_identical(
    capture_clear_query_url(
      "https://example.com/cb#code=part=tail&keep=a=b"
    ),
    "/cb#keep=a=b"
  )
})

# Error path: SameSite=None requires HTTPS

testthat::test_that("SameSite=None does not set cookie on non-HTTPS origins", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = make_test_app(samesite = "None", id = "authnone"),
    name = "cookie-samesite-none",
    load_timeout = 10000
  )
  on.exit(stop_test_app_driver(app), add = TRUE)

  # The cookie should not be created under HTTP when SameSite=None
  cookie_name <- browser_cookie_name("authnone")
  # Wait a bit for the attempted set + error path to run
  app$wait_for_idle(timeout = 8000)
  # Poll briefly to ensure it never appears
  deadline <- Sys.time() + 6
  ever_set <- FALSE
  repeat {
    val <- app$get_js(cookie_value_js(cookie_name))
    if (!is.null(val)) {
      ever_set <- TRUE
      break
    }
    if (Sys.time() > deadline) {
      break
    }
    app$wait_for_idle(200)
  }
  testthat::expect_false(ever_set)
})

# Zero TTL should result in no persistent cookie (immediate expiry)

testthat::test_that("Zero TTL cookie is not persisted (maxAgeMs = 0)", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = make_test_app(samesite = "Strict", id = "authzero"),
    name = "cookie-zero-ttl",
    load_timeout = 10000
  )
  on.exit(stop_test_app_driver(app), add = TRUE)

  cookie_name <- browser_cookie_name("authzero")

  # Ensure a clean start: clear any existing cookie
  app$click("clear")
  app$wait_for_js(
    sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)),
    timeout = 8000
  )

  # Click the special button that sets cookie with maxAgeMs=0
  app$click("set_zero")

  # It should become (or remain) absent very quickly
  app$wait_for_js(
    sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)),
    timeout = 8000
  )
  v <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_true(is.null(v))
})
