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

make_test_app <- function(samesite = "Strict", id = "auth") {
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
      browser_cookie_samesite = samesite
    )

    # Wire buttons to the module's helpers
    shiny::observeEvent(input$set, { mod$set_browser_token() })
    shiny::observeEvent(input$clear, { mod$clear_browser_token() })

    # Special: directly invoke the client message with maxAgeMs = 0 to
    # verify zero TTL is honored by the browser helper (nullish coalescing fix)
    shiny::observeEvent(input$set_zero, {
      # Build the instance suffix similar to the module's logic
      ns_prefix <- tryCatch(session$ns(""), error = function(...) id)
      instance <- sub("-$", "", ns_prefix)
      instance <- gsub("[^A-Za-z0-9_\\-]", "-", instance)
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

# Basic cookie set/clear lifecycle

testthat::test_that("browser token cookie is set, cleared, and re-set with new value", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = make_test_app(samesite = "Strict", id = "auth"),
    name = "cookie-basic",
    load_timeout = 10000
  )
  on.exit(app$stop(), add = TRUE)

  # The cookie name includes the module instance suffix derived from id "auth"
  cookie_name <- "shinyOAuth_sid-auth"

  # Wait until the JS dependency is loaded and the module had a chance to set the cookie
  app$wait_for_js(cookie_value_js(cookie_name), timeout = 8000)

  v1 <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_type(v1, "character")
  testthat::expect_true(nchar(v1) == 128)
  testthat::expect_true(grepl("^[a-f0-9]{128}$", v1))

  # Clear the cookie via UI and wait until it disappears
  app$click("clear")
  app$wait_for_js(sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)), timeout = 8000)
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

# Error path: SameSite=None requires HTTPS

testthat::test_that("SameSite=None does not set cookie on non-HTTPS origins", {
  local_skip_env()

  app <- shinytest2::AppDriver$new(
    app = make_test_app(samesite = "None", id = "authnone"),
    name = "cookie-samesite-none",
    load_timeout = 10000
  )
  on.exit(app$stop(), add = TRUE)

  # The cookie should not be created under HTTP when SameSite=None
  cookie_name <- "shinyOAuth_sid-authnone"
  # Wait a bit for the attempted set + error path to run
  app$wait_for_idle(timeout = 8000)
  # Poll briefly to ensure it never appears
  deadline <- Sys.time() + 6
  ever_set <- FALSE
  repeat {
    val <- app$get_js(cookie_value_js(cookie_name))
    if (!is.null(val)) { ever_set <- TRUE; break }
    if (Sys.time() > deadline) break
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
  on.exit(app$stop(), add = TRUE)

  cookie_name <- "shinyOAuth_sid-authzero"

  # Ensure a clean start: clear any existing cookie
  app$click("clear")
  app$wait_for_js(sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)), timeout = 8000)

  # Click the special button that sets cookie with maxAgeMs=0
  app$click("set_zero")

  # It should become (or remain) absent very quickly
  app$wait_for_js(sprintf("(function(){return %s===null;})()", cookie_value_js(cookie_name)), timeout = 8000)
  v <- app$get_js(cookie_value_js(cookie_name))
  testthat::expect_true(is.null(v))
})
