## Browser E2E: callback URL/title cleanup after real Keycloak login

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

browser_cleanup_port_in_use <- function(port) {
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

submit_keycloak_login_for_cleanup <- function(drv) {
  drv$wait_for_js(
    "
    (function () {
      var authState = document.querySelector('#auth_state');
      var login = document.querySelector('#kc-login');
      var username = document.querySelector('#username');
      var password = document.querySelector('#password');
      var alreadyAuthenticated = !!(
        authState &&
        authState.innerText.indexOf('authenticated: TRUE') !== -1
      );
      return alreadyAuthenticated || !!(login && username && password);
    })();
  ",
    timeout = 20000
  )

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
      document.querySelector('#username').value = 'alice';
      document.querySelector('#password').value = 'alice';
      document.querySelector('#kc-login').click();
      return 'submitted';
    })();
  "
  )
}

testthat::test_that("browser callback cleanup removes OAuth parameters from URL and title", {
  maybe_skip_keycloak()
  testthat::skip_if_not_installed("shinytest2")
  testthat::skip_if_not_installed("chromote")

  app_port <- as.integer(Sys.getenv("SHINYOAUTH_E2E_PORT_CLEANUP", "8100"))
  if (browser_cleanup_port_in_use(app_port)) {
    testthat::skip(paste0(
      "Port ",
      app_port,
      " is already in use; skipping callback cleanup E2E"
    ))
  }

  provider <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  client <- shinyOAuth::oauth_client(
    provider = provider,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = sprintf("http://127.0.0.1:%d", app_port),
    scopes = c("openid", "profile", "email")
  )

  ui <- shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::titlePanel("Callback cleanup E2E"),
    shiny::verbatimTextOutput("auth_state")
  )
  server <- function(input, output, session) {
    auth <- shinyOAuth::oauth_module_server("auth", client)
    output$auth_state <- shiny::renderText({
      paste(
        "authenticated:",
        isTRUE(auth$authenticated),
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
  }

  drv <- shinytest2::AppDriver$new(
    shiny::shinyApp(ui, server),
    name = "keycloak-callback-cleanup",
    load_timeout = 15000,
    shiny_args = list(
      port = app_port,
      host = "127.0.0.1",
      test.mode = TRUE
    ),
    wait = FALSE
  )
  on.exit(try(drv$stop(), silent = TRUE), add = TRUE)

  submit_keycloak_login_for_cleanup(drv)

  drv$wait_for_js(
    "
    (function () {
      var el = document.querySelector('#auth_state');
      return !!(el && el.innerText.indexOf('authenticated: TRUE') !== -1);
    })();
  ",
    timeout = 20000
  )

  drv$wait_for_js(
    "
    (function () {
      var forbidden = [
        'code=', 'state=', 'iss=', 'error=',
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
      title: document.title || ''
    });
  "
  ))
  forbidden <- c(
    "code=",
    "state=",
    "iss=",
    "error=",
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
})
