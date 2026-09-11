retention_chrome_close <- function(chrome) {
  # Chromote 0.5.1 close() discards an asynchronous Browser.close promise.
  # Await our own request and process exit first, so a lost shutdown reply
  # cannot produce an unhandled promise error after the test has completed.
  process <- chrome$get_browser()$get_process()
  if (process$is_alive()) {
    tryCatch(chrome$Browser$close(timeout_ = 2), error = function(...) NULL)
    process$wait(timeout = 2000)
    if (process$is_alive()) {
      process$kill()
      process$wait(timeout = 2000)
    }
  }
  if (process$is_alive()) stop("Fixture Chrome did not stop")
  # The process is confirmed dead; websocket's close event can still be queued.
  tryCatch(chrome$close(wait = FALSE), error = function(...) NULL)
  invisible(NULL)
}

retention_browser_value <- function(browser, expression) {
  result <- browser$Runtime$evaluate(expression, returnByValue = TRUE)
  if (!is.null(result$exceptionDetails)) {
    return(NULL)
  }
  result$result$value
}

retention_browser_wait <- function(
  browser,
  predicate,
  description,
  timeout = 25
) {
  deadline <- Sys.time() + timeout
  repeat {
    result <- tryCatch(predicate(), error = function(...) NULL)
    if (!is.null(result) && !identical(result, FALSE)) {
      return(result)
    }
    if (Sys.time() >= deadline) {
      page <- retention_browser_value(
        browser,
        paste0(
          "({path:location.pathname, provider:document.querySelector('#provider')?.textContent,",
          "errors:(()=>{try{return JSON.parse(document.querySelector('#snapshot').textContent).errors}",
          "catch(_){return null}})()})"
        )
      )
      stop(
        "Browser timeout: ",
        description,
        "; ",
        jsonlite::toJSON(page, auto_unbox = TRUE, null = "null"),
        call. = FALSE
      )
    }
    Sys.sleep(0.1)
  }
}

retention_browser_snapshot <- function(browser) {
  retention_browser_value(
    browser,
    paste0(
      "(() => { const el = document.querySelector('#snapshot');",
      "try { return el ? JSON.parse(el.textContent) : null; } catch (_) { return null; } })()"
    )
  )
}

retention_browser_click <- function(browser, id) {
  retention_browser_value(
    browser,
    paste0(
      "document.getElementById(",
      jsonlite::toJSON(id, auto_unbox = TRUE),
      ").click()"
    )
  )
  invisible(NULL)
}

retention_browser_result <- function(browser, value) {
  retention_browser_wait(
    browser,
    function() {
      identical(
        retention_browser_value(
          browser,
          "document.querySelector('#result')?.textContent"
        ),
        value
      )
    },
    paste("result", value)
  )
}

retention_browser_setup <- function(
  async,
  response_mode = "query",
  provider_factory = retention_fixture_provider,
  app_script = "integration/connections/fixture-app.R",
  app_function = "retention_fixture_app",
  .env = parent.frame()
) {
  port <- httpuv::randomPort()
  origin <- paste0("http://127.0.0.1:", port)
  providers <- lapply(c("a", "b"), function(site) {
    provider <- provider_factory(
      site,
      paste0(origin, "/callback/", site)
    )
    withr::defer(provider$stop(), envir = .env)
    provider
  })
  names(providers) <- c("a", "b")
  # Different hosts force real cross-site navigation; both hosts remain loopback.
  bases <- lapply(providers, function(provider) {
    sub(
      "127.0.0.1",
      "localhost",
      sub("/$", "", provider$url()),
      fixed = TRUE
    )
  })
  app_file <- normalizePath(file.path(
    retention_root,
    app_script
  ))
  process <- callr::r_bg(
    function(app_file, origin, bases, async, response_mode, app_function) {
      Sys.setenv(CURL_SSL_BACKEND = "openssl")
      source(app_file, local = TRUE)
      get(app_function)(origin, bases, async, response_mode = response_mode)
    },
    args = list(
      app_file = app_file,
      origin = origin,
      bases = bases,
      async = async,
      response_mode = response_mode,
      app_function = app_function
    ),
    libpath = .libPaths(),
    supervise = TRUE,
    stdout = tempfile(),
    stderr = tempfile()
  )
  withr::defer(process$kill(), envir = .env)
  deadline <- Sys.time() + 30
  repeat {
    ready <- tryCatch(
      {
        response <- curl::curl_fetch_memory(
          origin,
          handle = curl::new_handle(timeout = 1)
        )
        response$status_code == 200L
      },
      error = function(...) FALSE
    )
    if (ready) {
      break
    }
    if (!process$is_alive() || Sys.time() >= deadline) {
      stop(
        "Retention fixture did not start; process stderr: ",
        process$get_error_file()
      )
    }
    Sys.sleep(0.1)
  }
  chrome <- chromote::Chromote$new()
  withr::defer(retention_chrome_close(chrome), envir = .env)
  new_browser <- function(chrome_instance = chrome) {
    context <- chrome_instance$Target$createBrowserContext()$browserContextId
    target <- chrome_instance$Target$createTarget(
      "about:blank",
      browserContextId = context
    )$targetId
    browser <- chromote::ChromoteSession$new(parent = chrome_instance, targetId = target)
    withr::defer(browser$close(), envir = .env)
    # Navigate from the initial blank document without waiting for a CDP
    # Page.navigate acknowledgement. The following wait requires actual app
    # output, so an unsuccessful navigation still fails the test.
    tryCatch(retention_browser_value(browser, paste0("window.location.replace(",
      jsonlite::toJSON(origin, auto_unbox = TRUE), ")")), error = function(...) NULL)
    retention_browser_wait(
      browser,
      function() retention_browser_snapshot(browser),
      "initial Shiny session"
    )
    browser
  }
  list(
    origin = origin,
    bases = bases,
    providers = providers,
    browser = new_browser(),
    new_browser = new_browser,
    process = process,
    chrome = chrome
  )
}
