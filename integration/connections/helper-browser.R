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
  .env = parent.frame()
) {
  port <- httpuv::randomPort()
  origin <- paste0("http://127.0.0.1:", port)
  providers <- lapply(c("a", "b"), function(site) {
    provider <- retention_fixture_provider(
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
    "integration/connections/fixture-app.R"
  ))
  process <- callr::r_bg(
    function(app_file, origin, bases, async, response_mode) {
      Sys.setenv(CURL_SSL_BACKEND = "openssl")
      source(app_file, local = TRUE)
      retention_fixture_app(origin, bases, async, response_mode = response_mode)
    },
    args = list(
      app_file = app_file,
      origin = origin,
      bases = bases,
      async = async,
      response_mode = response_mode
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
  withr::defer(chrome$close(), envir = .env)
  new_browser <- function() {
    context <- chrome$Target$createBrowserContext()$browserContextId
    target <- chrome$Target$createTarget(
      "about:blank",
      browserContextId = context
    )$targetId
    browser <- chromote::ChromoteSession$new(parent = chrome, targetId = target)
    withr::defer(browser$close(), envir = .env)
    browser$Page$navigate(origin)
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
