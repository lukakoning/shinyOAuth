# shinyOAuth-browser-suite
test_that("external browser navigation preserves a retained Strict owner", {
  skip_if_not(identical(Sys.getenv("SHINYOAUTH_BROWSER_TESTS"), "true"))
  skip_if_not_installed("chromote")
  for (same_site in c("Strict", "Lax")) {
    port <- httpuv::randomPort(min = 49152L, max = 65535L)
    origin <- paste0("http://127.0.0.1:", port)
    repo <- normalizePath(test_path("../.."), winslash = "/")
    process <- callr::r_bg(function(repo, port, origin, same_site) {
      library(shinyOAuth)
      source(file.path(repo, "tests/testthat/helper-login.R"), local = TRUE)
      client <- oauth_client(make_test_provider(), "entry-test",
        redirect_uri = paste0(origin, "/callback"), scopes = "read")
      manager <- oauth_connections(list(a = client), origin, retention = "browser",
        owner_policy = oauth_browser_owner(same_site = same_site, allow_http_loopback = TRUE),
        store = oauth_connection_store_memory(),
        keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
      ui <- oauth_connections_ui(shiny::fluidPage("Application"), "health", manager)
      httpuv::runServer("127.0.0.1", port, list(call = function(req) {
        if (identical(req[["PATH_INFO"]], "/external")) {
          return(list(status = 200L, headers = list("Content-Type" = "text/html"),
            body = paste0("<a id='app' href='", origin, "/?view=keep'>App</a>")))
        }
        owners <- manager[["state"]][["owners"]]
        cookie <- shinyOAuth:::connection_owner_cookie_read(req, owners[["cookie_name"]])
        owner <- owners[["resolve"]](cookie)
        if (!is.null(owner)) owners[["retain"]](owner)
        response <- ui(req)
        if (grepl("Application", response[["content"]], fixed = TRUE)) {
          response[["content"]] <- sub("</body>", paste0(
            "<p id='known-owner' data-cookie-name='", owners[["cookie_name"]],
            "'>", !is.null(owner), "</p></body>"
          ), response[["content"]], fixed = TRUE)
        }
        list(status = response[["status"]],
          headers = c(response[["headers"]], list("Content-Type" = response[["content_type"]])),
          body = response[["content"]])
      }))
    }, args = list(repo, port, origin, same_site), stdout = "|", stderr = "|")
    withr::defer(try(process[["kill"]](), silent = TRUE))
    for (i in seq_len(100L)) {
      ready <- try(httr2::req_perform(httr2::request(origin)), silent = TRUE)
      if (!inherits(ready, "try-error")) break
      Sys.sleep(0.1)
    }
    expect_false(inherits(ready, "try-error"), info = process[["read_error"]]())
    browser <- chromote::ChromoteSession[["new"]]()
    withr::defer(try(browser[["close"]](), silent = TRUE))
    evaluate <- function(js) {
      browser[["Runtime"]][["evaluate"]](js, returnByValue = TRUE)[["result"]][["value"]]
    }
    wait_for_app <- function() {
      for (i in seq_len(200L)) {
        loaded <- evaluate("location.hostname === '127.0.0.1' && !location.search.includes('shinyOAuth_owner_recovery') && !!document.getElementById('known-owner')")
        if (isTRUE(loaded)) return(invisible(TRUE))
        Sys.sleep(0.05)
      }
      stop("Browser did not complete ordinary owner recovery: ",
        evaluate("JSON.stringify({url:location.href, body:document.body.innerText})"))
    }
    owner_cookie <- function() {
      cookies <- browser[["Network"]][["getCookies"]](urls = list(origin))[["cookies"]]
      name <- evaluate("document.getElementById('known-owner').dataset.cookieName")
      matching <- Filter(function(x) identical(x[["name"]], name), cookies)
      expect_length(matching, 1L)
      expect_identical(matching[[1L]][["sameSite"]], same_site)
      matching[[1L]][["value"]]
    }
    # Other managers on this host share Chrome's cookie jar across ports.
    invisible(browser[["Network"]][["setCookie"]](
      name = "shinyOAuth-owner-unrelated", value = "unrelated-owner",
      url = origin, httpOnly = TRUE, sameSite = "Lax"
    ))
    browser[["go_to"]](paste0(origin, "/"))
    wait_for_app()
    first <- owner_cookie()
    browser[["go_to"]](paste0(origin, "/"))
    wait_for_app()
    expect_identical(evaluate("document.getElementById('known-owner').textContent"), "TRUE")
    browser[["go_to"]](paste0("http://localhost:", port, "/external"))
    evaluate("document.getElementById('app').click(); true")
    wait_for_app()
    expect_identical(evaluate("document.getElementById('known-owner').textContent"), "TRUE")
    expect_identical(evaluate("location.search"), "?view=keep")
    expect_identical(owner_cookie(), first, info = same_site)
    browser[["close"]]()
    process[["kill"]]()
  }
})
