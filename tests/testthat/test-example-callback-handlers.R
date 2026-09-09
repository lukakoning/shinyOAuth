example_callback_request <- function(client, path = "/") {
  state <- parse_query_param(
    prepare_call(client, browser_token = valid_browser_token()),
    "state",
    decode = TRUE
  )
  list(
    REQUEST_METHOD = "GET",
    PATH_INFO = path,
    QUERY_STRING = httr2::url_query_build(list(
      code = "example-code",
      state = state
    )),
    rook.url_scheme = "http",
    HTTP_HOST = "localhost:8100"
  )
}

expect_example_callback_bridge <- function(app, client, req) {
  response <- app$httpHandler(req)
  expect_identical(response$status, 303L, info = response$content)
  expect_identical(response$headers[["Referrer-Policy"]], "no-referrer")
  expect_identical(response$headers[["Cache-Control"]], "no-store")
  expect_identical(response$headers[["Pragma"]], "no-cache")
  location <- response$headers[["Location"]]
  expect_match(location, "shinyOAuth_form_post=")
  expect_false(grepl(
    "example-code|code=|state=|<script",
    paste(location, response$content)
  ))
  req$QUERY_STRING <- sub("^\\?", "", location)
  page <- app$httpHandler(req)
  expect_equal(page$status, 200L)
  expect_identical(page$headers[["Referrer-Policy"]], "no-referrer")
  expect_identical(page$headers[["Cache-Control"]], "no-store")
  expect_identical(page$headers[["Pragma"]], "no-cache")
  expect_match(page$content, "shinyOAuth.js", fixed = TRUE)
}

test_that("deployment apps bridge callbacks behind their configured public origin", {
  root <- test_path("../..")
  skip_if_not(dir.exists(file.path(root, "integration")))
  withr::local_envvar(c(
    GITHUB_OAUTH_CLIENT_ID = "example-client",
    GITHUB_OAUTH_CLIENT_SECRET = "example-secret",
    OAUTH_REDIRECT_URI = "https://example.test/"
  ))
  for (file in c("gcp/app.R", "posit/app.R", "posit/app-auto-redirect.R")) {
    env <- new.env(parent = globalenv())
    app <- source(file.path(root, "integration", file), local = env)$value
    req <- example_callback_request(env$client)
    # The ingress terminates HTTPS and forwards HTTP. Public origin comes from
    # configuration, while the actual request path must still match.
    req$HTTP_HOST <- "internal-service:8080"
    expect_example_callback_bridge(app, env$client, req)
    req$PATH_INFO <- "/other-route"
    expect_gte(app$httpHandler(req)$status, 400L)

    for (invalid in c("", "not-a-uri")) {
      withr::with_envvar(c(OAUTH_REDIRECT_URI = invalid), {
        env <- new.env(parent = globalenv())
        app <- source(file.path(root, "integration", file), local = env)$value
        req$PATH_INFO <- "/"
        req$QUERY_STRING <- ""
        page <- app$httpHandler(req)
        expect_equal(page$status, 200L)
        expect_identical(page$headers[["Cache-Control"]], "no-store")
        expect_identical(page$headers[["Referrer-Policy"]], "no-referrer")
        req$QUERY_STRING <- "code=sample&state=sample"
        expect_gte(app$httpHandler(req)$status, 400L)
      })
    }
  }
})

test_that("playground query apps execute the callback bridge before rendering", {
  root <- test_path("../../playground")
  skip_if_not(dir.exists(root))
  files <- list.files(root, pattern = "^example.*[.]R$", full.names = TRUE)
  files <- files[!grepl("form-post", files)]
  for (file in files) {
    # Evaluate the actual UI/server definitions and app constructor, with a
    # local client. Provider discovery, daemons, and browser launching belong
    # to each example's manual setup and are not needed for the HTTP handler.
    env <- list2env(as.list(asNamespace("shiny")), parent = environment())
    env$client <- make_test_client(use_nonce = FALSE)
    path <- if (basename(file) == "example-keycloak-docker.R") {
      "/callback"
    } else {
      "/"
    }
    env$client@redirect_uri <- paste0("http://localhost:8100", path)
    env$otel_endpoint <- "http://localhost:4318"
    env$useShinyjs <- function(...) htmltools::tagList()
    expressions <- parse(file)
    for (expr in expressions) {
      if (
        is.call(expr) &&
          identical(expr[[1]], as.name("<-")) &&
          as.character(expr[[2]]) %in% c("ui", "server")
      ) {
        eval(expr, env)
      }
    }
    find_app <- function(expr) {
      if (!is.call(expr)) {
        return(NULL)
      }
      if (identical(expr[[1]], as.name("shinyApp"))) {
        return(expr)
      }
      for (child in as.list(expr)[-1]) {
        found <- find_app(child)
        if (!is.null(found)) return(found)
      }
      NULL
    }
    calls <- Filter(Negate(is.null), lapply(expressions, find_app))
    expect_length(calls, 1L)
    app <- eval(calls[[1]], env)
    req <- example_callback_request(env$client, path)
    expect_example_callback_bridge(app, env$client, req)
  }
})
