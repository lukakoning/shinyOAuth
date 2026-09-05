spotify_dashboard_path <- function() {
  candidates <- c(
    file.path("inst", "examples", "spotify-dashboard.R"),
    testthat::test_path("..", "..", "inst", "examples", "spotify-dashboard.R"),
    system.file("examples", "spotify-dashboard.R", package = "shinyOAuth")
  )
  candidates <- candidates[file.exists(candidates) & nzchar(candidates)]
  if (!length(candidates)) {
    return(NA_character_)
  }
  candidates[[1]]
}

test_that("Spotify dashboard never disables table escaping", {
  path <- spotify_dashboard_path()
  skip_if(is.na(path), "Spotify dashboard is not available")

  source <- readLines(path, warn = FALSE)
  expect_false(any(grepl("escape\\s*=\\s*FALSE", source)))
  expect_gte(sum(grepl("escape\\s*=\\s*TRUE", source)), 2L)
})

test_that("DT escaping covers adversarial Spotify metadata", {
  skip_if_not_installed("DT")

  payload <- "<img src=x onerror=alert('stored-xss')>"
  metadata <- data.frame(
    Track = payload,
    Artist = payload,
    Album = payload,
    Genres = payload
  )

  widget <- DT::datatable(metadata, rownames = FALSE, escape = TRUE)

  expect_identical(attr(widget$x$options, "escapeIdx"), "true")
})

test_that("Spotify dashboard loads and transforms data in a fresh R process", {
  for (pkg in c("callr", "bslib", "ggplot2", "DT", "purrr", "dplyr")) {
    skip_if_not_installed(pkg)
  }
  path <- normalizePath(spotify_dashboard_path(), mustWork = TRUE)
  result <- callr::r(function(path, package_dir) {
    if (file.exists(file.path(package_dir, "R", "classes__OAuthClient.R"))) {
      pkgload::load_all(package_dir, quiet = TRUE)
    }
    Sys.setenv(SPOTIFY_OAUTH_CLIENT_ID = "smoke-client",
      SPOTIFY_OAUTH_CLIENT_SECRET = "smoke-secret")
    env <- new.env(parent = globalenv())
    expressions <- parse(path)
    for (expr in expressions) {
      # Build the UI and helpers without starting the interactive HTTP server.
      if (is.call(expr) && identical(expr[[1]], quote(shiny::runApp))) next
      eval(expr, env)
    }
    env$spotify_get <- function(...) list(items = list(list(name = "Track",
      artists = list(list(name = "Artist")), album = list(name = "Album"))))
    list(ui = is.function(env$ui) || inherits(env$ui, "shiny.tag") ||
        inherits(env$ui, "shiny.tag.list"),
      track = env$get_top_tracks(NULL)$name)
  }, args = list(path = path,
    package_dir = normalizePath(test_path("..", ".."))))
  expect_true(result$ui)
  expect_identical(result$track, "Track")
})
