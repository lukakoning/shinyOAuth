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

spotify_dashboard_helpers <- function() {
  path <- spotify_dashboard_path()
  skip_if(is.na(path), "Spotify dashboard is not available")
  env <- new.env(parent = globalenv())
  for (expr in parse(path)) {
    if (
      is.call(expr) &&
        identical(expr[[1L]], quote(`<-`)) &&
        is.call(expr[[3L]]) &&
        identical(expr[[3L]][[1L]], quote(`function`))
    ) {
      eval(expr, env)
    }
  }
  env
}

test_that("Spotify vignette clears cached data when authorization or scopes change", {
  candidates <- c(
    test_path("..", "..", "vignettes", "example-spotify.Rmd"),
    system.file("doc", "example-spotify.Rmd", package = "shinyOAuth")
  )
  candidates <- candidates[nzchar(candidates) & file.exists(candidates)]
  skip_if_not(length(candidates) > 0L, "Vignette source unavailable")
  lines <- readLines(candidates[[1L]], warn = FALSE)
  start <- match("```{r spotify-app, eval = FALSE}", lines)
  expect_false(is.na(start))
  end <- start + which(lines[-seq_len(start)] == "```")[[1L]]
  env <- new.env(parent = asNamespace("shinyOAuth"))
  for (name in getNamespaceExports("shiny")) {
    env[[name]] <- getExportedValue("shiny", name)
  }
  env[["library"]] <- function(...) invisible(NULL)
  env[["runApp"]] <- function(appDir, ...) appDir
  env[["oauth_module_server"]] <- function(...) {
    oauth_module_server(..., auto_redirect = FALSE)
  }
  withr::local_envvar(c(
    SPOTIFY_OAUTH_CLIENT_ID = "fixture-client",
    SPOTIFY_OAUTH_CLIENT_SECRET = "fixture-secret"
  ))
  eval(parse(text = lines[seq.int(start + 1L, end - 1L)]), env)

  requests <- 0L
  local_mocked_bindings(
    req_perform = function(req, ...) {
      requests <<- requests + 1L
      expect_match(req[["url"]], "https://api.spotify.com/v1/me/top/tracks", fixed = TRUE)
      httr2::response(
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"items":[{"name":"Fixture private track"}]}')
      )
    },
    .package = "httr2"
  )
  token <- OAuthToken(
    access_token = "fixture-access",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = c("user-read-private", "user-top-read"),
    granted_scopes_verified = TRUE
  )
  shiny::testServer(env[["server"]], {
    auth[["token"]] <- token
    session[["setInputs"]](load = 1)
    expect_match(output[["tracks"]], "Fixture private track", fixed = TRUE)
    expect_identical(requests, 1L)
    authorization <- auth[["connection"]]()[["id"]]

    narrowed <- token
    narrowed@granted_scopes <- "user-read-private"
    auth[["token"]] <- narrowed
    session[["flushReact"]]()
    expect_identical(auth[["connection"]]()[["id"]], authorization)
    expect_true(auth[["authenticated"]])
    expect_null(tracks())
    expect_error(output[["tracks"]], class = "shiny.silent.error")
    session[["setInputs"]](load = 2)
    expect_identical(requests, 1L)

    auth[["token"]] <- token
    session[["flushReact"]]()
    expect_null(tracks())
    expect_error(output[["tracks"]], class = "shiny.silent.error")
    session[["setInputs"]](load = 3)
    expect_match(output[["tracks"]], "Fixture private track", fixed = TRUE)

    # Replace the authorization without an intermediate reactive flush.
    auth[["logout"]]()
    auth[["token"]] <- token
    session[["flushReact"]]()
    expect_false(identical(auth[["connection"]]()[["id"]], authorization))
    expect_null(tracks())
    expect_error(output[["tracks"]], class = "shiny.silent.error")
    session[["setInputs"]](load = 4)
    expect_match(output[["tracks"]], "Fixture private track", fixed = TRUE)

    auth[["logout"]]()
    session[["flushReact"]]()
    expect_null(tracks())
    expect_error(output[["tracks"]], class = "shiny.silent.error")
    expect_identical(requests, 3L)
  })
})

test_that("Spotify URLs preserve safe links and reject unsupported origins", {
  helpers <- spotify_dashboard_helpers()
  safe_url <- helpers[["spotify_safe_url"]]
  expect_identical(
    safe_url("https://open.spotify.com/artist/123", "open.spotify.com"),
    "https://open.spotify.com/artist/123"
  )
  for (url in c(
    "http://open.spotify.com/artist/123",
    "https://open.spotify.com.example.test/artist/123",
    "https://user@open.spotify.com/artist/123",
    "https://open.spotify.com:444/artist/123"
  )) {
    expect_null(safe_url(url, "open.spotify.com"))
  }
  expect_identical(
    helpers[["spotify_safe_image_url"]]("https://i.scdn.co/image/abc"),
    "https://i.scdn.co/image/abc"
  )
})

test_that("Spotify dashboard never disables table escaping", {
  path <- spotify_dashboard_path()
  skip_if(is.na(path), "Spotify dashboard is not available")

  source <- readLines(path, warn = FALSE)
  expect_false(any(grepl("escape\\s*=\\s*FALSE", source)))
  expect_gte(sum(grepl("escape\\s*=\\s*TRUE", source)), 2L)
})

test_that("recent plays preserve UTC time and fractional seconds", {
  helpers <- spotify_dashboard_helpers()
  helpers[["spotify_get"]] <- function(...) {
    list(
      items = list(list(
        played_at = "2026-09-09T14:23:45.678Z",
        track = list(name = "Track", artists = list(list(name = "Artist")))
      ))
    )
  }
  result <- helpers[["get_recently_played"]](NULL)[["played_at"]]
  expect_equal(
    as.numeric(result) -
      as.numeric(as.POSIXct("2026-09-09 14:23:45", tz = "UTC")),
    0.678,
    tolerance = 1e-6
  )
  expect_identical(attr(result, "tzone", exact = TRUE), "UTC")
})

test_that("Spotify avatars render list and data frame images safely", {
  helpers <- spotify_dashboard_helpers()
  url <- "https://i.scdn.co/image/avatar"
  for (images in list(list(list(url = url)), data.frame(url = url))) {
    avatar <- helpers[["spotify_avatar"]](images)
    expect_identical(avatar[["name"]], "img")
    expect_identical(avatar[["attribs"]][["src"]], url)
  }
  for (images in list(
    NULL,
    list(),
    data.frame(),
    list(list()),
    list(list(url = "https://example.test/avatar"))
  )) {
    expect_null(helpers[["spotify_avatar"]](images))
  }
})

test_that("Spotify dashboard loads and transforms data in a fresh R process", {
  for (pkg in c(
    "callr",
    "pkgload",
    "bslib",
    "ggplot2",
    "DT",
    "purrr",
    "dplyr"
  )) {
    skip_if_not_installed(pkg)
  }
  path <- normalizePath(spotify_dashboard_path(), mustWork = TRUE)
  result <- callr::r(
    function(path, package_dir) {
      if (file.exists(file.path(package_dir, "R", "classes__OAuthClient.R"))) {
        pkgload::load_all(package_dir, quiet = TRUE)
      }
      Sys.setenv(
        SPOTIFY_OAUTH_CLIENT_ID = "smoke-client",
        SPOTIFY_OAUTH_CLIENT_SECRET = "smoke-secret"
      )
      env <- new.env(parent = globalenv())
      expressions <- parse(path)
      for (expr in expressions) {
        # Build the UI and helpers without starting the interactive HTTP server.
        if (is.call(expr) && identical(expr[[1]], quote(shiny::runApp))) {
          next
        }
        eval(expr, env)
      }
      env[["spotify_get"]] <- function(...) {
        list(
          items = list(list(
            name = "Track",
            artists = list(list(name = "Artist")),
            album = list(name = "Album")
          ))
        )
      }
      list(
        ui = is.function(env[["ui"]]) ||
          inherits(env[["ui"]], "shiny.tag") ||
          inherits(env[["ui"]], "shiny.tag.list"),
        track = env[["get_top_tracks"]](NULL)[["name"]]
      )
    },
    args = list(path = path, package_dir = normalizePath(test_path("..", "..")))
  )
  expect_true(result[["ui"]])
  expect_identical(result[["track"]], "Track")
})
