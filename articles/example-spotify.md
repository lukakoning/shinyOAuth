# Example: Spotify login to display listening data

## Overview

This app shows a user’s top tracks after they authorize access to
Spotify. Spotify handles sign-in and returns an access token, a
credential your app can use to ask its API for data. The app never needs
the user’s Spotify password.

Scopes name the permissions to request. Here `user-top-read` allows
reading listening preferences; other data needs different permissions.
For the shared login setup, see
[Usage](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

## Spotify app registration

1.  Create an app in the [Spotify developer
    dashboard](https://developer.spotify.com/dashboard).
2.  Register `http://127.0.0.1:8100` as its redirect URI. Spotify
    accepts a loopback IP address for local HTTP development, but not
    `localhost`. See [Spotify’s redirect URI
    rules](https://developer.spotify.com/documentation/web-api/concepts/redirect_uri).
3.  Store the credentials as `SPOTIFY_OAUTH_CLIENT_ID` and
    `SPOTIFY_OAUTH_CLIENT_SECRET` in your R environment. See the
    [environment setup
    example](https://lukakoning.github.io/shinyOAuth/articles/usage.html#github-app-registration)
    for `.Renviron` syntax.
4.  Check your app’s [development-mode access
    rules](https://developer.spotify.com/documentation/web-api/concepts/quota-modes).
    Development apps require the owner to have Spotify Premium, and test
    users need to be on the app’s allowlist.

## Shiny app example

Save this as `app.R`, run it, and open `http://127.0.0.1:8100` in a
regular browser. After connecting Spotify, click Load top tracks.

``` r

library(shiny)
library(shinyOAuth)

client <- oauth_client(
  provider = oauth_provider_spotify(),
  client_id = Sys.getenv("SPOTIFY_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("SPOTIFY_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("user-read-private", "user-top-read"),
  resource_bases = c(spotify = "https://api.spotify.com/v1")
)

ui <- oauth_ui(fluidPage(
  h2("My top tracks"),
  actionButton("load", "Load top tracks"),
  tableOutput("tracks")
), id = "auth", client = client)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)
  tracks <- reactiveVal(NULL)

  observe({
    connection <- auth[["connection"]]()
    result <- isolate(tracks())
    if (is.null(connection) ||
        !connection[["has_scopes"]]("user-top-read") ||
        (!is.null(result) &&
         !identical(result[["authorization"]], connection[["id"]]))) {
      tracks(NULL)
    }
  })

  observeEvent(input[["load"]], {
    connection <- req(auth[["connection"]]())
    req(connection[["has_scopes"]]("user-top-read"))
    data <- tryCatch({
      response <- connection[["request"]](
        "spotify", "me/top/tracks",
        query = list(limit = 10, time_range = "short_term"),
        required_scopes = "user-top-read",
        refresh = TRUE
      )
      httr2::resp_check_status(response)
      body <- httr2::resp_body_json(response, simplifyVector = FALSE)
      vapply(body[["items"]], function(track) track[["name"]], character(1))
    }, error = function(e) NULL)
    tracks(list(authorization = connection[["id"]], data = data))
  })

  output[["tracks"]] <- renderTable({
    connection <- req(auth[["connection"]]())
    req(connection[["has_scopes"]]("user-top-read"))
    result <- tracks()
    req(identical(result[["authorization"]], connection[["id"]]))
    values <- result[["data"]]
    validate(need(!is.null(values), "Could not load tracks. Try again later."))
    validate(need(length(values) > 0, "No listening data to show yet."))
    data.frame(Track = values)
  })
}

runApp(shinyApp(ui, server), port = 8100, launch.browser = FALSE)
```

## API requests and scopes

The request asks for up to ten tracks from the short-term range, using
the `user-top-read` permission. The module obtains and stores the access
token; the connection checks the operation’s scope and approved API
address, refreshing the token if needed before the request.
[`observeEvent()`](https://rdrr.io/pkg/shiny/man/observeEvent.html)
loads the data when the button is clicked, and
[`renderTable()`](https://rdrr.io/pkg/shiny/man/renderTable.html)
displays it for the current login. The observer clears cached tracks on
logout, a new login, or loss of permission to read them.

Other Spotify endpoints require their corresponding scopes. Empty
results can be normal for accounts without listening history; API errors
can indicate missing permissions, app access restrictions, or request
limits.

## Full dashboard example

A larger example is installed with the package. It adds profile
information, currently playing music, top artists, and recent tracks,
with a bslib layout. It uses the same authentication setup as the
example above.

``` r

install.packages(c("bslib", "ggplot2", "DT", "purrr", "dplyr"))
dashboard_file <- system.file(
  "examples", "spotify-dashboard.R", package = "shinyOAuth", mustWork = TRUE
)
file.show(dashboard_file)  # Read or copy the complete source.
source(dashboard_file)    # Run after setting your Spotify credentials.
```

The installed dashboard validates Spotify link and image URLs and
escapes text in its HTML output.
