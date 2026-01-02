# Example: Spotify login to display listening data

## Overview

This vignette demonstrates the code for an example Shiny application
that uses the `shinyOAuth` package to authenticate users via Spotify’s
OAuth 2.0 service.

After logging in, the app fetches and displays data about the user and
their listening behaviour in the form of a simple dashboard built with
‘bslib’. It shows the user’s profile information with their avatar, a
live view of what they are currently playing, their top tracks and
artists, and a history of recently played songs.

For a more detailed explanation of how to use ‘shinyOAuth’ and its
features, see:
[`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

## Code

``` r
# Example Shiny app using shinyOAuth to connect to Spotify API
#
# This app demonstrates logging into Spotify with shinyOAuth and fetching
# various user statistics via the Spotify Web API. We then build a simple
# dashboard to display this information
#
# Requirements:
# - Create a Spotify OAuth 2.0 application at https://developer.spotify.com
# - Add a redirect URI that matches redirect_uri below (default: http://127.0.0.1:8100)
# - Set environment variables `SPOTIFY_OAUTH_CLIENT_ID` and `SPOTIFY_OAUTH_CLIENT_SECRET`

# Load packages & configure OAuth 2.0 client for Spotify -----------------------

library(shiny)
library(shinyOAuth)
library(bslib)
library(ggplot2)
library(DT)

# Configure provider and client for Spotify

provider <- oauth_provider_spotify()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("SPOTIFY_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("SPOTIFY_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c(
    "user-read-email",
    "user-read-private",
    "user-top-read",
    "user-read-recently-played",
    "user-read-playback-state",
    "user-read-currently-playing"
  )
)


# Spotify API helpers ----------------------------------------------------------

# Small helpers to call Spotify API with the user's access token
# We define a few specialized functions for common endpoints

spotify_get <- function(token, path, query = list()) {
  url <- paste0("https://api.spotify.com", path)

  req <- client_bearer_req(token, url, query = query)
  resp <- httr2::req_perform(req)

  if (httr2::resp_is_error(resp)) {
    msg <- sprintf("Spotify API error: HTTP %s", httr2::resp_status(resp))
    stop(msg, call. = FALSE)
  }

  httr2::resp_body_json(resp, simplifyVector = TRUE)
}

# Specialized helper for endpoints that may return 204 (e.g., currently-playing)
spotify_get_maybe_empty <- function(token, path, query = list()) {
  url <- paste0("https://api.spotify.com", path)
  
  req <- client_bearer_req(token, url, query = query)
  resp <- httr2::req_perform(req)
  
  status <- httr2::resp_status(resp)
  if (status == 204L) {
    return(NULL)
  }
  
  if (httr2::resp_is_error(resp)) {
    msg <- sprintf("Spotify API error: HTTP %s", status)
    stop(msg, call. = FALSE)
  }
  
  httr2::resp_body_json(resp, simplifyVector = TRUE)
}

# Fetch top tracks and artists (short_term: last 4 weeks)
get_top_tracks <- function(token, limit = 10, time_range = "short_term") {
  out <- spotify_get(
    token,
    "/v1/me/top/tracks",
    query = list(limit = limit, time_range = time_range)
  )

  items <- out$items %||% list()
  if (length(items) == 0) {
    return(data.frame())
  }

  df <- purrr::map(seq_along(items), function(i) {
    item <- items[i, ]
    data.frame(
      name = item$name %||% NA_character_,
      artist = paste(item$artists[[1]]$name, collapse = ", "),
      album = item$album$name %||% NA_character_,
      popularity = as.numeric(item$popularity) %||% NA_real_,
      stringsAsFactors = FALSE
    )
  }) |> 
    dplyr::bind_rows()

  df
}

# Fetch top artists
get_top_artists <- function(token, limit = 10, time_range = "short_term") {
  out <- spotify_get(
    token,
    "/v1/me/top/artists",
    query = list(limit = limit, time_range = time_range)
  )

  items <- out$items %||% list()
  if (length(items) == 0) {
    return(data.frame())
  }

  df <- purrr::map(seq_along(items), function(i) {
    item <- items[i, ]
    data.frame(
      name = item$name %||% NA_character_,
      genres = paste(
        as.character(item$genres |> purrr::flatten() %||% character()),
        collapse = ", "
      ),
      popularity = as.numeric(item$popularity) %||% NA_real_,
      followers = as.numeric(item$followers$total %||% NA_real_),
      stringsAsFactors = FALSE
    )
  }) |>
    dplyr::bind_rows()

  df
}

# Get recently played tracks
get_recently_played <- function(token, limit = 20) {
  out <- spotify_get(
    token,
    "/v1/me/player/recently-played",
    query = list(limit = limit)
  )

  items <- out$items %||% list()
  if (length(items) == 0) {
    return(data.frame())
  }

  df <- purrr::map(seq_along(items), function(i) {
    item <- items[i, ]
    data.frame(
      played_at = as.POSIXct(item$played_at %||% NA_character_, tz = "UTC"),
      track = item$track$name %||% NA_character_,
      artist = paste(item$track$artists[[1]]$name, collapse = ", "),
      album = item$track$album$name %||% NA_character_,
      stringsAsFactors = FALSE
    )
  }) |>
    dplyr::bind_rows()

  df
}

# Currently playing (may be NULL if nothing is playing)
get_currently_playing <- function(token) {
  out <- spotify_get_maybe_empty(token, "/v1/me/player/currently-playing")

  if (is.null(out)) {
    return(NULL)
  }
  
  # Normalize essential fields with guards
  item <- out$item

  if (is.null(item)) {
    return(NULL)
  }
  
  artists <- tryCatch(
    {
      if (!is.null(item$artists) && length(item$artists) > 0) {
        paste(item$artists$name, collapse = ", ")
      } else {
        "—"
      }
    },
    error = function(e) "—"
  )
  
  art_url <- tryCatch(
    {
      item$album$images$url[[1]]
    },
    error = function(e) NULL
  )
  
  list(
    is_playing = isTRUE(out$is_playing),
    progress_ms = as.numeric(out$progress_ms %||% NA_real_),
    duration_ms = as.numeric(item$duration_ms %||% NA_real_),
    track = item$name %||% "—",
    artist = artists,
    album = item$album$name %||% "—",
    art = art_url
  )
}

# Helper to safely validate data frames returned from API calls
safe_df <- function(x) {
  if (inherits(x, "try-error")) {
    return(NULL)
  }
  
  if (is.null(x) || !is.data.frame(x) || nrow(x) == 0) {
    return(NULL)
  }
  
  x
}

# Format milliseconds to m:ss
format_ms <- function(ms) {
  if (is.null(ms) || is.na(ms)) {
    return("—")
  }
  
  s <- round(as.numeric(ms) / 1000)
  
  sprintf("%d:%02d", s %/% 60, s %% 60)
}


# Shiny app --------------------------------------------------------------------

## Theme & CSS -----------------------------------------------------------------

# Some basic Bootstrap theming
spotify_theme <- bs_theme(
  version = 5,
  base_font = font_google("Inter"),
  heading_font = font_google("Space Grotesk"),
  bg = "#121212",
  fg = "#F5F6F8",
  primary = "#1DB954",
  secondary = "#191414",
  success = "#1ED760",
  "navbar-bg" = "#0F0F0F",
  "card-border-color" = "#1DB95433"
)

# Add CSS
spotify_theme <- bs_add_rules(
  spotify_theme,
  paste(
    "body { background: radial-gradient(circle at top left, #1DB95411, #121212 55%); }",
    ".navbar-dark { border-bottom: 1px solid #1DB95422; }",
    ".card { background-color: #181818; border-radius: 18px; box-shadow: 0 18px 30px -24px rgba(0,0,0,0.7); transition: transform 0.2s, box-shadow 0.2s; }",
    ".card:hover { box-shadow: 0 20px 35px -20px rgba(29, 185, 84, 0.3); }",
    ".card-header { background-color: rgba(29, 185, 84, 0.08); border-bottom: 1px solid rgba(29, 185, 84, 0.2); font-weight: 600; }",
    ".profile-avatar { width: 72px; height: 72px; border-radius: 50%; object-fit: cover; box-shadow: 0 0 0 3px #1DB95455; transition: box-shadow 0.3s; }",
    ".profile-avatar:hover { box-shadow: 0 0 0 4px #1DB954; }",
    ".login-hero { min-height: 60vh; }",
    ".login-card { background: linear-gradient(130deg, #1DB954 0%, #1AA34A 55%, #121212 100%); color: #0C0C0C; border: none; }",
    ".login-card .btn { background-color: #121212; color: #F5F6F8; border: none; transition: all 0.3s; }",
    ".login-card .btn:hover { background-color: #0f0f0f; color: #1DB954; transform: scale(1.05); }",
    ".value-box { background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%); border: 1px solid #1DB95433; border-radius: 12px; transition: border-color 0.3s; padding: 0.6rem 0.9rem !important; }",
    ".value-box:hover { border-color: #1DB95466; }",
    ".value-box .value { font-size: 1.3rem; font-weight: 700; color: #1DB954; line-height: 1.2; }",
    ".value-box .value-box-title, .value-box h6, .value-box .title { font-size: 0.85rem; letter-spacing: .02em; opacity: .95; }",
    ".value-box p { margin-bottom: 0; font-size: 0.9rem; }",
    ".value-box .showcase-icon { color: #1DB954; opacity: 0.7; }",
    ".table { color: #F5F6F8; margin-bottom: 0; }",
    ".table thead { color: #1DB954; font-weight: 600; border-bottom: 2px solid #1DB95444; }",
    ".table tbody tr { transition: background-color 0.2s; }",
    ".table tbody tr:hover { background-color: rgba(29, 185, 84, 0.15); }",
    ".table td { vertical-align: middle; padding: 0.75rem; }",
    ".table td:first-child { color: #1DB954; font-weight: 600; width: 40px; text-align: center; }",
    ".control-card { background: rgba(16, 16, 16, 0.7); border: 1px solid #1DB95422; }",
    ".badge { font-size: 0.85rem; padding: 0.4em 0.8em; }",
    ".play-count-badge { background: linear-gradient(135deg, #1DB954 0%, #1AA34A 100%); color: #000; font-weight: 700; }",
    ".navbar .navbar-nav { display: none !important; }",
    sep = "\n"
  )
)

# Subtle readability and responsive polish overrides
spotify_theme <- bs_add_rules(
  spotify_theme,
  paste(
    "/* Ensure cards don't collapse too small on narrow screens */",
    ".card { min-width: 300px; }",
    "/* Avoid horizontal scroll within cards */",
    ".card .card-body { overflow-x: hidden; }",
    "/* Add gap between cards in layout_columns */",
    ".bslib-grid { gap: 1rem !important; }",
    "/* Ensure proper wrapping for cards - prevent cards from becoming too narrow */",
    ".bslib-grid > div { min-width: 300px; flex: 1 1 300px; }",
    "/* Prevent value box containers from collapsing */",
    ".card-body .bslib-grid { display: flex; flex-wrap: wrap; }",

    "/* Softer login gradient and better contrast */",
    ".login-card { background: linear-gradient(145deg, rgba(29,185,84,0.18) 0%, rgba(29,185,84,0.08) 38%, #1a1a1a 100%); color: #F5F6F8; border: 1px solid #1DB95422; overflow: hidden; }",
    ".login-card .btn { background-color: #121212; color: #F5F6F8; border: 1px solid #1DB95444; transition: background-color 0.25s, color 0.25s, box-shadow 0.25s; }",
    ".login-card .btn:hover { background-color: #0f0f0f; color: #1DB954; box-shadow: 0 8px 22px rgba(29,185,84,0.22); }",
    ".login-card .btn:focus, .login-card .btn:focus-visible { outline: none; box-shadow: 0 0 0 0.2rem rgba(29,185,84,0.35); }",

    "/* Improve muted text contrast inside cards/value boxes */",
    ".card .text-muted, .value-box .text-muted { color: #CFD3D8 !important; }",

    "/* DataTables dark theme tweaks */",
    ".dataTables_wrapper .dataTables_length select, .dataTables_wrapper .dataTables_filter input { background-color: #0f0f0f; color: #F5F6F8; border: 1px solid #1DB95433; }",
    ".dataTables_wrapper .dataTables_paginate .paginate_button { color: #F5F6F8 !important; border: 1px solid transparent; }",
    ".dataTables_wrapper .dataTables_paginate .paginate_button.current, .dataTables_wrapper .dataTables_paginate .paginate_button:hover { color: #1DB954 !important; background: #0f0f0f; border-color: #1DB95433; }",
    ".dataTables_wrapper .dataTables_info { color: #E4E7EB; }",

    "/* Slightly more visible table header border for clarity */",
    ".table thead { border-bottom: 2px solid #1DB95455; }",

    "/* Custom Spotify outline button (for Sign out) */",
    ".btn-spotify-outline { color: #1DB954; border: 1px solid #1DB95499; background: transparent; }",
    ".btn-spotify-outline:hover { color: #0b0b0b; background: #1DB954; border-color: #1DB954; }",

    "/* Plan badge for better readability */",
    ".badge-plan { background: transparent; border: 1px solid #1DB95466; color: #F5F6F8; }",

    "/* Sidebar toggle visibility */",
    ".layout-sidebar .collapse-toggle, .layout-sidebar .sidebar-toggle, .bslib-sidebar-layout .collapse-toggle { color: #F5F6F8; border: 1px solid #1DB95455; background: #0f0f0f; }",
    ".layout-sidebar .collapse-toggle:hover, .layout-sidebar .sidebar-toggle:hover, .bslib-sidebar-layout .collapse-toggle:hover { border-color: #1DB954aa; color: #1DB954; }",

    "/* Value box compact sizing and min width with proper wrapping */",
    ".value-box { min-width: 220px; margin-bottom: 0.75rem; flex: 1 1 220px; }",
    ".value-box .showcase-top, .value-box .showcase-bottom, .value-box .showcase-area { gap: .5rem; }",
    ".value-box .showcase-icon { font-size: 0.95rem; }",
    "/* Prevent value box text overflow */",
    ".value-box .value { word-break: break-word; font-size: 1.1rem !important; }",
    ".value-box p { word-break: break-word; overflow-wrap: break-word; font-size: 0.85rem; }",
    ".value-box .title, .value-box h6 { font-size: 0.8rem; }",

    "/* Now playing artwork sizing */",
    ".now-playing-art { width: 80px; height: 80px; object-fit: cover; border-radius: 8px; box-shadow: 0 8px 18px rgba(0,0,0,.35); }",

    sep = "\n"
  )
)


## UI --------------------------------------------------------------------------

ui <- bslib::page_fluid(
  title = tags$span(
    class = "d-flex align-items-center gap-2",
    icon("headphones"),
    span(class = "fw-semibold", "Spotify Listening Studio")
  ),
  theme = spotify_theme,
  use_shinyOAuth(),
  div(
    class = "pt-4 pb-5",
    uiOutput("oauth_error"),
    conditionalPanel(
      condition = "output.isAuthenticated",
      layout_sidebar(
        sidebar = sidebar(
          card(
            class = "control-card",
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("sliders-h"),
              span("Personalize view")
            )),
            card_body(
              selectInput(
                "time_range",
                "Listening window",
                choices = c(
                  "Last 4 weeks" = "short_term",
                  "Last 6 months" = "medium_term",
                  "All-time favorites" = "long_term"
                ),
                selected = "short_term"
              ),
              sliderInput(
                "top_limit",
                "Top items",
                min = 5,
                max = 20,
                value = 10,
                step = 1
              )
            ),
            card_footer(tags$small(
              class = "text-muted",
              "Adjust filters to explore different eras of your listening."
            ))
          ),
          width = 320,
          open = TRUE
        ),
        fillable = TRUE,
        layout_column_wrap(
          width = "350px",
          heights_equal = "row",
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("user"),
              span("Profile")
            )),
            card_body(uiOutput("profile"))
          ),
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("play-circle"),
              span("Listening sessions")
            )),
            card_body(uiOutput("summary_boxes"))
          ),
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("broadcast-tower"),
              span("Now playing")
            )),
            card_body(uiOutput("now_playing"))
          )
        ),
        layout_column_wrap(
          width = "400px",
          fill = TRUE,
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("music"),
              span("Top tracks")
            )),
            card_body(DTOutput("top_tracks"))
          ),
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("users"),
              span("Top artists")
            )),
            card_body(DTOutput("top_artists"))
          )
        ),
        layout_column_wrap(
          width = NULL,
          fill = TRUE,
          style = css(grid_template_columns = "3fr 2fr"),
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("history"),
              span("Recent plays")
            )),
            card_body(DTOutput("recent"))
          ),
          card(
            card_header(div(
              class = "d-flex align-items-center gap-2",
              icon("chart-bar"),
              span("Artists on repeat")
            )),
            card_body(plotOutput("recent_artist_plot", height = "400px"))
          )
        )
      )
    ),
    conditionalPanel(
      condition = "!output.isAuthenticated",
      div(
        class = "login-hero d-flex justify-content-center align-items-center",
        card(
          class = "login-card text-center p-5",
          card_body(
            icon("headphones", class = "display-4 mb-3"),
            h2("Spotify Listening Studio"),
            p(
              class = "lead",
              "Sign in to reveal your personal soundtrack: relive your top tracks, spotlight your favorite artists, and surface the songs you can't stop replaying."
            ),
            actionButton(
              "login",
              "Sign in with Spotify",
              class = "btn btn-lg px-4 py-3 mt-2"
            ),
            div(
              class = "mt-3 small",
              tags$strong("Scopes:"),
              " user-top-read • user-read-recently-played • user-read-email • user-read-private"
            )
          )
        )
      )
    )
  )
)


## Server ----------------------------------------------------------------------

server <- function(input, output, session) {
  # Handle Spotify login -------------------------------------------------------

  auth <- oauth_module_server("auth", client, auto_redirect = FALSE)

  # Expose auth state to JS for our conditionalPanel
  output$isAuthenticated <- shiny::reactive({
    isTRUE(auth$authenticated)
  })
  shiny::outputOptions(output, "isAuthenticated", suspendWhenHidden = FALSE)

  observeEvent(input$login, {
    auth$request_login()
  })

  observeEvent(input$logout, {
    req(isTRUE(auth$authenticated))
    auth$logout()
  })

  output$oauth_error <- renderUI({
    if (!is.null(auth$error)) {
      msg <- auth$error
      if (!is.null(auth$error_description)) {
        msg <- paste0(msg, ": ", auth$error_description)
      }
      div(class = "alert alert-danger", role = "alert", msg)
    }
  })

  # Show user profile ----------------------------------------------------------

  output$profile <- renderUI({
    req(auth$token)
    user_info <- auth$token@userinfo
    if (length(user_info) == 0) {
      return(div(class = "text-muted", "No user info"))
    }

    avatar <- NULL
    if (
      !is.null(user_info$images) &&
        is.data.frame(user_info$images) &&
        nrow(user_info$images) > 0
    ) {
      img_url <- user_info$images$url[[1]]
      if (!is.null(img_url) && nzchar(img_url)) {
        avatar <- tags$img(
          src = img_url,
          class = "profile-avatar",
          alt = "User avatar"
        )
      }
    }

    display_name <- user_info$display_name %||% user_info$id %||% "<unknown>"

    followers_badge <- NULL
    if (
      !is.null(user_info$followers) &&
        is.list(user_info$followers) &&
        !is.null(user_info$followers$total)
    ) {
      followers_badge <- span(
        class = "badge bg-success-subtle text-success-emphasis",
        "Followers:",
        tags$span(
          class = "ms-1",
          format(user_info$followers$total, big.mark = ",")
        )
      )
    }

    plan_badge <- NULL
    if (!is.null(user_info$product)) {
      plan_badge <- span(
        class = "badge badge-plan",
        paste("Plan:", user_info$product)
      )
    }

    country_badge <- NULL
    if (!is.null(user_info$country)) {
      country_badge <- span(
        class = "badge bg-dark border border-success",
        paste("Country:", user_info$country)
      )
    }

    spotify_link <- NULL
    if (
      !is.null(user_info$external_urls) &&
        is.list(user_info$external_urls) &&
        !is.null(user_info$external_urls$spotify)
    ) {
      spotify_link <- a(
        icon("external-link-alt", class = "ms-2"),
        href = user_info$external_urls$spotify,
        class = "text-decoration-none text-success",
        target = "_blank",
        title = "Open in Spotify"
      )
    }

    tagList(
      div(
        class = "d-flex align-items-center gap-3 flex-wrap",
        avatar,
        div(
          h4(class = "mb-1", display_name, spotify_link),
          if (!is.null(user_info$email)) {
            span(class = "text-muted", user_info$email)
          }
        ),
        div(
          class = "ms-auto",
          actionButton(
            "logout",
            "Sign out",
            class = "btn btn-spotify-outline btn-sm"
          )
        )
      ),
      hr(class = "border-success-subtle"),
      div(
        class = "d-flex flex-wrap gap-2",
        followers_badge,
        plan_badge,
        country_badge
      )
    )
  })

  # Reactives containing Spotify data ------------------------------------------

  # Data fetch reactives
  top_tracks <- reactive({
    req(auth$token, input$time_range, input$top_limit)
    try(
      get_top_tracks(
        auth$token,
        limit = input$top_limit,
        time_range = input$time_range
      ),
      silent = FALSE
    )
  })

  top_artists <- reactive({
    req(auth$token, input$time_range, input$top_limit)
    try(
      get_top_artists(
        auth$token,
        limit = input$top_limit,
        time_range = input$time_range
      ),
      silent = FALSE
    )
  })

  recent <- reactive({
    req(auth$token)
    try(get_recently_played(auth$token, limit = 50), silent = FALSE)
  })

  summary_data <- reactive({
    tracks_df <- safe_df(top_tracks())
    artists_df <- safe_df(top_artists())
    recent_df <- safe_df(recent())

    list(
      top_track = if (!is.null(tracks_df)) {
        list(
          name = tracks_df$name[1] %||% "—",
          artist = tracks_df$artist[1] %||% "—"
        )
      } else {
        NULL
      },
      top_artist = if (!is.null(artists_df)) {
        list(
          name = artists_df$name[1] %||% "—",
          genres = if (
            !is.null(artists_df$genres[1]) && nzchar(artists_df$genres[1])
          ) {
            artists_df$genres[1]
          } else {
            "—"
          }
        )
      } else {
        NULL
      },
      last_play = if (!is.null(recent_df)) {
        list(
          track = recent_df$track[1] %||% "—",
          artist = recent_df$artist[1] %||% "—",
          played_at = recent_df$played_at[1]
        )
      } else {
        NULL
      },
      unique_recent = if (!is.null(recent_df)) {
        dplyr::n_distinct(recent_df$artist)
      } else {
        NA_integer_
      }
    )
  })

  # Summary cards --------------------------------------------------------------

  # These show a few different summary stats about the user's listening

  output$summary_boxes <- renderUI({
    data <- summary_data()

    top_track <- data$top_track
    top_artist <- data$top_artist
    last_play <- data$last_play

    top_track_name <- if (!is.null(top_track)) top_track$name else "—"
    top_track_artist <- if (!is.null(top_track)) {
      top_track$artist
    } else {
      "No data for this window"
    }

    top_artist_name <- if (!is.null(top_artist)) top_artist$name else "—"
    top_artist_genres <- if (!is.null(top_artist)) {
      top_artist$genres
    } else {
      "No genres available"
    }

    last_track_name <- if (!is.null(last_play)) last_play$track else "—"
    last_track_details <- if (!is.null(last_play)) {
      parts <- c(last_play$artist %||% "—")
      if (!is.null(last_play$played_at) && !is.na(last_play$played_at)) {
        parts <- c(parts, format(last_play$played_at, "%b %d • %H:%M", tz = ""))
      }
      paste(parts, collapse = "  |  ")
    } else {
      "No recent playback"
    }

    unique_recent <- data$unique_recent
    unique_recent_value <- if (!is.na(unique_recent)) unique_recent else "—"

    layout_column_wrap(
      width = "220px",
      value_box(
        title = "Top Track",
        value = top_track_name,
        showcase = icon("music"),
        p(class = "text-muted", top_track_artist)
      ),
      value_box(
        title = "Top Artist",
        value = top_artist_name,
        showcase = icon("star"),
        p(class = "text-muted", top_artist_genres)
      ),
      value_box(
        title = "Recent Session",
        value = last_track_name,
        showcase = icon("clock"),
        p(class = "text-muted", last_track_details)
      ),
      value_box(
        title = "Unique Artists (recent)",
        value = unique_recent_value,
        showcase = icon("users"),
        p(class = "text-muted", "Across your latest 50 plays")
      )
    )
  })

  # Top tracks -----------------------------------------------------------------

  # Shows the user's top tracks in a data table

  output$top_tracks <- renderDT({
    df <- top_tracks()
    shiny::validate(
      need(!inherits(df, "try-error"), "Failed to load top tracks"),
      need(!is.null(df) && nrow(df) > 0, "No tracks returned for this window")
    )

    # Calculate play counts from recent plays
    recent_df <- safe_df(recent())
    if (!is.null(recent_df)) {
      recent_df$key <- paste0(recent_df$track, " — ", recent_df$artist)
      df$key <- paste0(df$name, " — ", df$artist)
      play_counts <- table(recent_df$key)
      df$plays <- vapply(
        df$key,
        function(k) {
          count <- suppressWarnings(play_counts[k])
          if (is.na(count)) 0L else as.integer(count)
        },
        integer(1)
      )
    } else {
      df$plays <- 0L
    }

    # Drop rows that are entirely missing name & artist
    keep <- (!is.na(df$name) & nzchar(df$name)) |
      (!is.na(df$artist) & nzchar(df$artist))
    df <- df[keep, , drop = FALSE]

    df <- df[, c("name", "artist", "album", "plays", "popularity")]
    df$plays <- ifelse(df$plays > 0, sprintf("🔁 %d", df$plays), "—")
    df$popularity <- ifelse(
      is.na(df$popularity),
      "—",
      sprintf("⭐ %d", round(df$popularity))
    )

    # Add rank numbers
    df <- cbind(`#` = seq_len(nrow(df)), df)

    df <- stats::setNames(
      df,
      c("#", "Track", "Artist", "Album", "Recent Plays", "Popularity")
    )
    datatable(
      df,
      rownames = FALSE,
      escape = FALSE,
      options = list(
        pageLength = 10,
        lengthChange = FALSE,
        order = list(list(0, 'asc')),
        columnDefs = list(
          list(orderable = FALSE, targets = 0)
        )
      )
    )
  })

  # Top artists ----------------------------------------------------------------

  # Shows the user's top artists in a data table

  output$top_artists <- renderDT({
    df <- top_artists()
    shiny::validate(
      need(!inherits(df, "try-error"), "Failed to load top artists"),
      need(!is.null(df) && nrow(df) > 0, "No artists returned for this window")
    )
    df <- df[, c("name", "genres", "popularity", "followers")]
    df$genres[df$genres == ""] <- "—"
    df$genres <- vapply(
      df$genres,
      function(g) {
        if (nchar(g) > 50) paste0(substr(g, 1, 47), "...") else g
      },
      character(1)
    )
    df$popularity <- ifelse(
      is.na(df$popularity),
      "—",
      sprintf("⭐ %d", round(df$popularity))
    )
    df$followers <- ifelse(
      is.na(df$followers),
      "—",
      paste0("👥 ", format(round(df$followers), big.mark = ","))
    )

    # Add rank numbers
    df <- cbind(`#` = seq_len(nrow(df)), df)

    df <- stats::setNames(
      df,
      c("#", "Artist", "Genres", "Popularity", "Followers")
    )
    datatable(
      df,
      rownames = FALSE,
      escape = FALSE,
      options = list(
        pageLength = 10,
        lengthChange = FALSE,
        order = list(list(0, 'asc')),
        columnDefs = list(
          list(orderable = FALSE, targets = 0)
        )
      )
    )
  })

  # Recent plays ---------------------------------------------------------------

  # Shows the user's recent plays in a data table

  output$recent <- renderDT({
    df <- recent()
    shiny::validate(
      need(!inherits(df, "try-error"), "Failed to load recent plays"),
      need(!is.null(df) && nrow(df) > 0, "No recent plays available")
    )
    df$played <- format(df$played_at, "%b %d • %H:%M", tz = "")
    df <- df[, c("played", "track", "artist", "album")]

    # Add rank numbers
    df <- cbind(`#` = seq_len(nrow(df)), df)
    df <- stats::setNames(df, c("#", "Played", "Track", "Artist", "Album"))
    datatable(
      df,
      rownames = FALSE,
      options = list(
        pageLength = 10,
        lengthChange = FALSE,
        order = list(list(0, 'desc')),
        columnDefs = list(
          list(orderable = FALSE, targets = 0)
        )
      )
    )
  })

  # Recent artists plot --------------------------------------------------------

  # Bar plot of most frequently played artists in recent plays

  output$recent_artist_plot <- renderPlot({
    df_recent <- recent()
    shiny::validate(
      need(!inherits(df_recent, "try-error"), "Failed to load recent plays"),
      need(
        !is.null(df_recent) && nrow(df_recent) > 0,
        "No recent plays available"
      )
    )

    # Primary: counts from recent plays
    counts <- sort(table(df_recent$artist), decreasing = TRUE)
    counts_df <- data.frame(
      artist = names(counts),
      plays = as.numeric(counts),
      stringsAsFactors = FALSE
    )

    # If the recent signal is weak (<= 3 artists or max <= 1), fall back to time-range top artists by popularity
    use_fallback <- nrow(counts_df) <= 3 ||
      max(counts_df$plays, na.rm = TRUE) <= 1
    if (isTRUE(use_fallback)) {
      df_top <- safe_df(top_artists())
      if (!is.null(df_top) && nrow(df_top) > 0) {
        counts_df <- df_top[, c("name", "popularity")]
        names(counts_df) <- c("artist", "plays")
      }
    }

    # Take top 10 and order for plotting
    counts_df <- utils::head(
      counts_df[order(counts_df$plays, decreasing = TRUE), ],
      10L
    )
    counts_df$artist <- factor(counts_df$artist, levels = rev(counts_df$artist))

    x_lab <- if (isTRUE(use_fallback)) "Popularity" else "Plays (last 50)"

    ggplot(counts_df, aes_string(x = "plays", y = "artist")) +
      geom_col(fill = "#1DB954", width = 0.65) +
      geom_text(aes(label = plays), hjust = -0.2, color = "#F5F6F8", size = 4) +
      scale_x_continuous(expand = expansion(mult = c(0, 0.08))) +
      labs(x = x_lab, y = NULL) +
      theme_minimal(base_family = "Inter", base_size = 13) +
      theme(
        plot.background = element_rect(fill = "#181818", colour = NA),
        panel.background = element_rect(fill = "#181818", colour = NA),
        panel.grid.major.y = element_blank(),
        panel.grid.major.x = element_line(colour = "#FFFFFF22"),
        text = element_text(colour = "#F5F6F8"),
        axis.text.y = element_text(colour = "#F5F6F8", size = 12),
        axis.text.x = element_text(colour = "#F5F6F8", size = 11),
        plot.margin = margin(10, 20, 10, 20)
      )
  })

  # Now playing ----------------------------------------------------------------

  # Shows the user's currently playing track with a progress bar

  output$now_playing <- renderUI({
    req(auth$token)
    # refresh every 5 seconds
    invalidateLater(5000, session)
    playing <- try(get_currently_playing(auth$token), silent = FALSE)
    if (inherits(playing, "try-error") || is.null(playing)) {
      return(div(class = "text-muted", "Nothing playing right now"))
    }

    pct <- NA_real_
    if (
      !is.na(playing$progress_ms) &&
        !is.na(playing$duration_ms) &&
        playing$duration_ms > 0
    ) {
      pct <- max(
        0,
        min(100, round(playing$progress_ms / playing$duration_ms * 100))
      )
    }

    progress_bar <- NULL
    if (!is.na(pct)) {
      progress_bar <- div(
        class = "progress mt-2",
        div(
          class = "progress-bar bg-success",
          role = "progressbar",
          style = paste0("width: ", pct, "%"),
          `aria-valuenow` = pct,
          `aria-valuemin` = 0,
          `aria-valuemax` = 100
        )
      )
    }

    time_label <- span(
      class = "small text-muted",
      paste(format_ms(playing$progress_ms), "/", format_ms(playing$duration_ms))
    )

    tagList(
      div(
        class = "d-flex gap-3 align-items-center",
        if (!is.null(playing$art)) {
          tags$img(
            src = playing$art,
            class = "now-playing-art",
            alt = "Album art"
          )
        },
        div(
          div(class = "fw-semibold", playing$track),
          div(class = "text-muted", paste(playing$artist, "•", playing$album))
        )
      ),
      progress_bar,
      div(class = "d-flex justify-content-end", time_label)
    )
  })
}


# Run app ----------------------------------------------------------------------

shiny::runApp(
  shinyApp(ui, server), port = 8100,
  launch.browser = FALSE
)

# Open the app in your regular browser at http://127.0.01:8100
# (viewers in RStudio/Positron/etc. cannot perform necessary redirects)
```
