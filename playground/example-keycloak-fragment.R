# This script can start the local Keycloak Docker fixture when needed:
#   docker compose -f integration/keycloak/docker-compose.yml up -d
# This app uses the realm 'shinyoauth' and client 'shiny-public' by default.
# Make sure the client allows:
#   http://127.0.0.1:8100/callback
# Set SHINYOAUTH_START_KEYCLOAK=false to skip Docker auto-start.

devtools::load_all()

library(shiny)

auth_port <- as.integer(Sys.getenv("SHINYOAUTH_APP_PORT", "8100"))
keycloak_base_url <- Sys.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080")
keycloak_realm <- Sys.getenv("KEYCLOAK_REALM", "shinyoauth")
start_local_keycloak <- !identical(
  tolower(Sys.getenv("SHINYOAUTH_START_KEYCLOAK", "true")),
  "false"
)
keycloak_compose_file <- file.path(
  "integration",
  "keycloak",
  "docker-compose.yml"
)
redirect_uri <- sprintf("http://127.0.0.1:%d/callback", auth_port)

is_local_keycloak_base_url <- function(url) {
  grepl(
    "^https?://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?(/|$)",
    url
  )
}

is_keycloak_ready <- function(base_url, realm) {
  discovery_url <- paste0(
    sub("/+$", "", base_url),
    "/realms/",
    realm,
    "/.well-known/openid-configuration"
  )

  resp <- tryCatch(
    httr2::request(discovery_url) |>
      httr2::req_timeout(2) |>
      httr2::req_error(is_error = function(resp) FALSE) |>
      httr2::req_perform(),
    error = function(...) NULL
  )

  !is.null(resp) && identical(httr2::resp_status(resp), 200L)
}

ensure_local_keycloak <- function(base_url, realm, compose_file) {
  if (!isTRUE(start_local_keycloak) || !is_local_keycloak_base_url(base_url)) {
    return(invisible(FALSE))
  }

  if (is_keycloak_ready(base_url, realm)) {
    return(invisible(FALSE))
  }

  docker <- Sys.which("docker")
  if (!nzchar(docker)) {
    stop(
      paste(
        "Docker CLI was not found, and the local Keycloak test fixture is not running.",
        "Start it manually with `docker compose -f integration/keycloak/docker-compose.yml up -d`."
      ),
      call. = FALSE
    )
  }
  if (!file.exists(compose_file)) {
    stop(
      sprintf(
        "Could not find Docker compose file at '%s'. Run this script from the repo root.",
        compose_file
      ),
      call. = FALSE
    )
  }

  message("Starting local Keycloak via Docker Compose...")
  status <- system2(docker, c("compose", "-f", compose_file, "up", "-d"))
  if (!identical(status, 0L)) {
    stop("Failed to start local Keycloak Docker Compose stack.", call. = FALSE)
  }

  deadline <- Sys.time() + 60
  while (Sys.time() < deadline) {
    if (is_keycloak_ready(base_url, realm)) {
      return(invisible(TRUE))
    }

    Sys.sleep(1)
  }

  stop(
    paste(
      "Docker Compose started, but Keycloak did not become ready within 60 seconds.",
      "Check `docker compose -f integration/keycloak/docker-compose.yml logs -f`."
    ),
    call. = FALSE
  )
}

ensure_local_keycloak(
  keycloak_base_url,
  keycloak_realm,
  keycloak_compose_file
)

provider <- oauth_provider_keycloak(
  base_url = keycloak_base_url,
  realm = keycloak_realm
)
client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("KEYCLOAK_CLIENT_ID", "shiny-public"),
  client_secret = Sys.getenv("KEYCLOAK_CLIENT_SECRET", ""),
  redirect_uri = redirect_uri,
  scopes = c("openid", "profile", "email"),
  response_mode = "fragment"
)

base_ui <- fluidPage(
  titlePanel("shinyOAuth + Keycloak (fragment)"),
  p("Uses the local Keycloak fixture with response_mode = 'fragment'."),
  p(
    paste(
      "Login with alice / alice.",
      "The callback briefly lands on /callback so the browser can hand the fragment",
      "back to the server before the app resumes normally."
    )
  ),
  actionButton("login_btn", "Login"),
  actionButton("logout_btn", "Logout"),
  tags$hr(),
  h4("Browser state"),
  verbatimTextOutput("ready_state"),
  tags$hr(),
  h4("Auth state"),
  verbatimTextOutput("auth_state"),
  tags$hr(),
  h4("User info"),
  verbatimTextOutput("user_info")
)

ui <- oauth_fragment_ui(base_ui, id = "auth", client = client)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, auto_redirect = FALSE)

  observeEvent(input$login_btn, ignoreInit = TRUE, {
    auth$request_login()
  })

  observeEvent(input$logout_btn, ignoreInit = TRUE, {
    auth$logout()
  })

  output$ready_state <- renderText({
    paste("browser_ready:", isTRUE(auth$has_browser_token()))
  })

  output$auth_state <- renderText({
    paste(
      "authenticated:",
      isTRUE(auth$authenticated),
      "\nhas_token:",
      !is.null(auth$token),
      "\nerror:",
      if (!is.null(auth$error)) auth$error else "<none>",
      "\nerror_description:",
      if (!is.null(auth$error_description)) {
        auth$error_description
      } else {
        "<none>"
      }
    )
  })

  output$user_info <- renderPrint({
    if (is.null(auth$token)) {
      return("<not logged in>")
    }

    auth$token@userinfo
  })
}

app <- shinyApp(ui, server, uiPattern = ".*")
shiny::runApp(app, port = auth_port, host = "127.0.0.1")
