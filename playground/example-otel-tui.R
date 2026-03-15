devtools::load_all()

library(shiny)
library(otel)
library(otelsdk)

options(
  shinyOAuth.print_errors = TRUE,
  shinyOAuth.print_traceback = TRUE
)

setup_otel_tui <- function(
  endpoint = Sys.getenv("OTEL_TUI_ENDPOINT", "http://127.0.0.1:4318")
) {
  base_url <- sub("/+$", "", endpoint)
  otel_ns <- asNamespace("otel")
  otel_state <- get("the", envir = otel_ns)

  # Also configure the current process explicitly so spans/logs emitted before
  # any lazy OTEL initialization use the same exporters immediately.
  otel_state$tracer_provider <- getElement(
    otelsdk::tracer_provider_http,
    "new"
  )(list(
    url = paste0(base_url, "/v1/traces"),
    timeout = 1000L
  ))
  otel_state$logger_provider <- getElement(
    otelsdk::logger_provider_http,
    "new"
  )(list(
    url = paste0(base_url, "/v1/logs"),
    timeout = 1000L
  ))

  invisible(base_url)
}

otel_endpoint <- setup_otel_tui()
mirai::daemons(2)

provider <- oauth_provider_github()

client_id <- Sys.getenv("GITHUB_OAUTH_CLIENT_ID", "")
client_secret <- Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
redirect_uri <- Sys.getenv("GITHUB_OAUTH_REDIRECT_URI", "http://127.0.0.1:8100")

if (!nzchar(client_id) || !nzchar(client_secret)) {
  stop(
    paste(
      "Set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET before running this app.",
      "For local use, set the GitHub OAuth callback URL to",
      redirect_uri
    )
  )
}

client <- oauth_client(
  provider = provider,
  client_id = client_id,
  client_secret = client_secret,
  redirect_uri = redirect_uri,
  scopes = character(0)
)

ui <- fluidPage(
  use_shinyOAuth(),
  tags$h3("shinyOAuth + otel-tui"),
  tags$p(
    "Collector endpoint:",
    tags$code(otel_endpoint)
  ),
  tags$p(
    "Run ",
    tags$code("otel-tui"),
    " in another terminal, then click login and watch traces/logs appear."
  ),
  actionButton("login", "Login with GitHub"),
  tags$hr(),
  uiOutput("oauth_error"),
  verbatimTextOutput("auth_status"),
  verbatimTextOutput("userinfo")
)

server <- function(input, output, session) {
  auth <- oauth_module_server(
    id = "auth",
    client = client,
    auto_redirect = FALSE,
    async = TRUE
  )

  observeEvent(input$login, {
    auth$request_login()
  })

  output$oauth_error <- renderUI({
    if (is.null(auth$error)) {
      return(NULL)
    }

    msg <- auth$error
    if (!is.null(auth$error_description)) {
      msg <- paste0(msg, ": ", auth$error_description)
    }

    div(class = "alert alert-danger", role = "alert", msg)
  })

  output$auth_status <- renderPrint({
    list(
      authenticated = auth$authenticated,
      has_token = !is.null(auth$token),
      error = auth$error,
      error_description = auth$error_description,
      expires_at = if (!is.null(auth$token)) auth$token@expires_at else NULL
    )
  })

  output$userinfo <- renderPrint({
    req(auth$token)
    auth$token@userinfo
  })

  onStop(function() {
    try(otel::get_default_tracer_provider()$flush(), silent = TRUE)
  })
}

shiny::runApp(
  shinyApp(ui, server),
  port = 8100
)
