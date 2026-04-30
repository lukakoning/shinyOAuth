# devtools::load_all()

library(shinyOAuth)
library(shiny)
library(otel)
library(otelsdk)

options(
  shinyOAuth.otel_tracing_enabled = TRUE,
  shinyOAuth.otel_logging_enabled = TRUE
)

setup_otel_tui <- function(
  endpoint = Sys.getenv("OTEL_TUI_ENDPOINT", "http://127.0.0.1:4318")
) {
  base_url <- sub("/+$", "", endpoint)

  # Make the example robust after prior test/dev sessions that may have left
  # noop providers or disabled shinyOAuth's own telemetry gates behind.
  # Configure via environment so mirai workers inherit the same exporters.
  Sys.setenv(
    OTEL_R_TRACES_EXPORTER = "http",
    OTEL_R_LOGS_EXPORTER = "http",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_TRACES_EXPORTER = "http",
    OTEL_LOGS_EXPORTER = "http",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_ENDPOINT = base_url,
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = paste0(base_url, "/v1/traces"),
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT = paste0(base_url, "/v1/logs")
  )

  # Clear otel's internal cache so it re-detects exporters from the env vars.
  otel_clean_cache <- tryCatch(
    get("otel_clean_cache", envir = asNamespace("otel"), inherits = FALSE),
    error = function(...) NULL
  )
  if (is.function(otel_clean_cache)) {
    otel_clean_cache()
  }

  invisible(base_url)
}

otel_endpoint <- setup_otel_tui()
message(
  "shinyOAuth OTel: tracing=",
  getOption("shinyOAuth.otel_tracing_enabled"),
  ", logging=",
  getOption("shinyOAuth.otel_logging_enabled"),
  ", otel tracing=",
  otel::is_tracing_enabled(),
  ", otel logging=",
  otel::is_logging_enabled()
)
try(mirai::daemons(0), silent = TRUE)
mirai::daemons(2)
mirai::everywhere(setup_otel_tui())

provider <- oauth_provider_github()

client_id <- Sys.getenv("GITHUB_OAUTH_CLIENT_ID", "")
client_secret <- Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
app_port <- as.integer(Sys.getenv("GITHUB_OAUTH_APP_PORT", "8101"))
redirect_uri <- Sys.getenv(
  "GITHUB_OAUTH_REDIRECT_URI",
  paste0("http://127.0.0.1:", app_port)
)

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

  observeEvent(
    list(auth$error, auth$error_description),
    {
      if (interactive() && !is.null(auth$error_description)) {
        rlang::inform(c(
          "OAuth error details",
          "i" = paste0("error: ", auth$error),
          "i" = paste0("error_description: ", auth$error_description)
        ))
      }
    },
    ignoreInit = TRUE
  )

  output$oauth_error <- renderUI({
    if (is.null(auth$error)) {
      return(NULL)
    }

    msg <- if (identical(auth$error, "access_denied")) {
      "Sign-in was canceled or denied. Please try again."
    } else {
      "Authentication failed. Please try again."
    }

    div(class = "alert alert-danger", role = "alert", msg)
  })

  output$auth_status <- renderPrint({
    list(
      authenticated = auth$authenticated,
      has_token = !is.null(auth$token),
      error = auth$error,
      has_error_description = !is.null(auth$error_description),
      expires_at = if (!is.null(auth$token)) auth$token@expires_at else NULL
    )
  })

  output$userinfo <- renderPrint({
    req(auth$token)
    auth$token@userinfo
  })

  onStop(function() {
    try(otel::get_default_tracer_provider()$flush(), silent = TRUE)
    try(otel::get_default_logger_provider()$flush(), silent = TRUE)
    try(mirai::daemons(0), silent = TRUE)
  })
}

shiny::runApp(
  shinyApp(ui, server),
  port = app_port
)
