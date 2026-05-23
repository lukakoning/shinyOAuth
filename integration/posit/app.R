library(shiny)
library(shinyOAuth)


# 1 GitHub OAuth client -------------------------------------------------------

provider <- oauth_provider_github()

client_id <- Sys.getenv("GITHUB_OAUTH_CLIENT_ID", "")
client_secret <- Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
redirect_uri <- Sys.getenv("OAUTH_REDIRECT_URI", "")

required_env <- c(
  GITHUB_OAUTH_CLIENT_ID = nzchar(client_id),
  GITHUB_OAUTH_CLIENT_SECRET = nzchar(client_secret),
  OAUTH_REDIRECT_URI = nzchar(redirect_uri)
)
missing_env <- names(required_env)[!required_env]

redirect_uri_is_posit_cloud_content_url <- grepl(
  "^https://connect\\.posit\\.cloud/[^/]+/content/",
  redirect_uri
)

client <- if (length(missing_env) == 0) {
  oauth_client(
    provider = provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = redirect_uri,
    scopes = character(0)
  )
} else {
  NULL
}


# 2 Shiny app -----------------------------------------------------------------

ui <- fluidPage(
  use_shinyOAuth(),
  titlePanel("shinyOAuth on Posit Connect Cloud"),
  p(
    paste(
      "This is a minimal GitHub authentication example for Posit Connect",
      "Cloud. Use a top-level app URL as OAUTH_REDIRECT_URI and in your",
      "GitHub OAuth app. That URL can be a claimed Posit Connect Cloud",
      "URL or your own custom domain, but it should not be the default",
      "embedded content URL."
    )
  ),
  if (isTRUE(redirect_uri_is_posit_cloud_content_url)) {
    div(
      class = "alert alert-danger",
      role = "alert",
      tags$p(
        "OAUTH_REDIRECT_URI points at the default embedded Connect Cloud content URL."
      ),
      tags$p(
        paste(
          "Use a top-level app URL instead, either a claimed Posit Connect",
          "Cloud URL or your own custom domain, and register that same URL",
          "in the GitHub OAuth callback configuration."
        )
      )
    )
  },
  if (is.null(client)) {
    div(
      class = "alert alert-warning",
      role = "alert",
      tags$p(
        "Login is disabled until the required environment variables are set."
      ),
      tags$ul(
        lapply(missing_env, function(var) tags$li(tags$code(var)))
      ),
      tags$p(
        "The GitHub OAuth callback URL must exactly match OAUTH_REDIRECT_URI."
      )
    )
  } else {
    uiOutput("login_controls")
  },
  uiOutput("oauth_error"),
  tags$hr(),
  h4("Auth summary"),
  verbatimTextOutput("auth_print"),
  tags$hr(),
  h4("User info"),
  verbatimTextOutput("user_info")
)

server <- function(input, output, session) {
  if (is.null(client)) {
    output$auth_print <- renderText({
      paste(
        c(
          "Missing OAuth configuration.",
          "",
          "Required environment variables:",
          paste0("- ", missing_env),
          "",
          paste0(
            "Configured redirect URI: ",
            if (nzchar(redirect_uri)) redirect_uri else "<unset>"
          )
        ),
        collapse = "\n"
      )
    })

    output$user_info <- renderText({
      "No user information is available until GitHub OAuth is configured."
    })

    output$oauth_error <- renderUI(NULL)

    return(invisible(NULL))
  }

  auth <- oauth_module_server("auth", client, auto_redirect = FALSE)

  observeEvent(input$login_btn, ignoreInit = TRUE, {
    auth$request_login()
  })

  observeEvent(input$logout_btn, ignoreInit = TRUE, {
    auth$logout()
  })

  output$login_controls <- renderUI({
    if (isTRUE(auth$authenticated)) {
      return(
        div(
          style = "margin-bottom: 1rem;",
          actionButton("logout_btn", "Logout", class = "btn-default")
        )
      )
    }

    div(
      style = "margin-bottom: 1rem;",
      actionButton("login_btn", "Login with GitHub", class = "btn-primary")
    )
  })

  output$auth_print <- renderText({
    token <- auth$token
    refresh_token <- if (!is.null(token)) token@refresh_token else NULL
    id_token <- if (!is.null(token)) token@id_token else NA_character_

    paste0(
      "Authenticated? ",
      if (isTRUE(auth$authenticated)) "YES" else "NO",
      "\n",
      "Has token? ",
      if (!is.null(token)) "YES" else "NO",
      "\n",
      "Has error? ",
      if (!is.null(auth$error)) "YES" else "NO",
      "\n\n",
      "Token present: ",
      !is.null(token),
      "\n",
      "Has refresh token: ",
      !is.null(refresh_token) && nzchar(refresh_token),
      "\n",
      "Has ID token: ",
      !is.na(id_token),
      "\n",
      "Expires at: ",
      if (!is.null(token)) token@expires_at else "N/A"
    )
  })

  output$user_info <- renderPrint({
    req(isTRUE(auth$authenticated), !is.null(auth$token))
    auth$token@userinfo
  })

  output$oauth_error <- renderUI({
    if (is.null(auth$error)) {
      return(NULL)
    }

    message <- if (identical(auth$error, "access_denied")) {
      "Sign-in was canceled or denied. Please try again."
    } else {
      auth$error_description %||%
        "Authentication failed. Please try again."
    }

    div(class = "alert alert-danger", role = "alert", message)
  })
}

shinyApp(ui = ui, server = server)
