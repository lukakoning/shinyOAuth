if (
  # Example requires configured GitHub OAuth 2.0 app
  # (go to https://github.com/settings/developers to create one):
  nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_ID")) 
  && nzchar(Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"))
  && interactive()
) {
  library(shiny)
  library(shinyOAuth)
  
  # Define client
  client <- oauth_client(
    provider = oauth_provider_github(),
    client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100"
  )
  
  # Choose which app you want to run
  app_to_run <- NULL
  while (!isTRUE(app_to_run %in% c(1:4))) {
    app_to_run <- readline(
      prompt = paste0(
        "Which example app do you want to run?\n",
        "  1: Auto-redirect login\n",
        "  2: Manual login button\n",
        "  3: Fetch additional resource with access token\n",
        "  4: No app (all will be defined but none run)\n",
        "Enter 1, 2, 3, or 4... "
      )
    )
  }
  
  
  # Example app with auto-redirect (1) -----------------------------------------
  
  ui_1 <- fluidPage(
    use_shinyOAuth(),
    uiOutput("login")
  )
  
  server_1 <- function(input, output, session) {
    # Auto-redirect (default):
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = TRUE
    )
    
    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }
  
  app_1 <- shinyApp(ui_1, server_1)
  if (app_to_run == "1") {
    runApp(app_1, port = 8100)
  }
  
  
  # Example app with manual login button (2) -----------------------------------
  
  ui_2 <- fluidPage(
    use_shinyOAuth(),
    actionButton("login_btn", "Login"),
    uiOutput("login")
  )
  
  server_2 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE
    )
    
    observeEvent(input$login_btn, {
      auth$request_login()
    })
    
    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }
  
  app_2 <- shinyApp(ui_2, server_2)
  if (app_to_run == "2") {
    runApp(app_2, port = 8100)
  }
  

  # Example app requesting additional resource with access token (3) -----------
  
  # Below app shows the authenticated username + their GitHub repositories,
  # fetched via GitHub API using the access token obtained during login
  
  ui_3 <- fluidPage(
    use_shinyOAuth(),
    uiOutput("ui")
  )
  
  server_3 <- function(input, output, session) {
    auth <- oauth_module_server(
      "auth",
      client,
      auto_redirect = TRUE
    )
    
    repositories <- reactiveVal(NULL)
    
    observe({
      req(auth$authenticated)
      
      # Example additional API request using the access token
      # (e.g., fetch user repositories from GitHub)
      req <- client_bearer_req(auth$token, "https://api.github.com/user/repos")
      resp <- httr2::req_perform(req)
      
      if (httr2::resp_is_error(resp)) {
        repositories(NULL)
      } else {
        repos_data <- httr2::resp_body_json(resp, simplifyVector = TRUE)
        repositories(repos_data)
      }
    })
    
    # Render username + their repositories
    output$ui <- renderUI({
      if (isTRUE(auth$authenticated)) {
        user_info <- auth$token@userinfo
        repos <- repositories()
        
        return(tagList(
          tags$p(paste("You are logged in as:", user_info$login)),
          tags$h4("Your repositories:"),
          if (!is.null(repos)) {
            tags$ul(
              Map(function(url, name) {
                tags$li(tags$a(href = url, target = "_blank", name))
              }, repos$html_url, repos$full_name)
            )
          } else {
            tags$p("Loading repositories...")
          }
        ))
      }
      
      return(tags$p("You are not logged in."))
    })
  }
  
  app_3 <- shinyApp(ui_3, server_3)
  if (app_to_run == "3") {
    runApp(app_3, port = 8100)
  }
}
