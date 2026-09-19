# Remind developers to start OAuth in a top-level browser tab.
# Product markers also work for deployments with custom domains. Match Posit's
# connectapi detection: https://github.com/rstudio/connectapi/blob/main/R/utils.R
warn_about_browser_deployment <- function() {
  if (.is_test()) {
    return(invisible(NULL))
  }

  product <- Sys.getenv("POSIT_PRODUCT")
  on_connect_cloud <- identical(product, "CONNECT_CLOUD")
  on_connect <- identical(product, "CONNECT") ||
    identical(Sys.getenv("RSTUDIO_PRODUCT"), "CONNECT")

  if (on_connect_cloud || on_connect) {
    warn_pkg(
      "Open your Posit Connect app at its direct URL",
      c(
        "!" = paste0(
          "Posit Connect deployment detected. OAuth redirects may fail in ",
          "the dashboard's embedded app preview."
        ),
        "i" = paste0(
          "Copy the direct app URL and paste it into a new browser tab or ",
          "window before starting login. On Connect Cloud, copy the sharing ",
          "URL from Settings > URL."
        ),
        "i" = paste0(
          "Bad Connect Cloud example (dashboard preview): ",
          "https://connect.posit.cloud/<account>/content/<content-id>"
        ),
        "i" = paste0(
          "Good Connect Cloud example (app sharing URL): ",
          "https://<content-id>.share.connect.posit.cloud ",
          "(or your configured custom app URL). Replace the placeholders ",
          "with your app's actual URL from Settings > URL."
        ),
        "i" = paste0(
          "Register the exact public callback URL with your provider; ",
          "the dashboard URL is not a callback URL. A dedicated callback ",
          "path is not necessarily the app's entry point."
        )
      ),
      .frequency = "once",
      .frequency_id = "oauth_module_server_remind_posit_connect"
    )
  } else {
    warn_pkg(
      "Open your Shiny app in a regular browser",
      c(
        "!" = "`oauth_module_server()` was called; view your app in a standard web browser (e.g., Chrome, Firefox, Safari)",
        "i" = "Viewers in RStudio/Positron/etc. cannot perform necessary redirects for OAuth 2.0 flows"
      ),
      .frequency = "once",
      .frequency_id = "oauth_module_server_remind_browser"
    )
  }

  invisible(TRUE)
}
