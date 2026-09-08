# Advanced example: your code supplies browser redirects and callback handling.
# For a Shiny app, oauth_module_server() manages these steps for you.

if (interactive()) {
  # Define client
  client <- oauth_client(
    provider = oauth_provider_github(),
    client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100"
  )

  # Get the login URL and store state in client's state store
  # `<browser_token>` must be unpredictable and persisted for this transaction
  # in storage bound to the application's exact origin (scheme, host, port).
  # The module combines origin-scoped storage with an independent marker cookie
  # and checks both on return. A cookie alone does not provide this boundary:
  # cookies can be shared by applications on different ports of the same host.
  # Shiny applications should use oauth_module_server() for the complete flow.
  authorization_url <- prepare_call(client, "<browser_token>")

  # Redirect user to authorization URL; retrieve code & state from the query;
  # recover this transaction's `<browser_token>` through the origin-bound flow
  # and verify its independent marker before calling handle_callback().
  code <- "..."
  state <- "..."
  browser_token <- "..."

  # Handle callback, exchanging code for token and validating state
  token <- handle_callback(client, code, state, browser_token)
}
