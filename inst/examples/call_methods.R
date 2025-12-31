# Please note: `prepare_call()` & `handle_callback()` are typically
# not called by users of this package directly, but are called 
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Below code shows generic usage of `prepare_call()` and `handle_callback()`
# (code is not run because it would require user interaction)
\dontrun{
# Define client
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100"
)

# Get authorization URL and and store state in client's state store
# `<browser_token>` is a token that identifies the browser session
#  and would typically be stored in a browser cookie
#  (`oauth_module_server()` handles this typically)
authorization_url <- prepare_call(client, "<browser_token>")

# Redirect user to authorization URL; retrieve code & payload from query;
# read also `<browser_token>` from browser cookie
# (`oauth_module_server()` handles this typically)
code <- "..."
payload <- "..."
browser_token <- "..."

# Handle callback, exchanging code for token and validating state
# (`oauth_module_server()` handles this typically)
token <- handle_callback(client, code, payload, browser_token)
}
