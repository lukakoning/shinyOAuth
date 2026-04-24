# Please note: `get_userinfo()`, `introspect_token()`, and `refresh_token()`
# are typically not called by users of this package directly, but are called
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Example requires a real token from a completed OAuth flow
# (code is therefore not run; would error with placeholder values below)
\dontrun{
# Define client
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100"
)

# Have a valid OAuthToken object; fake example below
# (typically provided by `oauth_module_server()` or `handle_callback()`)
token <- handle_callback(client, "<code>", "<payload>", "<browser_token>")

# Get userinfo
user_info <- get_userinfo(client, token)

# Introspect token (if supported by provider)
introspection <- introspect_token(client, token)

# Refresh token
new_token <- refresh_token(client, token, introspect = TRUE)
}
