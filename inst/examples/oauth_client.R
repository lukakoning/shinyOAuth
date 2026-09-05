# Register an app with GitHub and store its credentials in your environment.
# This creates the configuration; it does not start login or contact GitHub.
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = "your-client-id",
  client_secret = "your-client-secret",
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

# In a real app, read credentials with Sys.getenv() and create client
# outside server(). Inside server(), start login with:
# auth <- oauth_module_server("auth", client)
