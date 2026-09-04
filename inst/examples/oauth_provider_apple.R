# Sign in with Apple requires an Apple Services ID, Team ID, key ID, and the
# corresponding P-256 private key. Network access is required for discovery.
if (interactive()) {
  apple_provider <- oauth_provider_apple()

  apple_secret <- oauth_client_secret_apple(
    client_id = "com.example.web",
    team_id = "ABCDEFGHIJ",
    key_id = "ABC123DEFG",
    private_key = openssl::read_key("AuthKey_ABC123DEFG.p8")
  )

  apple_client <- oauth_client(
    provider = apple_provider,
    client_id = "com.example.web",
    client_secret = apple_secret,
    redirect_uri = "https://example.com/oauth/callback",
    scopes = c("openid", "email", "name"),
    response_mode = "form_post"
  )
}
