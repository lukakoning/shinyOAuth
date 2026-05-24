# Minimal signed-JARM configuration example.
#
# These `authorization_*_response_*` settings describe the provider-side
# client metadata and callback behavior that shinyOAuth should expect; they are
# not emitted dynamically as authorization-request parameters.

provider <- oauth_provider(
  name = "Example OIDC",
  auth_url = "https://issuer.example.com/authorize",
  token_url = "https://issuer.example.com/token",
  issuer = "https://issuer.example.com",
  response_modes_supported = c("jwt", "form_post.jwt"),
  authorization_signing_alg_values_supported = "RS256"
)

client <- oauth_client(
  provider = provider,
  client_id = "shiny-public",
  client_secret = "",
  redirect_uri = "http://127.0.0.1:8100/callback",
  scopes = c("openid", "profile"),
  response_mode = "jwt",
  authorization_signed_response_alg = "RS256"
)

# For encrypted JARM, add the provider's advertised encryption metadata and
# configure the matching client expectations plus the private decryption key.
