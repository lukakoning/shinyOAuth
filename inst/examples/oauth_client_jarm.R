provider <- oauth_provider(
  name = "Example OIDC",
  auth_url = "https://issuer.example.com/authorize",
  token_url = "https://issuer.example.com/token",
  issuer = "https://issuer.example.com",
  jwks_uri = "https://issuer.example.com/jwks",
  token_auth_style = "public",
  use_pkce = TRUE
)

# 'jwt' configured with a signed response:
client <- oauth_client(
  provider = provider,
  client_id = "shiny-public",
  client_secret = "",
  redirect_uri = "http://127.0.0.1:8100/callback",
  scopes = c("openid", "profile"),
  response_mode = "jwt",
  jarm_signed_response_alg = "RS256"
)

# 'form_post.jwt' configured with a signed and encrypted response.
# (Note: this also requires use of `oauth_form_post_ui()`)
# Register the matching public key with the provider before using this client.
jarm_decryption_private_key <- openssl::rsa_keygen(bits = 2048)
encrypted_client <- oauth_client(
  provider = provider,
  client_id = "shiny-public",
  client_secret = "",
  redirect_uri = "http://127.0.0.1:8100/callback",
  scopes = c("openid", "profile"),
  response_mode = "form_post.jwt",
  jarm_signed_response_alg = "RS256",
  jarm_encrypted_response_alg = "RSA-OAEP",
  jarm_encrypted_response_enc = "A256CBC-HS512",
  jarm_decryption_private_key = jarm_decryption_private_key,
  jarm_decryption_private_key_kid = "jarm-enc-1"
)
