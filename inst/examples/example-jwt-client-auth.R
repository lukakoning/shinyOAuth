# Examples: JWT client authentication at the token endpoint
#
# Note: These examples demonstrate configuring the client for RFC 7523
# client assertions. You will need to provide valid credentials and a
# provider that supports the selected method.

# client_secret_jwt (HMAC) ----------------------------------------------------
prov_jwt_hs <- oauth_provider(
  name = "example-oidc",
  auth_url = "https://issuer.example.com/oauth2/authorize",
  token_url = "https://issuer.example.com/oauth2/token",
  issuer = "https://issuer.example.com",
  use_nonce = TRUE,
  token_auth_style = "client_secret_jwt"
)

client_hs <- oauth_client(
  provider = prov_jwt_hs,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://localhost:8100",
  scopes = c("openid", "profile")
)

# private_key_jwt (asymmetric) -----------------------------------------------
prov_jwt_pk <- oauth_provider(
  name = "example-oidc",
  auth_url = "https://issuer.example.com/oauth2/authorize",
  token_url = "https://issuer.example.com/oauth2/token",
  issuer = "https://issuer.example.com",
  use_nonce = TRUE,
  token_auth_style = "private_key_jwt"
)

# Supply an RSA/EC private key (PEM or openssl::key)
# See openssl::read_key("path/to/key.pem")
client_pk <- oauth_client(
  provider = prov_jwt_pk,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = "", # not used for private_key_jwt
  client_private_key = Sys.getenv("OAUTH_CLIENT_PRIVATE_KEY_PEM"),
  client_private_key_kid = Sys.getenv("OAUTH_CLIENT_KEY_KID"),
  redirect_uri = "http://localhost:8100",
  scopes = c("openid", "profile")
)
