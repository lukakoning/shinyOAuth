# Create an authentik [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure login for an authentik OAuth2/OIDC application. Supply the
instance URL and application slug, then pass the registered credentials
to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with the scopes configured in authentik.

## Usage

``` r
oauth_provider_authentik(
  base_url,
  application_slug,
  name = "authentik",
  token_auth_style = NULL
)
```

## Arguments

- base_url:

  authentik instance URL, for example `"https://auth.example.com"`.

- application_slug:

  Application slug configured in authentik (not the display name or
  client ID).

- name:

  Optional provider name (default `"authentik"`).

- token_auth_style:

  Authentication style for token requests: "header"
  (client_secret_basic), "body" (client_secret_post), or "public"
  (public client; send `client_id` only). The alias `"none"` is also
  accepted for `"public"`. If NULL (default), it is inferred
  conservatively from discovery: `"header"` (client_secret_basic) is
  preferred, followed by `"body"` (client_secret_post), then `"public"`
  if `none` is advertised and PKCE is enabled. Set
  `token_auth_style = "public"` explicitly for a public client
  registration. JWT methods (`"client_secret_jwt"`, `"private_key_jwt"`)
  and mTLS methods (`"tls_client_auth"`,
  `"self_signed_tls_client_auth"`) must be selected explicitly. See
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  for the supported methods and their credentials.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for the authentik application.

## Details

Uses authentik's default per-application issuer mode and preserves its
trailing slash. Global issuer mode is not supported by this preset;
configure the endpoints explicitly with
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
for that mode. For refresh tokens, both request `"offline_access"` and
enable the corresponding scope mapping in authentik. Configure a signing
key that supports RS256 for OIDC discovery. See [authentik's provider
guide](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_authentik("https://auth.example.com", "shiny-app")
} # }
```
