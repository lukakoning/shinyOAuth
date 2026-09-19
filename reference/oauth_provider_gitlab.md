# Create a GitLab [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure OIDC sign-in with GitLab.com or a self-managed GitLab
instance. Register an OAuth application on that instance, then pass its
credentials to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with `scopes = c("openid", "profile", "email")`.

## Usage

``` r
oauth_provider_gitlab(
  base_url = "https://gitlab.com",
  name = "gitlab",
  token_auth_style = NULL
)
```

## Arguments

- base_url:

  GitLab instance URL, including HTTPS and any deployment subpath.
  Defaults to `"https://gitlab.com"`.

- name:

  Optional provider name (default `"gitlab"`).

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
object configured for GitLab.

## Details

Supply only the scopes your app needs; `"openid"` is enough to request
an ID token. API and repository access require separate GitLab scopes.
See [GitLab's OIDC
guide](https://docs.gitlab.com/integration/openid_connect_provider/).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_gitlab()
oauth_provider_gitlab("https://gitlab.example.edu")
} # }
```
