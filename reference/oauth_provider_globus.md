# Configure sign-in with Globus Auth

Let users sign in with Globus Auth. Register a web application with a
client secret at <https://app.globus.org/settings/developers>, then pass
this provider and the credentials to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with `scopes = c("openid", "profile", "email")`.

## Usage

``` r
oauth_provider_globus(name = "globus")
```

## Arguments

- name:

  Optional provider name (default `"globus"`).

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Globus Auth login.

## Details

This helper supports OIDC login. Globus API grants can return separate
credentials for several resource servers in `other_tokens`. Those fields
are preserved in `token@extra_fields`, but shinyOAuth does not
automatically select, refresh, or revoke the nested tokens. The
supported login scopes are `openid`, `profile`, `email` and optionally
`offline_access`. Multi-resource API authorization needs a Globus-aware
integration that manages each resource server's separate token.

## Advanced provider settings

The preset uses Globus's published endpoints and RS512 identity-token
signatures. It does not use generic discovery, which requires advertised
RS256 support.

See the [Globus Auth
guide](https://docs.globus.org/api/auth/developer-guide/).

## Examples

``` r
oauth_provider_globus()
#> <shinyOAuth::OAuthProvider>
#>  @ name               : chr "globus"
#>  @ auth_url           : chr "https://auth.globus.org/"
#>  @ token_url          : chr "https://auth.globus.org/"
#>  @ issuer             : chr "https://auth.globus.org/"
#>  @ userinfo_url       : chr "https://auth.globus.org/"
#>  @ jwks_uri           : chr "https://auth.globus.org/"
#>  @ introspection_url  : NA
#>  @ revocation_url     : chr "https://auth.globus.org/"
#>  @ token_auth_style   : chr "header"
#>  @ use_pkce           : logi TRUE
#>  @ use_nonce          : logi TRUE
#>  @ extra_auth_params  : list()
#>  @ extra_token_params : list()
#>  @ extra_token_headers: list()
```
