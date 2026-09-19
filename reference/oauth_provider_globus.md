# Create a Globus Auth [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Configure OIDC sign-in with Globus Auth using its published endpoints
and RS512 ID token signatures. Register a confidential web application
at <https://app.globus.org/settings/developers> and request
`scopes = c("openid", "profile", "email")` on
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

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

This preset does not make a discovery request. Globus currently
advertises RS512 only, whereas generic OIDC discovery requires
advertised RS256 support. The preset pins RS512 and the Globus JWKS URL,
retaining signature, issuer, audience, nonce, UserInfo subject, and S256
PKCE validation.

This helper supports OIDC login. Globus API grants can return separate
credentials for several resource servers in `other_tokens`. Those fields
are preserved in `token@extra_fields`, but shinyOAuth does not
automatically select, refresh, or revoke the nested tokens. Keep this
login client's scopes limited to `openid`, `profile`, `email`, and
optionally `offline_access`; use a separate Globus-aware integration for
multi-resource API authorization. Never send the login access token to
another resource server merely because a nested token granted access to
it.

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
