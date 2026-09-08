# Create a GitHub [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Create the provider configuration for a GitHub OAuth App, then pass it
with your app credentials to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
This configures profile retrieval from GitHub's API; GitHub does not
return an OIDC ID token.

## Usage

``` r
oauth_provider_github(name = "github")
```

## Arguments

- name:

  Optional provider name (default "github")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object for use with a GitHub OAuth 2.0 app

## Details

You can register a new GitHub OAuth 2.0 app in your [OAuth App
settings](https://github.com/settings/developers).

## Examples

``` r
oauth_provider_github()
#> <shinyOAuth::OAuthProvider>
#>  @ name               : chr "github"
#>  @ auth_url           : chr "https://github.com/"
#>  @ token_url          : chr "https://github.com/"
#>  @ issuer             : NA
#>  @ userinfo_url       : chr "https://api.github.com/"
#>  @ jwks_uri           : NA
#>  @ introspection_url  : NA
#>  @ revocation_url     : NA
#>  @ token_auth_style   : chr "body"
#>  @ use_pkce           : logi TRUE
#>  @ use_nonce          : logi FALSE
#>  @ extra_auth_params  : list()
#>  @ extra_token_params : list()
#>  @ extra_token_headers: list [1] (Accept)
```
