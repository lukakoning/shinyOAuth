# Create a Google [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Use your Google app registration with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
to add Google sign-in. The helper configures OIDC validation and profile
retrieval.

## Usage

``` r
oauth_provider_google(name = "google")
```

## Arguments

- name:

  Optional provider name (default "google")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object for use with a Google OAuth 2.0 app

## Details

You can register a new Google OAuth 2.0 app in the [Google Cloud
Console](https://console.cloud.google.com/apis/credentials). Configure
the client ID & secret in your
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md).

## Examples

``` r
oauth_provider_google()
#> <shinyOAuth::OAuthProvider>
#>  @ name               : chr "google"
#>  @ auth_url           : chr "https://accounts.google.com/"
#>  @ token_url          : chr "https://oauth2.googleapis.com/"
#>  @ issuer             : chr "https://accounts.google.com/"
#>  @ userinfo_url       : chr "https://openidconnect.googleapis.com/"
#>  @ jwks_uri           : NA
#>  @ introspection_url  : NA
#>  @ revocation_url     : chr "https://oauth2.googleapis.com/"
#>  @ token_auth_style   : chr "header"
#>  @ use_pkce           : logi TRUE
#>  @ use_nonce          : logi TRUE
#>  @ extra_auth_params  : list [1] (access_type)
#>  @ extra_token_params : list()
#>  @ extra_token_headers: list()
```
