# Create an Auth0 [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Look up login settings for your Auth0 domain. Pass the result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with your registered app credentials. This helper makes a discovery
request during setup.

## Usage

``` r
oauth_provider_auth0(domain, name = "auth0", audience = NULL)
```

## Arguments

- domain:

  Your Auth0 domain, e.g., "your-domain.auth0.com"

- name:

  Optional provider name (default "auth0")

- audience:

  Optional audience value to send in authorization requests.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for the specified Auth0 domain

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_auth0("your-domain.auth0.com")
} # }
```
