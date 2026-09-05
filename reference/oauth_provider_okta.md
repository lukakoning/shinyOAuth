# Create an Okta [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Look up login settings for your Okta domain and authorization server.
Pass the result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with your registered app credentials. This helper makes a discovery
request during setup.

## Usage

``` r
oauth_provider_okta(domain, auth_server = "default", name = "okta")
```

## Arguments

- domain:

  Your Okta domain, e.g., "dev-123456.okta.com"

- auth_server:

  Authorization server ID for a custom authorization server (default
  "default"). Use `NULL` to target the org authorization server at
  `https://{yourOktaDomain}`.

- name:

  Optional provider name (default "okta")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for the specified Okta domain

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_okta("dev-123456.okta.com")
} # }
```
