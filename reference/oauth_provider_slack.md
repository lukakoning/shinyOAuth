# Create a Slack [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Look up Slack's OpenID Connect settings for Sign in with Slack. This
helper contacts the discovery service during setup; pass its result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with your Slack app credentials.

## Usage

``` r
oauth_provider_slack(name = "slack")
```

## Arguments

- name:

  Optional provider name (default "slack")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Slack

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_slack()
} # }
```
