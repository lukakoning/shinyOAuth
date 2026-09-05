# Create a Slack [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Look up Slack's OpenID Connect settings for Sign in with Slack. This
helper contacts the discovery service during setup; pass its result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with your Slack app credentials.

## Usage

``` r
oauth_provider_slack(
  name = "slack",
  profile = c("confidential", "public_pkce")
)
```

## Arguments

- name:

  Optional provider name (default "slack")

- profile:

  Slack app registration profile: `"confidential"` (default) uses HTTP
  Basic and OIDC nonce validation without PKCE; `"public_pkce"` uses
  S256 PKCE and sends no client secret. Select the public profile only
  after enabling PKCE for that Slack app. Slack marks the app public,
  and reversing that registration setting requires contacting Slack
  support. See <https://docs.slack.dev/authentication/using-pkce/>.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Slack

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_slack()
} # }
```
