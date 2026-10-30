# Configure researcher sign-in with ORCID

Let users sign in with their ORCID account. Register your app with
ORCID, then pass this provider, the client ID and client secret to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with `scopes = "openid"`.

## Usage

``` r
oauth_provider_orcid(name = "orcid", sandbox = FALSE)
```

## Arguments

- name:

  Optional provider name (default `"orcid"`).

- sandbox:

  Logical; use ORCID's sandbox instead of production.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for ORCID.

## Details

ORCID's OIDC login uses the `openid` scope; `/authenticate` is its
separate OAuth login scope. Its OIDC metadata does not advertise
`profile` or `email` scopes. Additional record permissions depend on
whether you registered a Public or Member API client.

Sandbox and production require separate credentials and user accounts.
Production redirect URIs must use HTTPS.

## Advanced registration settings

This preset uses `client_secret_post` authentication. ORCID does not
advertise PKCE, so the helper uses client authentication and OIDC nonce
validation without PKCE. See the [ORCID authentication
guide](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_orcid()
oauth_provider_orcid(sandbox = TRUE)
} # }
```
