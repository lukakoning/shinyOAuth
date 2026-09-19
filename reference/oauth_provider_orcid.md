# Create an ORCID [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure researcher sign-in with ORCID. Discovery selects ORCID's
`client_secret_post` authentication; pass a client secret to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

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

Request `scopes = "openid"` on the client. ORCID uses this instead of
`/authenticate` for OIDC login; do not request both. Its OIDC metadata
does not advertise `profile` or `email` scopes. Additional record
permissions depend on whether you registered a Public or Member API
client.

Sandbox and production require separate credentials and user accounts.
Production redirect URIs must use HTTPS. ORCID does not advertise PKCE
in its discovery metadata, so this confidential-client preset uses
client authentication and validated OIDC nonce without claiming PKCE
protection. See the [ORCID authentication
guide](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_orcid()
oauth_provider_orcid(sandbox = TRUE)
} # }
```
