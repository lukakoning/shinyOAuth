# Create a SURFconext [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure institutional OIDC login through SURFconext. Register your
service with SURFconext before using its client credentials with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

## Usage

``` r
oauth_provider_surfconext(
  environment = c("production", "test"),
  name = "surfconext",
  token_auth_style = NULL
)
```

## Arguments

- environment:

  SURFconext environment: `"production"` (default) or `"test"`.

- name:

  Optional provider name (default `"surfconext"`).

- token_auth_style:

  Authentication style for token requests: "header"
  (client_secret_basic), "body" (client_secret_post), or "public"
  (public client; send `client_id` only). The alias `"none"` is also
  accepted for `"public"`. If NULL (default), it is inferred
  conservatively from discovery: `"header"` (client_secret_basic) is
  preferred, followed by `"body"` (client_secret_post), then `"public"`
  if `none` is advertised and PKCE is enabled. Set
  `token_auth_style = "public"` explicitly for a public client
  registration. JWT methods (`"client_secret_jwt"`, `"private_key_jwt"`)
  and mTLS methods (`"tls_client_auth"`,
  `"self_signed_tls_client_auth"`) must be selected explicitly. See
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  for the supported methods and their credentials.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for SURFconext.

## Details

Request the `"openid"` scope. Additional claims depend on your service's
agreed attribute release policy; requesting `"email"` or `"profile"`
does not guarantee those attributes will be released. Use the validated
issuer and `sub` to identify a user, rather than assuming email is
present. Test and production environments require their own service
configuration. See [SURFconext for service
providers](https://servicedesk.surf.nl/wiki/spaces/IAM/pages/128909810/SURFconext+for+Service+Providers).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_surfconext()
oauth_provider_surfconext(environment = "test")
} # }
```
