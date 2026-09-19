# Create an Amazon Cognito [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure OIDC login for an Amazon Cognito user pool. Register an app
client with the authorization code grant, configure a user pool login
domain, and pass the app credentials to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
with the enabled OIDC scopes.

## Usage

``` r
oauth_provider_cognito(issuer, name = "cognito", token_auth_style = NULL)
```

## Arguments

- issuer:

  Exact user pool issuer URL from AWS, for example
  `"https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example"`.

- name:

  Optional provider name (default `"cognito"`).

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
object configured for a Cognito user pool.

## Details

Use the exact user pool issuer, not the managed-login or custom domain.
Discovery obtains authorization, token, and UserInfo URLs on that login
domain while retaining the pool issuer for ID token validation. Both the
original `cognito-idp` and updated `issuer-cognito-idp` issuer forms are
supported, as are AWS partition-specific hostnames. No AWS credentials
are needed for discovery.

See [Cognito
endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_cognito(
  "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example"
)
} # }
```
