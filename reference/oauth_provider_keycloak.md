# Create a Keycloak [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Look up login settings for a Keycloak realm. Supply your server URL and
realm name, then pass the result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
This helper contacts the Keycloak server during setup.

## Usage

``` r
oauth_provider_keycloak(
  base_url,
  realm,
  name = paste0("keycloak-", realm),
  token_auth_style = "body",
  jarm_tolerate_duplicate_top_level_iss = TRUE
)
```

## Arguments

- base_url:

  Base URL of the Keycloak server, e.g., "http://localhost:8080". Local
  HTTP development also requires
  `options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)`.

- realm:

  Keycloak realm name, e.g., "myrealm"

- name:

  Optional provider name. Defaults to `paste0('keycloak-', realm)`

- token_auth_style:

  Optional override for token endpoint authentication method. One of
  "header" (client_secret_basic), "body" (client_secret_post), "public"
  (send `client_id` only; `"none"` alias also accepted),
  "private_key_jwt", or "client_secret_jwt". Defaults to "body" for
  Keycloak, which works for many common setups. Use `"public"` if you
  need to suppress `client_secret` even when it is set in the
  environment. If you pass `NULL`, discovery will infer the method from
  the provider's `token_endpoint_auth_methods_supported` metadata.

- jarm_tolerate_duplicate_top_level_iss:

  Logical. Defaults to `TRUE` for Keycloak because current Keycloak JARM
  responses may repeat an identical top-level `iss` claim. Set `FALSE`
  to fail closed on duplicate top-level `iss` members instead of
  applying this interoperability workaround.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for the specified Keycloak realm

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_keycloak("https://login.example.com", realm = "myrealm")
} # }
```
