# Package index

## Shiny module

- [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  : OAuth 2.0 & OIDC authentication module for Shiny applications
- [`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
  : Add JavaScript dependency to the UI of a Shiny app

## S7 classes

- [`OAuthProvider()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
  : OAuthProvider S7 class
- [`OAuthClient()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  : OAuthClient S7 class
- [`OAuthToken()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  : OAuthToken S7 class

## OAuth provider configuration

### Generic

- [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  : Create generic OAuthProvider
- [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  : Create a generic OpenID Connect (OIDC) OAuthProvider
- [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
  : Discover and create an OpenID Connect (OIDC) OAuthProvider

### Preconfigured

- [`oauth_provider_auth0()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_auth0.md)
  : Create an Auth0 OAuthProvider (via OIDC discovery)
- [`oauth_provider_github()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_github.md)
  : Create a GitHub OAuthProvider
- [`oauth_provider_google()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_google.md)
  : Create a Google OAuthProvider
- [`oauth_provider_keycloak()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_keycloak.md)
  : Create a Keycloak OAuthProvider (via OIDC discovery)
- [`oauth_provider_microsoft()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_microsoft.md)
  : Create a Microsoft (Entra ID) OAuthProvider
- [`oauth_provider_okta()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_okta.md)
  : Create an Okta OAuthProvider (via OIDC discovery)
- [`oauth_provider_slack()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_slack.md)
  : Create a Slack OAuthProvider (via OIDC discovery)
- [`oauth_provider_spotify()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_spotify.md)
  : Create a Spotify OAuthProvider

## OAuth client configuration

- [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  : Create generic OAuthClient

## Authentication flow

### Prepare & handle OAuth 2.0 calls; typically not needed by end users

- [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
  : Prepare a OAuth 2.0 authorization call and build an authorization
  URL
- [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
  : Handle OAuth 2.0 callback: verify state, swap code for token, verify
  token

## Token methods

### Methods for OAuthToken objects

- [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  : Get user info from OAuth 2.0 provider
- [`refresh_token()`](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.md)
  : Refresh an OAuth 2.0 token
- [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
  : Revoke an OAuth 2.0 token
- [`introspect_token()`](https://lukakoning.github.io/shinyOAuth/reference/introspect_token.md)
  : Introspect an OAuth 2.0 token
- [`client_bearer_req()`](https://lukakoning.github.io/shinyOAuth/reference/client_bearer_req.md)
  : Build an authorized httr2 request with Bearer token

## Miscellaneous

- [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  : Check if URL(s) are HTTPS and/or in allowed hosts lists
- [`error_on_softened()`](https://lukakoning.github.io/shinyOAuth/reference/error_on_softened.md)
  : Throw an error if any safety checks have been disabled
- [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  : Create a custom cache backend (cachem-like)
