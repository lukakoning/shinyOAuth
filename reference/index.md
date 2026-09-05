# Package index

## Shiny integration

- [`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
  : Set up a Shiny UI for shinyOAuth
- [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  : Configure OAuth/OIDC client credentials and login settings
- [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  : OAuth 2.0 authorization and OIDC authentication module for Shiny
- [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
  : Wrap a Shiny UI to enable OAuth 2.0/OIDC form_post callbacks
- [`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
  : Add JavaScript dependency to the UI of a Shiny app

## Object reference

- [`OAuthProvider()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
  : OAuthProvider S7 class
- [`OAuthClient()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  : OAuthClient S7 class
- [`OAuthToken()`](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  : OAuthToken S7 class

## Provider configuration

### Generic

- [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  : Configure OAuth/OIDC provider endpoints and validation settings
- [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  : Create a generic OpenID Connect (OIDC) OAuthProvider
- [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
  : Discover and create an OpenID Connect (OIDC) OAuthProvider

### Preconfigured

- [`oauth_provider_apple()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_apple.md)
  : Create an Apple OAuthProvider
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

## Provider-specific client settings

- [`oauth_client_mtls_registration()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_mtls_registration.md)
  : Prepare client-certificate registration settings (mTLS)
- [`oauth_client_secret_apple()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_secret_apple.md)
  : Create a client secret for Sign in with Apple

## Custom login handling

### Advanced helpers for managing login without the Shiny module

- [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)
  : Prepare an OAuth 2.0 authorization request and build its URL
- [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
  : Handle OAuth 2.0 callback: verify state, swap code for token, verify
  token

## Tokens and API requests

- [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  : Fetch a user's profile (UserInfo)

- [`refresh_token()`](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.md)
  : Refresh an OAuth 2.0 token

- [`revoke_token()`](https://lukakoning.github.io/shinyOAuth/reference/revoke_token.md)
  : Revoke an OAuth 2.0 token

- [`introspect_token()`](https://lukakoning.github.io/shinyOAuth/reference/introspect_token.md)
  : Introspect an OAuth 2.0 token

- [`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
  : Prepare an API request with an access token

- [`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
  : Call an API with an access token

- [`client_bearer_req()`](https://lukakoning.github.io/shinyOAuth/reference/client_bearer_req.md)
  **\[deprecated\]** :

  Alias for
  [`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)

- [`perform_client_bearer_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_client_bearer_req.md)
  **\[deprecated\]** :

  Alias for
  [`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)

## Deployment helpers

- [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)
  : Check a URL against the package's host policy
- [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  : Create a custom state store or signing-key cache
- [`error_on_softened()`](https://lukakoning.github.io/shinyOAuth/reference/error_on_softened.md)
  **\[deprecated\]** : Check selected debugging options (deprecated)
