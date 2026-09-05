# Handle OAuth 2.0 callback: verify state, swap code for token, verify token

Check a returning login request and exchange the provider's temporary
authorization code for an
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
(OAuth 2.0 Authorization Code flow). Use this in a custom callback
handler after starting authorization with
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md).
It applies shinyOAuth's state, token, and configured identity checks
while your application manages the HTTP callback and stores the returned
token.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
handles these responsibilities for Shiny sessions.

## Usage

``` r
handle_callback(
  oauth_client,
  code,
  payload,
  browser_token,
  shiny_session = NULL,
  iss = NULL
)
```

## Arguments

- oauth_client:

  An
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object.

- code:

  Authorization code received from the provider on a classic direct
  callback.

- payload:

  Encrypted state payload returned by the provider on a classic direct
  callback. This should be the same value that was originally sent in
  [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md).

- browser_token:

  Browser token present in the user's session. This is usually managed
  by
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).

- shiny_session:

  Optional captured Shiny session details for audit events. Normally
  supplied by the module; leave `NULL` when calling directly.

- iss:

  Optional RFC 9207 callback issuer (`iss`) from the authorization
  response. Pass this when one callback URL can receive responses from
  more than one authorization server. If
  `oauth_client@enforce_callback_issuer` is `TRUE`, this parameter is
  required and must match the configured provider issuer before any
  token exchange occurs.

  This low-level API cannot verify which redirect URI received the
  response. Clients configured with
  `authorization_server_mode = "multi_redirect_uri"` must use
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  instead.

## Value

An
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object. If callback validation, token exchange, or token verification
fails, the function raises an error.

## Details

Pass the returned `code`, the callback's `state` as `payload`, and the
browser token saved for this login. This helper accepts direct
code/state callbacks only. For signed responses using JWT Secured
Authorization Response Mode (JARM; `"jwt"`, `"query.jwt"`, or
`"form_post.jwt"`), use
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
and, for POST responses,
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
There is no public JARM resume API.

## Examples

``` r
# Advanced example: your code supplies browser redirects and callback handling.
# For a Shiny app, oauth_module_server() manages these steps for you.

if (interactive()) {
  # Define client
  client <- oauth_client(
    provider = oauth_provider_github(),
    client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100"
  )

  # Get the login URL and store state in client's state store
  # `<browser_token>` is a token that identifies the browser session
  #  and would typically be stored in a browser cookie
  #  (`oauth_module_server()` handles this typically)
  authorization_url <- prepare_call(client, "<browser_token>")

  # Redirect user to authorization URL; retrieve code & state from the query;
  # read also `<browser_token>` from browser cookie
  code <- "..."
  state <- "..."
  browser_token <- "..."

  # Handle callback, exchanging code for token and validating state
  token <- handle_callback(client, code, state, browser_token)
}
```
