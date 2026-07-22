# Handle OAuth 2.0 callback: verify state, swap code for token, verify token

Completes the callback step of the login flow. It validates the callback
state, exchanges the returned code for tokens, and verifies the result.
This low-level helper accepts only the classic authorization-code
callback shape for non-JARM clients: a `code`, the sealed `state`
payload returned as `payload`, and an optional RFC 9207 `iss` callback
parameter. It does not accept a raw JARM `response` JWT, and it also
does not provide a public way to resume a JARM callback after separate
validation. For clients configured with `response_mode = "jwt"`,
`"query.jwt"`, or `"form_post.jwt"`, use
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
(and
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
for `form_post.jwt`) so shinyOAuth validates the callback JWT and
resumes through its internal prevalidated callback path.

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

  Optional pre-captured Shiny session context (from
  `capture_shiny_session_context()`) to include in audit events. Used
  when calling from async workers that lack access to the reactive
  domain.

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

## Examples

``` r
# Please note: `prepare_call()` & `handle_callback()` are typically
# not called by users of this package directly, but are called
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Below code shows generic usage of `prepare_call()` and `handle_callback()`
# (code is not run because it would require user interaction)
if (interactive()) {
  # Define client
  client <- oauth_client(
    provider = oauth_provider_github(),
    client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100"
  )

  # Get authorization URL and and store state in client's state store
  # `<browser_token>` is a token that identifies the browser session
  #  and would typically be stored in a browser cookie
  #  (`oauth_module_server()` handles this typically)
  authorization_url <- prepare_call(client, "<browser_token>")

  # Redirect user to authorization URL; retrieve code & payload from query;
  # read also `<browser_token>` from browser cookie
  # (`oauth_module_server()` handles this typically)
  code <- "..."
  payload <- "..."
  browser_token <- "..."

  # Handle callback, exchanging code for token and validating state
  # (`oauth_module_server()` handles this typically)
  token <- handle_callback(client, code, payload, browser_token)
}
```
