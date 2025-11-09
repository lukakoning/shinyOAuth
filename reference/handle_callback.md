# Handle OAuth 2.0 callback: verify state, swap code for token, verify token

Handle OAuth 2.0 callback: verify state, swap code for token, verify
token

## Usage

``` r
handle_callback(
  oauth_client,
  code,
  payload,
  browser_token,
  decrypted_payload = NULL,
  state_store_values = NULL
)
```

## Arguments

- oauth_client:

  An
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object representing the OAuth client configuration.

- code:

  The authorization code received from the OAuth provider during the
  callback.

- payload:

  The encrypted state payload received from the OAuth provider during
  the callback (this should be the same value that was generated and
  sent in
  [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)).

- browser_token:

  Browser token present in the user's session (this is managed by
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  and should match the one used in
  [`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md)).

- decrypted_payload:

  Optional pre-decrypted and validated payload list (as returned by
  `state_decrypt_gcm()` followed by internal validation). Supplying this
  allows callers to validate and bind the state on the main thread
  before dispatching to a background worker for async flows.

- state_store_values:

  Optional pre-fetched state store entry (a list with `browser_token`,
  `pkce_code_verifier`, and `nonce`). When supplied, the function will
  skip reading/removing from `oauth_client@state_store` and use the
  provided values instead. This supports async flows that prefetch and
  remove the single-use state entry on the main thread to avoid
  cross-process cache visibility issues.

## Value

An
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)\`
object containing the access token, refresh token, expiration time, user
information (if requested), and ID token (if applicable). If any step of
the process fails (e.g., state verification, token exchange, token
validation), an error is thrown indicating the failure reason.

## Examples

``` r
# Please note: `prepare_callback()` & `handle_callback()` are typically
# not called by users of this package directly, but are called 
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Below code shows generic usage of `prepare_callback()` and `handle_callback()`
# (code is not run because it would require user interaction)
if (FALSE) { # \dontrun{
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
authorization_url <- prepare_callback(client, "<browser_token>")

# Redirect user to authorization URL; retrieve code & payload from query;
# read also `<browser_token>` from browser cookie
# (`oauth_module_server()` handles this typically)
code <- "..."
payload <- "..."
browser_token <- "..."

# Handle callback, exchanging code for token and validating state
# (`oauth_module_server()` handles this typically)
token <- handle_callback(client, code, payload, browser_token)
} # }
```
