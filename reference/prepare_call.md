# Prepare an OAuth 2.0 authorization request and build its URL

Prepare a login request and return the URL to open in the user's
browser. Use this when your application controls the browser redirect
and callback handling itself but needs shinyOAuth to construct the OAuth
2.0 authorization request. Pair it with
[`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
to complete the code flow.

## Usage

``` r
prepare_call(
  oauth_client,
  browser_token,
  request_uri_publisher = NULL,
  .requested_max_age = NULL,
  .defer_build = FALSE
)
```

## Arguments

- oauth_client:

  An
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object.

- browser_token:

  Browser-bound token used to tie the login attempt to the current
  browser session.

- request_uri_publisher:

  Optional function used when `request_object_mode = "request_uri"`. It
  must accept `request_object`, `request_handle_id`, `expires_at`, and
  `oauth_client` arguments and return an absolute HTTPS request-object
  URL that the provider can fetch.

- .requested_max_age:

  Internal normalized OIDC `max_age` override used by the Shiny module
  for forced reauthentication.

- .defer_build:

  Internal flag returning prepared local state for async authorization
  work instead of completing the authorization URL.

## Value

A length-1 string containing the authorization URL to send the user to.
When PAR is used, the returned string also carries
`shinyOAuth.par_request_uri`, `shinyOAuth.par_expires_in`, and
`shinyOAuth.par_expires_at` attributes so callers can tell when the
pushed authorization request should be regenerated.

## Details

In a Shiny app using
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
call `auth$request_login()` to start login through the module, which
manages both operations and the reactive session state.

The helper records one-time state and creates any required PKCE and
nonce values. Custom callers must preserve the browser binding and
process the returning callback themselves.

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
