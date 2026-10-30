# Prepare a browser authorization request using GET or POST

Creates the same one-use state, PKCE and nonce as
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md),
returning a plain list describing how to send the request. Use this for
applications that handle their own browser navigation and
[`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md).
In Shiny, the module's `request_login()` sends the request
automatically.

## Usage

``` r
prepare_authorization_request(
  client,
  browser_token,
  request_uri_publisher = NULL
)
```

## Arguments

- client:

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

## Value

A list with `method` (`"GET"` or `"POST"`), `url` and `fields`. `fields`
is empty for GET; for POST it is a list of lists, each with scalar
character `name` and `value`. PAR expiry attributes are preserved as
documented in
[`prepare_call()`](https://lukakoning.github.io/shinyOAuth/reference/prepare_call.md).
The result contains transient authorization data for that login attempt.

## Details

For GET, `url` is the browser navigation target. For POST, it is the
action of an `application/x-www-form-urlencoded` browser form. Each
`fields` entry represents one hidden input, with repeated names
preserved as separate inputs. Names and values require DOM assignment or
HTML escaping when constructing the form. Browser submission gives the
provider access to the user's login cookies; an R HTTP request cannot
perform that interaction.

The client selects `authorization_method = "POST"` explicitly; support
depends on the provider.
[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md)
additionally requires the `authorize-post` capability. The outgoing
method is independent of the callback `response_mode`. Configured PAR
and Request Object requirements still apply. Each result belongs to one
login attempt with single-use state.

POST preserves the authorization endpoint's fixed query and sends newly
composed fields in the body. It permits up to 256 fields and 128 KiB of
encoded form data; CR/LF and the browser-reserved `_charset_` field are
rejected to prevent the browser changing field values. Existing state
and callback size limits also apply. Configure your app's Content
Security Policy `form-action` to allow the authorization endpoint.
Custom callers must preserve browser binding and callback handling.

## Examples

``` r
provider <- oauth_provider(
  name = "Example service",
  auth_url = "https://example.com/authorize",
  token_url = "https://example.com/token",
  token_auth_style = "public"
)
client <- oauth_client(
  provider = provider,
  client_id = "example-client",
  redirect_uri = "http://127.0.0.1:8100/callback"
)
# In a custom browser flow, bind this secret to the initiating browser and
# supply it again to handle_callback(). Shiny modules manage this for you.
browser_token <- paste(format(openssl::rand_bytes(64)), collapse = "")
request <- prepare_authorization_request(client, browser_token)
request[["method"]]
#> [1] "GET"
```
