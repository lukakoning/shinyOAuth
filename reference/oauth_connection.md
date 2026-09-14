# Make API requests with a Shiny session's current OAuth credentials

Combine one module's reactive token with its client and approved API
addresses configured on
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
Call `$request()` on the returned connection instead of assembling a
token, client and URL for each request. It reads the reactive token
again after refresh or logout and restricts requests to the configured
APIs. This optional wrapper expires with its Shiny session; it does not
implement refresh itself or retain credentials across redirects.

## Usage

``` r
oauth_connection(client, token, session = shiny::getDefaultReactiveDomain())
```

## Arguments

- client:

  An
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  with non-empty `resource_bases`, created by
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  or
  [`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md).

- token:

  A Shiny reactive expression returning the current
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  or `NULL`, usually `shiny::reactive(auth$token)`. It must come from
  the module using `client`. Supplying that association is trusted
  server application wiring; a resource policy cannot prove an opaque
  token's audience.

- session:

  The owning Shiny session; defaults to the current session.

## Value

An
[OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
with `$id`, `$is_usable()`, `$summary()` and
`$request(resource_id, path = "", query = NULL, method = "GET", required_scopes = character(), configure = NULL)`.
Requests return
[httr2](https://httr2.r-lib.org/reference/httr2-package.html) responses.
`configure` can add a body and application headers; see
[OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
for its contract.

## Details

Create the reference once inside `server()`. Access it only in that
session's reactive context. `$summary()` excludes tokens, identity
claims and extension context. `$is_usable()` checks local presence,
known expiry and required scopes; it cannot guarantee remote
authorization. Unknown token expiry is unusable.

Paths are relative to the selected base directory. Absolute and
root-relative references (including pagination links) must stay within
that same base. Dot segments and ambiguous encodings are rejected;
redirects are never followed. Bearer, DPoP and mTLS use the existing
transport and the configured client.

Use request-level `required_scopes` for optional operations. They must
be included in the client's requested scopes and covered by the current
grant. The package cannot infer arbitrary API permissions from an HTTP
method/path. The legacy module continues to own refresh and logout.
Retained connection storage and its independent lifecycle are available
through
[`oauth_connections()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.md)
and
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md).

## Examples

``` r
if (FALSE) { # \dontrun{
# Configure outside server():
client <- oauth_client(provider, "registered-app",
  redirect_uri = "https://app.example/callback", scopes = "read",
  resource_bases = c(api = "https://api.example/v1"))
# Inside server():
auth <- oauth_module_server("auth", client)
connection <- oauth_connection(client, shiny::reactive(auth$token))
data <- shiny::reactive({
  shiny::req(connection$is_usable())
  connection$request("api", "records", required_scopes = "read")
})
} # }
```
