# Create a Spotify [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Connect your app to a user's Spotify account. Pass this provider to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
and request the scopes needed by the Spotify API calls you plan to make.
The helper configures profile retrieval through Spotify's API and does
not expect an ID token.

## Usage

``` r
oauth_provider_spotify(name = "spotify", allow_legacy_id = FALSE)
```

## Arguments

- name:

  Optional provider name (default "spotify")

- allow_legacy_id:

  Whether to fall back to Spotify's mutable `id` when `account_id` is
  absent. Default `FALSE`; enable only during migration.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object for use with a Spotify OAuth 2.0 app

## Details

Spotify requires scopes to be included in the authorization request. Set
requested scopes on the client with `oauth_client(..., scopes = ...)`.
Identity uses Spotify's immutable `account_id`. Existing installations
must migrate stored account mappings and audit digests from `id` before
upgrading. Link the old and new identifiers only from a successfully
authenticated profile; do not use display names or email to merge
accounts. To temporarily preserve old mappings, explicitly replace
`provider@userinfo_id_selector` with
`function(userinfo) userinfo[["id"]]` while completing the migration.

## See also

For a Shiny app that connects to Spotify to display the user's listening
data, see the [Spotify
example](https://lukakoning.github.io/shinyOAuth/articles/example-spotify.html).

## Examples

``` r
oauth_provider_spotify()
#> <shinyOAuth::OAuthProvider>
#>  @ name               : chr "spotify"
#>  @ auth_url           : chr "https://accounts.spotify.com/"
#>  @ token_url          : chr "https://accounts.spotify.com/"
#>  @ issuer             : NA
#>  @ userinfo_url       : chr "https://api.spotify.com/"
#>  @ jwks_uri           : NA
#>  @ introspection_url  : NA
#>  @ revocation_url     : NA
#>  @ token_auth_style   : chr "header"
#>  @ use_pkce           : logi TRUE
#>  @ use_nonce          : logi FALSE
#>  @ extra_auth_params  : list()
#>  @ extra_token_params : list()
#>  @ extra_token_headers: list()
```
