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
#>  @ name                                            : chr "spotify"
#>  @ auth_url                                        : chr "https://accounts.spotify.com/authorize"
#>  @ token_url                                       : chr "https://accounts.spotify.com/api/token"
#>  @ issuer                                          : chr NA
#>  @ issuer_thus_oidc                                : logi TRUE
#>  @ issuer_match                                    : chr "url"
#>  @ token_auth_style                                : chr "header"
#>  @ use_pkce                                        : logi TRUE
#>  @ pkce_method                                     : chr "S256"
#>  @ use_nonce                                       : logi FALSE
#>  @ userinfo_url                                    : chr "https://api.spotify.com/v1/me"
#>  @ userinfo_required                               : logi TRUE
#>  @ userinfo_id_selector                            : function (userinfo)  
#>  @ userinfo_id_token_match                         : logi FALSE
#>  @ userinfo_signed_jwt_required                    : logi FALSE
#>  @ id_token_required                               : logi FALSE
#>  @ id_token_validation                             : logi FALSE
#>  @ id_token_at_hash_required                       : logi FALSE
#>  @ introspection_url                               : chr NA
#>  @ revocation_url                                  : chr NA
#>  @ extra_auth_params                               : list()
#>  @ extra_token_params                              : list()
#>  @ extra_token_headers                             : chr(0) 
#>  @ jwks_uri                                        : chr NA
#>  @ jwks_cache                                      :List of 9
#>  .. $ get   :function (key, missing = missing_)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 232 10 263 3 10 3 933 964
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ set   :function (key, value)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 265 10 335 3 10 3 966 1036
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ exists:function (key)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 337 13 360 3 13 3 1038 1061
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ keys  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 362 11 374 3 11 3 1063 1075
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ remove:function (key)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 376 13 381 3 13 3 1077 1082
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ reset :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 217 12 230 3 12 3 918 931
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ prune :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 383 12 447 3 12 3 1084 1148
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ size  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 449 11 458 3 11 3 1150 1159
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. $ info  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 460 11 469 3 11 3 1161 1170
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x55afd76671d0> 
#>  .. - attr(*, "class")= chr [1:2] "cache_mem" "cachem"
#>  @ jwks_pins                                       : chr(0) 
#>  @ jwks_pin_mode                                   : chr "any"
#>  @ jwks_host_issuer_match                          : logi FALSE
#>  @ jwks_host_allow_only                            : chr NA
#>  @ userinfo_allowed_algs                           : NULL
#>  @ allowed_algs                                    : chr [1:7] "RS256" "RS384" "RS512" "ES256" "ES384" "ES512" "EDDSA"
#>  @ allowed_token_types                             : chr "Bearer"
#>  @ leeway                                          : num 30
#>  @ par_url                                         : chr NA
#>  @ par_required                                    : logi FALSE
#>  @ signed_request_object_required                  : logi FALSE
#>  @ request_parameter_supported                     : logi NA
#>  @ request_uri_parameter_supported                 : logi NA
#>  @ request_uri_registration_required               : logi NA
#>  @ request_object_signing_alg_values_supported     : chr(0) 
#>  @ request_object_encryption_alg_values_supported  : chr(0) 
#>  @ request_object_encryption_enc_values_supported  : chr(0) 
#>  @ request_object_encryption_jwk                   : NULL
#>  @ authorization_request_front_channel_mode        : chr "compat"
#>  @ authorization_response_iss_parameter_supported  : logi FALSE
#>  @ response_modes_supported                        : chr(0) 
#>  @ jarm_signing_alg_values_supported               : chr(0) 
#>  @ jarm_encryption_alg_values_supported            : chr(0) 
#>  @ jarm_encryption_enc_values_supported            : chr(0) 
#>  @ jarm_tolerate_duplicate_top_level_iss           : logi FALSE
#>  @ token_endpoint_auth_signing_alg_values_supported: chr(0) 
#>  @ endpoint_auth_metadata                          : list()
#>  @ dpop_signing_alg_values_supported               : chr(0) 
#>  @ mtls_endpoint_aliases                           : list()
#>  @ mtls_client_certificate_bound_access_tokens     : logi FALSE
```
