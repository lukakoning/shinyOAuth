# Create a Google [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Use your Google app registration with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
to add Google sign-in. The helper configures OIDC validation and profile
retrieval.

## Usage

``` r
oauth_provider_google(name = "google")
```

## Arguments

- name:

  Optional provider name (default "google")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object for use with a Google OAuth 2.0 app

## Details

You can register a new Google OAuth 2.0 app in the [Google Cloud
Console](https://console.cloud.google.com/apis/credentials). Configure
the client ID & secret in your
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md).

## Examples

``` r
oauth_provider_google()
#> <shinyOAuth::OAuthProvider>
#>  @ name                                            : chr "google"
#>  @ auth_url                                        : chr "https://accounts.google.com/o/oauth2/v2/auth"
#>  @ token_url                                       : chr "https://oauth2.googleapis.com/token"
#>  @ issuer                                          : chr "https://accounts.google.com"
#>  @ issuer_thus_oidc                                : logi TRUE
#>  @ issuer_match                                    : chr "url"
#>  @ token_auth_style                                : chr "header"
#>  @ use_pkce                                        : logi TRUE
#>  @ pkce_method                                     : chr "S256"
#>  @ use_nonce                                       : logi TRUE
#>  @ userinfo_url                                    : chr "https://openidconnect.googleapis.com/v1/userinfo"
#>  @ userinfo_required                               : logi TRUE
#>  @ userinfo_id_selector                            : function (userinfo)  
#>  @ userinfo_id_token_match                         : logi TRUE
#>  @ userinfo_signed_jwt_required                    : logi FALSE
#>  @ id_token_required                               : logi TRUE
#>  @ id_token_validation                             : logi TRUE
#>  @ id_token_at_hash_required                       : logi FALSE
#>  @ introspection_url                               : chr NA
#>  @ revocation_url                                  : chr "https://oauth2.googleapis.com/revoke"
#>  @ extra_auth_params                               :List of 1
#>  .. $ access_type: chr "offline"
#>  @ extra_token_params                              : list()
#>  @ extra_token_headers                             : chr(0) 
#>  @ jwks_uri                                        : chr NA
#>  @ jwks_cache                                      :List of 9
#>  .. $ get   :function (key, missing = missing_)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 232 10 263 3 10 3 933 964
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ set   :function (key, value)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 265 10 335 3 10 3 966 1036
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ exists:function (key)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 337 13 360 3 13 3 1038 1061
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ keys  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 362 11 374 3 11 3 1063 1075
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ remove:function (key)  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 376 13 381 3 13 3 1077 1082
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ reset :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 217 12 230 3 12 3 918 931
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ prune :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 383 12 447 3 12 3 1084 1148
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ size  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 449 11 458 3 11 3 1150 1159
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. $ info  :function ()  
#>  ..  ..- attr(*, "srcref")= 'srcref' int [1:8] 460 11 469 3 11 3 1161 1170
#>  ..  .. ..- attr(*, "srcfile")=Classes 'srcfilealias', 'srcfile' <environment: 0x558c2ded1bf8> 
#>  .. - attr(*, "class")= chr [1:2] "cache_mem" "cachem"
#>  @ jwks_pins                                       : chr(0) 
#>  @ jwks_pin_mode                                   : chr "any"
#>  @ jwks_host_issuer_match                          : logi TRUE
#>  @ jwks_host_allow_only                            : chr "www.googleapis.com"
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
