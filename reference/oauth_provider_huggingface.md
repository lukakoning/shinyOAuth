# Create a Hugging Face [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Configure Sign in with Hugging Face. Register an OAuth application in
your Hugging Face settings, then pass its credentials to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

## Usage

``` r
oauth_provider_huggingface(name = "huggingface")
```

## Arguments

- name:

  Optional provider name (default `"huggingface"`).

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Hugging Face.

## Details

For login, request `scopes = c("openid", "profile")`, adding `"email"`
only if needed. Repository access and inference require their own
scopes, such as `"read-repos"` or `"inference-api"`, and user consent.
This preset targets confidential applications with a client secret. See
[Sign in with Hugging Face](https://huggingface.co/docs/hub/oauth).

## Examples

``` r
if (FALSE) { # \dontrun{
oauth_provider_huggingface()
} # }
```
