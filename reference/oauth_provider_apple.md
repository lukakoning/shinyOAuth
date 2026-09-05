# Create an Apple [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Look up Apple's login settings and return an
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
for use with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).
This helper makes an OIDC discovery request during setup.

## Usage

``` r
oauth_provider_apple(name = "apple")
```

## Arguments

- name:

  Optional provider name (default "apple")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Sign in with Apple

## Details

Configure your client with:

- Your Apple Services ID or App ID as `client_id`.

- A client secret created with
  [`oauth_client_secret_apple()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_secret_apple.md)
  using your Apple developer key.

- An HTTPS return address with a domain name; Apple does not accept
  localhost or IP addresses.

- `response_mode = "form_post"` and
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
  when requesting `email` or `name`.

Read identity information from the validated ID token's claims. Apple
has no userinfo endpoint, so `userinfo_required` is `FALSE`. The
one-time `user` payload that Apple may send with a form POST callback is
not mapped into `token@userinfo`; do not rely on this helper to retrieve
that payload.

## Examples

``` r
# Sign in with Apple requires an Apple Services ID, Team ID, key ID, and the
# corresponding P-256 private key. Network access is required for discovery.
if (interactive()) {
  apple_provider <- oauth_provider_apple()

  apple_secret <- oauth_client_secret_apple(
    client_id = "com.example.web",
    team_id = "ABCDEFGHIJ",
    key_id = "ABC123DEFG",
    private_key = openssl::read_key("AuthKey_ABC123DEFG.p8")
  )

  apple_client <- oauth_client(
    provider = apple_provider,
    client_id = "com.example.web",
    client_secret = apple_secret,
    redirect_uri = "https://example.com/oauth/callback",
    scopes = c("openid", "email", "name"),
    response_mode = "form_post"
  )
}
```
