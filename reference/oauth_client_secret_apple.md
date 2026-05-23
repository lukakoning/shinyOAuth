# Create an Apple client secret JWT

Builds the ES256-signed JWT that Apple expects in the token-request
`client_secret` form field for Sign in with Apple.

## Usage

``` r
oauth_client_secret_apple(
  client_id,
  team_id,
  key_id,
  private_key,
  expires_in = 15776700,
  issued_at = Sys.time(),
  audience = "https://appleid.apple.com"
)
```

## Arguments

- client_id:

  Apple Services ID or App ID used as the OAuth client id

- team_id:

  Apple Developer Team ID. Apple documents this as a 10-character
  identifier

- key_id:

  Apple Sign in with Apple private-key identifier (`kid`). Apple
  documents this as a 10-character identifier

- private_key:

  Apple private key as an `openssl::key` or PEM string. The key must be
  compatible with `ES256` (P-256 ECDSA)

- expires_in:

  Positive lifetime in seconds. Must be no more than `15777000` seconds
  (six months). Defaults to `15776700` seconds, leaving a five-minute
  margin below Apple's documented maximum

- issued_at:

  Issue time for the JWT. Defaults to
  [`Sys.time()`](https://rdrr.io/r/base/Sys.time.html)

- audience:

  Audience claim. Defaults to `"https://appleid.apple.com"`

## Value

A compact signed JWT string suitable for
`oauth_client(..., client_secret = ...)`

## Details

Apple currently requires the following JWT shape for Sign in with Apple
token requests:

- JOSE header `alg = ES256` and `kid = <Apple key id>`

- `iss = <Apple Developer Team ID>`

- `sub = <client_id>`

- `aud = "https://appleid.apple.com"`

- `exp` no more than `15777000` seconds (six months) after `iat`

The resulting string can be supplied directly to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
as the `client_secret` for
[`oauth_provider_apple()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_apple.md).

## Examples

``` r
if (FALSE) { # \dontrun{
key <- openssl::ec_keygen(curve = "P-256")

oauth_client_secret_apple(
  client_id = "com.example.web",
  team_id = "ABCDEFGHIJ",
  key_id = "ABC123DEFG",
  private_key = key
)
} # }
```
