# Decrypt and validate OAuth state payload

Internal utility that decrypts the encrypted `state` payload using the
client's `state_key`, then validates freshness and client binding.

## Usage

``` r
state_payload_decrypt_validate(client, encrypted_payload)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  instance

- encrypted_payload:

  Encrypted state payload string received via the `state` query
  parameter.

## Value

A named list payload (state, client_id, redirect_uri, scopes, provider,
issued_at) on success; otherwise throws an error via
`err_invalid_state()`.
