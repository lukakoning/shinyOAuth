# Decrypt and validate OAuth state payload

Internal utility that decrypts the encrypted `state` payload using the
client's `state_key`, then validates freshness and client binding. Used
by callback handling before the code exchange continues.

## Usage

``` r
state_payload_decrypt_validate(
  client,
  encrypted_payload,
  shiny_session = NULL,
  audit_success = FALSE
)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  instance

- encrypted_payload:

  Encrypted state payload string received via the `state` query
  parameter.

- shiny_session:

  Optional pre-captured Shiny session context (from
  `capture_shiny_session_context()`) to include in audit events. Used
  when calling from async workers that lack access to the reactive
  domain.

- audit_success:

  Whether successful payload validation should emit the standard
  callback validation audit event. Defaults to `FALSE` because callback
  handlers normally still need to validate the browser-bound token and
  consume the single-use state entry before success is final. Failures
  are still audited.

## Value

A named list payload (state, client_id, redirect_uri, scopes, provider,
client_policy, issued_at) on success; otherwise throws an error via
`err_invalid_state()`.
