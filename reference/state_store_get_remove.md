# Fetch and remove the single-use state entry

Retrieves the state-bound values from the client's `state_store` and
removes the entry to enforce single-use semantics.

## Usage

``` r
state_store_get_remove(client, state)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  instance

- state:

  Plain (decrypted) state string used as the logical key

## Value

A list with `browser_token`, `pkce_code_verifier`, and `nonce`. Throws
an error via `err_invalid_state()` if retrieval or removal fails, or if
the retrieved value is missing/malformed.
