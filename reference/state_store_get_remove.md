# Fetch and remove the single-use state entry

Retrieves the state-bound values from the client's `state_store` and
removes the entry to enforce single-use semantics.

## Usage

``` r
state_store_get_remove(client, state, shiny_session = NULL)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  instance

- state:

  Plain (decrypted) state string used as the logical key

- shiny_session:

  Optional pre-captured Shiny session context (from
  `capture_shiny_session_context()`) to include in audit events. Used
  when calling from async workers that lack access to the reactive
  domain.

## Value

A list with `browser_token`, `pkce_code_verifier`, and `nonce`. Throws
an error via `err_invalid_state()` if retrieval or removal fails, or if
the retrieved value is missing/malformed.

## Details

When the store exposes an atomic `$take(key, missing)` method (see
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)),
it is used preferentially to guarantee single-use even under concurrent
access in shared/distributed backends. When `$take()` is not available,
the function falls back to `$get()` + `$remove()` with a post-removal
absence check. This fallback is safe for per-process caches (e.g.,
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html))
but **errors** for any other store (e.g.,
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
or custom backends) because non-atomic get+remove cannot guarantee
single-use under concurrent access. Shared stores **must** implement
`$take()` to be used as a state store.
