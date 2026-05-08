# Fetch and remove the single-use state entry

Uses the client's `state_store` to read and remove the state-bound
values after the encrypted callback payload has been decrypted and
validated.

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

Validated state-store value list. On failure this function raises
`err_invalid_state()` instead of returning a partial result.

## Details

When the store exposes an atomic `$take(key, missing)` method (see
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)),
that path is used first so single-use semantics still hold under
concurrent access. When `$take()` is unavailable, the function falls
back to `$get()` + `$remove()` with a post-removal absence check. That
fallback is safe for per-process caches such as
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html).
For shared stores it errors by default, because non-atomic get+remove
cannot guarantee single-use semantics under concurrent access; operators
may opt in to that weaker fallback with
`options(shinyOAuth.allow_non_atomic_state_store = TRUE)`, but doing so
is discouraged.
