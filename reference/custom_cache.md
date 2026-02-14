# Create a custom cache backend (cachem-like)

Builds a minimal cachem-like cache backend object that exposes
cachem-compatible methods: `$get(key, missing)`, `$set(key, value)`,
`$remove(key)`, and `$info()`.

Use this helper when you want to plug a custom state store or JWKS cache
into 'shinyOAuth', when
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
is not suitable (e.g., multi-process deployments with non-sticky
workers). In such cases, you may want to use a shared external cache
(e.g., database, Redis, Memcached).

The resulting object can be used in both places where 'shinyOAuth'
accepts a cache-like object:

- OAuthClient@state_store (requires `$get`, `$set`, `$remove`; optional
  `$info`)

- OAuthProvider@jwks_cache (requires `$get`, `$set`; optional `$remove`,
  `$info`)

The `$info()` method is optional, but if provided and it returns a list
with `max_age` (seconds), shinyOAuth will align browser cookie max-age
in
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
to that value.

## Usage

``` r
custom_cache(get, set, remove, take = NULL, info = NULL)
```

## Arguments

- get:

  A function(key, missing = NULL) -\> value. Required. Should return the
  stored value, or the `missing` argument if the key is not present. The
  `missing` parameter is mandatory because both `OAuthClient` and
  `OAuthProvider` validators will pass it explicitly.

- set:

  A function(key, value) -\> invisible(NULL). Required. Should store the
  value under the given key

- remove:

  A function(key) -\> any. Required.

  Deletes the entry for `key`. When `$take()` is provided, `$remove()`
  serves only as a best-effort cleanup and its return value is ignored.
  When `$take()` is not provided, 'shinyOAuth' falls back to `$get()` +
  `$remove()` followed by a post-removal absence check via
  `$get(key, missing = NA)`. In this fallback path the return value of
  `$remove()` is not relied upon; the post-check is authoritative.

- take:

  A function(key, missing = NULL) -\> value. Optional.

  An atomic get-and-delete operation. When provided, 'shinyOAuth' uses
  `$take()` instead of separate `$get()` + `$remove()` calls to enforce
  single-use state consumption. This prevents TOCTOU (time-of-check /
  time-of-use) replay attacks in multi-worker deployments with shared
  state stores.

  Should return the stored value and atomically remove the entry, or
  return the `missing` argument (default `NULL`) if the key is not
  present.

  If your backend supports atomic get-and-delete natively (e.g., Redis
  `GETDEL`, SQL `DELETE ... RETURNING`), wire it through this parameter
  for replay-safe state stores.

  When `take` is not provided and the state store is not a per-process
  cache (like
  [`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)),
  'shinyOAuth' will **error** at state consumption time because
  non-atomic `$get()` + `$remove()` cannot guarantee single-use under
  concurrent access in shared stores.

- info:

  Function() -\> list(max_age = seconds, ...). Optional

  This may be provided to because TTL information from `$info()` is used
  to align browser cookie max age in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)

## Value

An R6 object exposing cachem-like `$get/$set/$remove/$info` methods

## Examples

``` r
mem <- new.env(parent = emptyenv())

my_cache <- custom_cache(
  get = function(key, missing = NULL) {
    base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
  },

  set = function(key, value) {
    assign(key, value, envir = mem)
    invisible(NULL)
  },

  remove = function(key) {
    if (exists(key, envir = mem, inherits = FALSE)) {
      rm(list = key, envir = mem)
    }
    invisible(NULL)
  },

  # Atomic get-and-delete: preferred for state stores in multi-worker
  # deployments to prevent TOCTOU replay attacks. For per-process caches
  # (like cachem::cache_mem()) this is optional; for shared backends (Redis,
  # database) it should map to the backend's atomic primitive (e.g., GETDEL).
  take = function(key, missing = NULL) {
    val <- base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
    if (exists(key, envir = mem, inherits = FALSE)) {
      rm(list = key, envir = mem)
    }
    val
  },

  info = function() list(max_age = 600)
)
```
