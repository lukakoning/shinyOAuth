# Create a custom cache backend (cachem-like)

Builds a minimal cachem-like cache backend object that exposes
cachem-compatible methods: `$get(key, missing)`, `$set(key, value)`,
`$remove(key)`, and `$info()`.

Use this helper when you want to plug a custom state store or JWKS cache
into 'shinyOAuth', when
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
or
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
are not suitable. This may be useful specifically when you deploy a
Shiny app to a multi-process environment with non-sticky workers. In
such cases, you may want to use a shared external cache (e.g., database,
Redis, Memcached).

The resulting object can be used in both places where 'shinyOAuth'
accepts a cache-like object:

- OAuthClient@state_store (requires `$get`, `$set`, `$remove`; optional
  `$info`)

- OAuthProvider@jwks_cache (requires `$get`, `$set`; optional `$remove`,
  `$info`)

The `$info()` method is optional, but if provided and it returns a list
with `max_age` (seconds), shinyOAuth will align cookie/issued_at TTLs to
that value.

## Usage

``` r
custom_cache(get, set, remove, info = NULL)
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

  A function(key) -\> logical or sentinel. Required.

  For state stores, this enforces single-use eviction. If your backend
  performs an atomic "get-and-delete" (e.g., SQL DELETE .. RETURNING),
  you may supply a function which does nothing here but returns `TRUE`.
  (The login flow will always attempt to call `$remove()` after `$get()`
  as a best-effort cleanup.)

  Recommended contract for interoperability and strong replay
  protection:

  - Return `TRUE` when a key was actually deleted or if it already did
    not exist

  - Return `FALSE` when they key could not be deleted or when it is
    unknown if they key was deleted

  When the return value is not `TRUE`, 'shinyOAuth' will attempt to
  retrieve the value from the state store to check if it may still be
  present; if that fails (i.e., key is not present), it will treat the
  removal as succesful. If it does find the key, it will produce an
  error indicating that removal did not succeed.

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
      return(TRUE) # signal successful deletion
    }
    return(TRUE) # key did not exist
  },

  info = function() list(max_age = 600)
)
```
