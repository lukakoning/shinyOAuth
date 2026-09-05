# Create a custom state store or signing-key cache

Connect shinyOAuth to a shared storage backend, such as Redis or a
database, by wrapping your R functions in a cachem-like interface. Use
the result as `state_store` in
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
to share pending login state, or as `jwks_cache` in
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
to share provider signing keys (JWKS).

A shared state store is needed when a login can start on one R process
and its callback can arrive at another, for example in a multi-worker
deployment without sticky routing. A shared signing-key cache lets
workers reuse keys fetched from the provider rather than maintaining
separate caches.

## Usage

``` r
custom_cache(get, set, remove, take = NULL, info = NULL, set_if_absent = NULL)
```

## Arguments

- get:

  A function(key, missing = NULL) -\> value. Required. Should return the
  stored value, or the `missing` argument if the key is not present. The
  `missing` parameter is required because shinyOAuth passes it
  explicitly.

- set:

  A function(key, value) -\> invisible(NULL). Required. Should store the
  value under the given key.

- remove:

  A function(key) -\> any. Required.

  Deletes the entry for `key`. When `$take()` is provided, `$remove()`
  serves only as a best-effort cleanup and its return value is ignored.
  When `$take()` is not provided, shinyOAuth falls back to `$get()` +
  `$remove()` followed by a post-removal absence check via
  `$get(key, missing = NA)`. In this fallback path the return value of
  `$remove()` is not relied upon; the post-check is authoritative.

- take:

  A function(key, missing = NULL) -\> value. Optional.

  An atomic get-and-delete operation. When provided, shinyOAuth uses
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
  shinyOAuth will **error** at state consumption time because non-atomic
  `$get()` + `$remove()` cannot guarantee single-use under concurrent
  access in shared stores.

- info:

  Function() -\> list(max_age = seconds, ...). Optional

  TTL information from `$info()` is used to align browser cookie max age
  in
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).

- set_if_absent:

  A function(key, value, ttl = NULL) -\> logical. Optional.

  An atomic set-if-missing operation for shared JWKS caches. It must
  store `value` and return `TRUE` only when `key` did not already exist;
  otherwise it must leave the existing value unchanged and return
  `FALSE`. When `ttl` is supplied, the claimed key must expire after
  that many seconds. Map this to a native backend primitive such as
  Redis `SET ... NX EX` or a database uniqueness constraint with expiry.
  shinyOAuth uses this operation to make forced JWKS-refresh throttling
  safe across workers. Without it, forced refresh is disabled for
  shared/custom caches;
  [`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
  keeps its process-local serialized fallback.

## Value

An R6 object exposing cachem-like `$get/$set/$remove/$info` methods and
the optional `$take` and `$set_if_absent` atomic methods.

## Details

This helper adapts your storage functions; it does not create a
database, open connections, or make process-local storage shared. Your
backend must preserve stored R values and expire entries after their
configured lifetime.

## Shared login state in multi-worker deployments

The default
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
state store belongs to one R process. If a load balancer sends the
returning callback to another worker, that worker cannot find the
pending login and validation fails. Configure all workers with access to
the same external store when routing does not keep the authorization
request and callback on the same process.

For a shared `state_store`, implement `take`: it must read and delete a
pending login as one indivisible operation, so two requests cannot use
it. Redis `GETDEL` and SQL `DELETE ... RETURNING` are examples of
backend operations that can do this. Use the same `state_key` and
matching provider/client settings on every worker. Separate reads and
deletes, including those in
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html),
cannot ensure single-use state under concurrent access. See the
[deployment
guidance](https://lukakoning.github.io/shinyOAuth/articles/usage.html#multiple-r-processes).

Store values are small R lists. Preserve `browser_token` as a non-empty
string, and preserve `pkce_code_verifier` and `nonce` when those
features are enabled. When disabled, these two fields can be `NULL` or
omitted.

For a state store, returning `max_age` in seconds from `info()` also
lets
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
align the browser cookie lifetime with the store. Reporting this value
does not expire entries; your backend must enforce it.

## Shared provider signing keys

A shared `jwks_cache` can reduce repeated key downloads when several R
workers use the same provider. This is independent of sharing login
state: sharing signing keys alone does not let another worker resume a
login.

Key caching uses `get` and `set`. Also implement `set_if_absent` to
coordinate rate-limited forced key refreshes across workers, for example
when the provider rotates its signing keys. Without that atomic
operation, forced refresh is disabled for custom/shared caches. Use
separate stores or key namespaces for login state and signing keys when
they require different expiry policies.

## Examples

``` r
# This in-memory example illustrates the cache interface in one R process.
# It does not share entries across workers or implement timed expiry.
# A production shared store must implement both itself.
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

  # In a shared store, replace this with the backend's atomic get-and-delete
  # operation, such as Redis GETDEL. This R environment is process-local.
  take = function(key, missing = NULL) {
    val <- base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
    if (exists(key, envir = mem, inherits = FALSE)) {
      rm(list = key, envir = mem)
    }
    val
  },

  info = function() list(max_age = Inf)
)
```
