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
deployment without sticky routing. With a shared signing-key cache,
workers reuse keys fetched by other workers.

## Usage

``` r
custom_cache(
  get,
  set,
  remove,
  take = NULL,
  info = NULL,
  set_if_absent = NULL,
  worker_safe = FALSE
)
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

  Delete the entry for `key`. shinyOAuth does not depend on the return
  value. State consumption uses atomic `take` where available; a
  process-local fallback checks that removal succeeded.

- take:

  A function(key, missing = NULL) -\> value. Optional.

  Read and remove the entry as one indivisible operation, returning its
  value or the `missing` argument when absent. Required for shared state
  stores: separate reads and deletes can let two requests use the same
  login record. Redis `GETDEL` and SQL `DELETE ... RETURNING` are
  examples. The process-local memory store has a safe fallback;
  custom/shared stores without `take` fail by default when login state
  is consumed.

- info:

  Function() -\> list(max_age = seconds, ...). Optional

  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  uses the returned `max_age` to align the browser cookie's maximum age
  with the store's retention period.

- set_if_absent:

  A function(key, value, ttl = NULL) -\> logical. Optional.

  An atomic set-if-missing operation for shared JWKS caches and callback
  bridge slots. It must store `value` and return `TRUE` only when `key`
  did not already exist; otherwise it must leave the existing value
  unchanged and return `FALSE`. When `ttl` is supplied, the claimed key
  must expire after that many seconds. Map this to a native backend
  primitive such as Redis `SET ... NX EX` or a database uniqueness
  constraint with expiry. shinyOAuth uses this operation to make forced
  JWKS-refresh throttling safe across workers. Without it, forced
  refresh is disabled for shared/custom caches;
  [`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
  keeps its process-local serialized fallback. Callback bridges require
  it for custom/shared stores to avoid overwriting concurrent
  candidates; full partitions reject callbacks until slots expire or are
  consumed. The process-local memory store uses a serialized fallback.
  The existing `shinyOAuth.allow_non_atomic_state_store = TRUE` option
  also permits non-atomic callback insertion, with no protection against
  concurrent writers replacing a candidate. Other state-store writes
  still use `set`.

- worker_safe:

  Logical, default `FALSE`. Explicitly declares that this backend can be
  serialized and used in another R process. Applies when the cache is
  used as `jwks_cache`; see the worker-safety requirements above.

## Value

An R6 object exposing cachem-like
`[["get"]]/[["set"]]/[["remove"]]/[["info"]]` methods and the optional
`[["take"]]` and `[["set_if_absent"]]` atomic methods.

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
pending login and validation fails. Shared storage allows either worker
to resume it, provided both use the same `state_key` and provider/client
settings.

A shared `state_store` requires atomic `take`: reading and deleting a
pending login in one operation so two requests cannot use it. Redis
`GETDEL` and SQL `DELETE ... RETURNING` provide this operation. Separate
reads and deletes, including those in
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html),
can let two workers consume the same state. See the [deployment
guidance](https://lukakoning.github.io/shinyOAuth/articles/usage.html#multiple-r-processes).
For the `form_post` and `form_post.jwt` callback bridges, also implement
`set_if_absent` to reserve callback slots without replacing pending
responses.

The backend preserves stored R values and enforces access controls,
expiry and atomic consumption. Pending login records are encrypted. An
upgrade can invalidate pending records; affected logins then restart.

Hosted Request Objects (`request_object_mode = "request_uri"`) use
separate records. Signed objects can contain readable authorization
details; configure Request Object encryption if these details must be
confidential in storage.

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

A custom signing-key cache defaults to synchronous fallback for
asynchronous login and token operations. `worker_safe = TRUE` declares
that its functions and captured values remain usable in a new R process.
That requires per-operation connections rather than captured
database/file handles; serialization alone cannot establish worker
safety. Standard
[`cachem::cache_mem()`](https://cachem.r-lib.org/reference/cache_mem.html)
and
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
backends support worker dispatch automatically. Other cache
implementations can expose a scalar logical `worker_safe` member with
the same contract. State stores are not used in callback workers.

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
