# This file contains the helper for building custom cache backends for
# shinyOAuth
# Used for storing login state or provider signing keys in a shared backend
# instead of the default in-memory cache

# 1 Custom cache helper --------------------------------------------------------

## 1.1 Build cachem-like backend -----------------------------------------------

# Functions in this section create cachem-compatible objects from caller-supplied
# backend functions.

#' Create a custom state store or signing-key cache
#'
#' @description
#' Connect shinyOAuth to a shared storage backend, such as Redis or a database,
#' by wrapping your R functions in a cachem-like interface. Use the result as
#' `state_store` in [oauth_client()] to share pending login state, or as
#' `jwks_cache` in [oauth_provider()] to share provider signing keys (JWKS).
#'
#' A shared state store is needed when a login can start on one R process and
#' its callback can arrive at another, for example in a multi-worker deployment
#' without sticky routing. A shared signing-key cache lets workers reuse keys
#' fetched from the provider rather than maintaining separate caches.
#'
#' @details
#' This helper adapts your storage functions; it does not create a database,
#' open connections, or make process-local storage shared. Your backend must
#' preserve stored R values and expire entries after their configured lifetime.
#'
#' @section Shared login state in multi-worker deployments:
#' The default [cachem::cache_mem()] state store belongs to one R process.
#' If a load balancer sends the returning callback to another worker, that
#' worker cannot find the pending login and validation fails. Configure all
#' workers with access to the same external store when routing does not keep
#' the authorization request and callback on the same process.
#'
#' For a shared `state_store`, implement `take`: it must read and delete a pending
#' login as one indivisible operation, so two requests cannot use it. Redis
#' `GETDEL` and SQL `DELETE ... RETURNING` are examples of backend operations
#' that can do this. Use the same `state_key` and matching provider/client
#' settings on every worker. Separate reads and deletes, including those in
#' [cachem::cache_disk()], cannot ensure single-use state under concurrent access.
#' See the [deployment guidance](https://lukakoning.github.io/shinyOAuth/articles/usage.html#multiple-r-processes).
#'
#' Store values are small R lists. Preserve `browser_token` as a non-empty
#' string, and preserve `pkce_code_verifier` and `nonce` when those features are
#' enabled. When disabled, these two fields can be `NULL` or omitted.
#'
#' For a state store, returning `max_age` in seconds from `info()` also lets
#' [oauth_module_server()] align the browser cookie lifetime with the store.
#' Reporting this value does not expire entries; your backend must enforce it.
#'
#' @section Shared provider signing keys:
#' A shared `jwks_cache` can reduce repeated key downloads when several R
#' workers use the same provider. This is independent of sharing login state:
#' sharing signing keys alone does not let another worker resume a login.
#'
#' Key caching uses `get` and `set`. Also implement `set_if_absent` to coordinate
#' rate-limited forced key refreshes across workers, for example when the provider
#' rotates its signing keys. Without that atomic operation, forced refresh is
#' disabled for custom/shared caches. Use separate stores or key namespaces for
#' login state and signing keys when they require different expiry policies.
#'
#' @param get A function(key, missing = NULL) -> value. Required.
#' Should return the stored value, or the `missing` argument if the key is not
#' present. The `missing` parameter is required because shinyOAuth passes it
#' explicitly.
#'
#' @param set A function(key, value) -> invisible(NULL). Required.
#' Should store the value under the given key.
#'
#' @param remove A function(key) -> any. Required.
#'
#'   Deletes the entry for `key`. When `$take()` is provided, `$remove()` serves
#'   only as a best-effort cleanup and its return value is ignored. When
#'   `$take()` is not provided, shinyOAuth falls back to
#'   `$get()` + `$remove()` followed by a post-removal absence check via
#'   `$get(key, missing = NA)`. In this fallback path the return value of
#'   `$remove()` is not relied upon; the post-check is authoritative.
#'
#' @param take A function(key, missing = NULL) -> value. Optional.
#'
#'   An atomic get-and-delete operation. When provided, shinyOAuth uses
#'   `$take()` instead of separate `$get()` + `$remove()` calls to enforce
#'   single-use state consumption. This prevents TOCTOU (time-of-check /
#'   time-of-use) replay attacks in multi-worker deployments with shared state
#'   stores.
#'
#'   Should return the stored value and atomically remove the entry, or
#'   return the `missing` argument (default `NULL`) if the key is not present.
#'
#'   If your backend supports atomic get-and-delete natively
#'   (e.g., Redis `GETDEL`, SQL `DELETE ... RETURNING`), wire it through this
#'   parameter for replay-safe state stores.
#'
#'   When `take` is not provided and the state store is not a per-process cache
#'   (like [cachem::cache_mem()]), shinyOAuth will **error** at state
#'   consumption time because non-atomic `$get()` + `$remove()` cannot
#'   guarantee single-use under concurrent access in shared stores.
#'
#' @param set_if_absent A function(key, value, ttl = NULL) -> logical. Optional.
#'
#'   An atomic set-if-missing operation for shared JWKS caches. It must store
#'   `value` and return `TRUE` only when `key` did not already exist; otherwise
#'   it must leave the existing value unchanged and return `FALSE`. When `ttl`
#'   is supplied, the claimed key must expire after that many seconds. Map this
#'   to a native backend primitive such as Redis `SET ... NX EX` or a database
#'   uniqueness constraint with expiry. shinyOAuth uses this operation to make
#'   forced JWKS-refresh throttling safe across workers. Without it, forced
#'   refresh is disabled for shared/custom caches; [cachem::cache_mem()] keeps
#'   its process-local serialized fallback.
#'
#' @param info Function() -> list(max_age = seconds, ...). Optional
#'
#'   TTL information from `$info()` is used to align browser cookie max age in
#'   [oauth_module_server()].
#'
#' @return An R6 object exposing cachem-like `$get/$set/$remove/$info` methods
#'   and the optional `$take` and `$set_if_absent` atomic methods.
#'
#' @example inst/examples/custom_cache.R
#'
#' @export
custom_cache <- function(
  get,
  set,
  remove,
  take = NULL,
  info = NULL,
  set_if_absent = NULL
) {
  # Validate required functions
  if (!is.function(get)) {
    err_input(
      "cache_backend: `get` must be a function(key, missing = NULL) (see `?custom_cache`)"
    )
  }
  if (!is.function(set)) {
    err_input(
      "cache_backend: `set` must be a function(key, value) (see `?custom_cache`)"
    )
  }
  if (!is.function(remove)) {
    err_input(
      "cache_backend: `remove` must be a function(key) -> boolean result (see `?custom_cache`)"
    )
  }
  # Validate optional take hook if provided
  if (!is.null(take)) {
    if (!is.function(take)) {
      err_input(
        "cache_backend: `take` must be a function(key, missing = NULL) for atomic get-and-delete (see `?custom_cache`)"
      )
    }
  }
  if (!is.null(set_if_absent) && !is.function(set_if_absent)) {
    err_input(
      "cache_backend: `set_if_absent` must be a function(key, value, ttl = NULL) for atomic JWKS refresh throttling (see `?custom_cache`)"
    )
  }
  # Validate optional info hook if provided. A missing hook is handled by the
  # R6 method itself so no one-off helper function is needed.
  if (!is.null(info) && !is.function(info)) {
    err_input(
      "cache_backend: `info` must be a function() -> list(max_age = seconds, ...) (see `?custom_cache`)"
    )
  }

  CacheCls <- R6::R6Class(
    classname = "shinyOAuthCustomCache",
    public = list(
      # Set to a function in initialize() when an atomic take implementation is
      # provided; remains NULL otherwise.  Duck-typing check
      # is.function(store$take) naturally returns TRUE/FALSE.
      take = NULL,
      set_if_absent = NULL,
      initialize = function(
        .get,
        .set,
        .remove,
        .take,
        .info,
        .set_if_absent
      ) {
        private$.get <- .get
        private$.set <- .set
        private$.remove <- .remove
        private$.info <- .info
        if (!is.null(.take)) {
          self$take <- function(key, missing = NULL) .take(key, missing)
        }
        if (!is.null(.set_if_absent)) {
          self$set_if_absent <- function(key, value, ttl = NULL) {
            .set_if_absent(key, value, ttl)
          }
        }
      },
      get = function(key, missing = NULL) {
        private$.get(key, missing)
      },
      set = function(key, value) {
        private$.set(key, value)
        invisible(NULL)
      },
      remove = function(key) {
        # Pass through the underlying return value so callers can distinguish
        # successful deletion (TRUE) from no-op/absence (non-TRUE). Visibility
        # is intentionally not forced to invisible, to preserve boolean returns.
        private$.remove(key)
      },
      info = function() {
        if (is.null(private$.info)) {
          return(list())
        }
        out <- try(private$.info(), silent = TRUE)
        if (inherits(out, "try-error") || is.null(out)) {
          return(list())
        }
        out
      }
    ),
    private = list(
      .get = NULL,
      .set = NULL,
      .remove = NULL,
      .info = NULL
    )
  )

  CacheCls$new(get, set, remove, take, info, set_if_absent)
}
