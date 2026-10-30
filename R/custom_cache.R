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
#' without sticky routing. With a shared signing-key cache, workers reuse keys
#' fetched by other workers.
#'
#' @details
#' This helper adapts your storage functions; it does not create a database,
#' open connections, or make process-local storage shared. Your backend must
#' preserve stored R values and expire entries after their configured lifetime.
#'
#' @section Shared login state in multi-worker deployments:
#' The default [cachem::cache_mem()] state store belongs to one R process.
#' If a load balancer sends the returning callback to another worker, that
#' worker cannot find the pending login and validation fails. Shared storage
#' allows either worker to resume it, provided both use the same `state_key`
#' and provider/client settings.
#'
#' A shared `state_store` requires atomic `take`: reading and deleting a pending
#' login in one operation so two requests cannot use it. Redis `GETDEL` and SQL
#' `DELETE ... RETURNING` provide this operation. Separate reads and deletes,
#' including those in
#' [cachem::cache_disk()], can let two workers consume the same state.
#' See the [deployment guidance](https://lukakoning.github.io/shinyOAuth/articles/usage.html#multiple-r-processes).
#' For the `form_post` and `form_post.jwt` callback bridges, also implement
#' `set_if_absent` to reserve callback slots without replacing pending responses.
#'
#' The backend preserves stored R values and enforces access controls, expiry
#' and atomic consumption. Pending login records are encrypted. An upgrade can
#' invalidate pending records; affected logins then restart.
#'
#' Hosted Request Objects (`request_object_mode = "request_uri"`) use separate
#' records. Signed objects can contain readable authorization details; configure
#' Request Object encryption if these details must be confidential in storage.
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
#' A custom signing-key cache defaults to synchronous fallback for asynchronous
#' login and token operations. `worker_safe = TRUE` declares that its functions
#' and captured values remain usable in a new R process. That requires per-operation
#' connections rather than captured database/file handles; serialization alone
#' cannot establish worker safety. Standard `cachem::cache_mem()` and
#' `cachem::cache_disk()` backends support worker dispatch automatically.
#' Other cache implementations can expose a scalar logical `worker_safe` member
#' with the same contract. State stores are not used in callback workers.
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
#'   Delete the entry for `key`. shinyOAuth does not depend on the return value.
#'   State consumption uses atomic `take` where available; a process-local
#'   fallback checks that removal succeeded.
#'
#' @param take A function(key, missing = NULL) -> value. Optional.
#'
#'   Read and remove the entry as one indivisible operation, returning its value
#'   or the `missing` argument when absent. Required for shared state stores:
#'   separate reads and deletes can let two requests use the same login record.
#'   Redis `GETDEL` and SQL `DELETE ... RETURNING` are examples. The process-local
#'   memory store has a safe fallback; custom/shared stores without `take` fail
#'   by default when login state is consumed.
#'
#' @param set_if_absent A function(key, value, ttl = NULL) -> logical. Optional.
#'
#'   An atomic set-if-missing operation for shared JWKS caches and callback
#'   bridge slots. It must store
#'   `value` and return `TRUE` only when `key` did not already exist; otherwise
#'   it must leave the existing value unchanged and return `FALSE`. When `ttl`
#'   is supplied, the claimed key must expire after that many seconds. Map this
#'   to a native backend primitive such as Redis `SET ... NX EX` or a database
#'   uniqueness constraint with expiry. shinyOAuth uses this operation to make
#'   forced JWKS-refresh throttling safe across workers. Without it, forced
#'   refresh is disabled for shared/custom caches; [cachem::cache_mem()] keeps
#'   its process-local serialized fallback.
#'   Callback bridges require it for custom/shared stores to avoid overwriting
#'   concurrent candidates; full partitions reject callbacks until slots expire
#'   or are consumed. The process-local memory store uses a serialized fallback.
#'   The existing `shinyOAuth.allow_non_atomic_state_store = TRUE` option also
#'   permits non-atomic callback insertion, with no protection against concurrent
#'   writers replacing a candidate. Other state-store writes still use `set`.
#'
#' @param info Function() -> list(max_age = seconds, ...). Optional
#'
#'   [oauth_module_server()] uses the returned `max_age` to align the browser
#'   cookie's maximum age with the store's retention period.
#'
#' @param worker_safe Logical, default `FALSE`. Explicitly declares that this
#'   backend can be serialized and used in another R process. Applies when the
#'   cache is used as `jwks_cache`; see the worker-safety requirements above.
#'
#' @return An R6 object exposing cachem-like `[["get"]]/[["set"]]/[["remove"]]/[["info"]]` methods
#'   and the optional `[["take"]]` and `[["set_if_absent"]]` atomic methods.
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
  set_if_absent = NULL,
  worker_safe = FALSE
) {
  if (!is.logical(worker_safe) || length(worker_safe) != 1L || is.na(worker_safe)) {
    err_input("custom_cache: worker_safe must be TRUE or FALSE")
  }
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
      "cache_backend: `remove` must be a function(key); state consumption ignores its return value (see `?custom_cache`)"
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
      worker_safe = FALSE,
      # Set to a function in initialize() when an atomic take implementation is
      # provided; remains NULL otherwise.  Duck-typing check
      # is.function(store[["take"]]) naturally returns TRUE/FALSE.
      take = NULL,
      set_if_absent = NULL,
      initialize = function(
        .get,
        .set,
        .remove,
        .take,
        .info,
        .set_if_absent,
        .worker_safe
      ) {
        self[["worker_safe"]] <- .worker_safe
        private[[".get"]] <- .get
        private[[".set"]] <- .set
        private[[".remove"]] <- .remove
        private[[".info"]] <- .info
        if (!is.null(.take)) {
          self[["take"]] <- function(key, missing = NULL) .take(key, missing)
        }
        if (!is.null(.set_if_absent)) {
          self[["set_if_absent"]] <- function(key, value, ttl = NULL) {
            .set_if_absent(key, value, ttl)
          }
        }
      },
      get = function(key, missing = NULL) {
        private[[".get"]](key, missing)
      },
      set = function(key, value) {
        private[[".set"]](key, value)
        invisible(NULL)
      },
      remove = function(key) {
        # Preserve the backend's return value and visibility for direct callers.
        # State consumption uses atomic take or a post-removal absence check.
        private[[".remove"]](key)
      },
      info = function() {
        if (is.null(private[[".info"]])) {
          return(list())
        }
        out <- try(private[[".info"]](), silent = TRUE)
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

  CacheCls[["new"]](get, set, remove, take, info, set_if_absent, worker_safe)
}
