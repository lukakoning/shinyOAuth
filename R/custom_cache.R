# This file contains the helper for building custom cache backends for
# shinyOAuth
# Used for storing login state or provider signing keys in a shared backend
# instead of the default in-memory cache

# 1 Custom cache helper --------------------------------------------------------

## 1.1 Build cachem-like backend -----------------------------------------------

# Functions in this section create cachem-compatible objects from caller-supplied
# backend functions.

#' Create a custom cache backend (cachem-like)
#'
#' @description
#' Builds a small cachem-like backend object with methods compatible with what
#' shinyOAuth needs: `$get(key, missing)`, `$set(key, value)`, `$remove(key)`,
#' and optional `$info()`.
#'
#' Use this helper when you want to plug a custom state store or JWKS cache
#' into shinyOAuth, when [cachem::cache_mem()] is not suitable (e.g.,
#' multi-process deployments with non-sticky workers).
#' In such cases, you may want to use a shared external cache (e.g., database,
#' Redis, Memcached).
#'
#' The resulting object can be used in both places where shinyOAuth accepts a cache-like object:
#' - OAuthClient@state_store (requires `$get`, `$set`, `$remove`; optional `$info`)
#' - OAuthProvider@jwks_cache (requires `$get`, `$set`; optional `$remove`, `$info`)
#'
#' For `OAuthClient@state_store`, stored values are small lists. `browser_token`
#' must always round-trip as a non-empty string. `pkce_code_verifier` and
#' `nonce` are required only when the provider enables PKCE or nonce
#' validation; otherwise stores may preserve them as `NULL` or omit them when
#' serializing.
#'
#' The `$info()` method is optional, but if provided and it returns a list with
#' `max_age` (seconds), shinyOAuth will align browser cookie max-age in
#' [oauth_module_server()] to that value.
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
#' @param info Function() -> list(max_age = seconds, ...). Optional
#'
#'   TTL information from `$info()` is used to align browser cookie max age in
#'   [oauth_module_server()].
#'
#' @return An R6 object exposing cachem-like `$get/$set/$remove/$info` methods
#'
#' @example inst/examples/custom_cache.R
#'
#' @export
custom_cache <- function(get, set, remove, take = NULL, info = NULL) {
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
      initialize = function(.get, .set, .remove, .take, .info) {
        private$.get <- .get
        private$.set <- .set
        private$.remove <- .remove
        private$.info <- .info
        if (!is.null(.take)) {
          self$take <- function(key, missing = NULL) .take(key, missing)
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

  CacheCls$new(get, set, remove, take, info)
}
