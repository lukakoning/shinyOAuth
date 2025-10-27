#' Create a custom cache backend (cachem-like)
#'
#' @description
#' Builds a minimal cachem-like cache backend object that exposes cachem-compatible methods:
#' `$get(key, missing)`, `$set(key, value)`, `$remove(key)`, and `$info()`.
#'
#' Use this helper when you want to plug a custom state store or JWKS cache
#' into 'shinyOAuth', when [cachem::cache_mem()] or [cachem::cache_disk()]
#' are not suitable. This may be useful specifically when you deploy
#' a Shiny app to a multi-process environment with non-sticky workers.
#' In such cases, you may want to use a shared external cache (e.g., database,
#' Redis, Memcached).
#'
#' The resulting object can be used in both places where 'shinyOAuth' accepts a cache-like object:
#' - OAuthClient@state_store (requires `$get`, `$set`, `$remove`; optional `$info`)
#' - OAuthProvider@jwks_cache (requires `$get`, `$set`; optional `$remove`, `$info`)
#'
#' The `$info()` method is optional, but if provided and it returns a list with
#' `max_age` (seconds), shinyOAuth will align cookie/issued_at TTLs to that value.
#'
#' @param get A function(key, missing = NULL) -> value. Required.
#' Should return the stored value, or the `missing` argument if the key is not present.
#' The `missing` parameter is mandatory because both `OAuthClient` and
#' `OAuthProvider` validators will pass it explicitly.
#'
#' @param set A function(key, value) -> invisible(NULL). Required.
#' Should store the value under the given key
#'
#' @param remove A function(key) -> logical or sentinel. Required.
#'
#'   For state stores, this enforces single-use eviction. If your backend performs
#'   an atomic "get-and-delete" (e.g., SQL DELETE .. RETURNING), you may supply
#'   a function which does nothing here but returns `TRUE`. (The login flow will always attempt to call
#'   `$remove()` after `$get()` as a best-effort cleanup.)
#'
#'   Recommended contract for interoperability and strong replay protection:
#'   - Return `TRUE` when a key was actually deleted or if it already did not exist
#'   - Return `FALSE` when they key could not be deleted or when it is unknown if
#'   they key was deleted
#'
#'   When the return value is not `TRUE`, 'shinyOAuth' will attempt to retrieve
#'   the value from the state store to check if it may still be present; if that
#'   fails (i.e., key is not present), it will treat the removal as succesful.
#'   If it does find the key, it will produce an error indicating that removal
#'   did not succeed.
#'
#' @param info Function() -> list(max_age = seconds, ...). Optional
#'
#'   This may be provided to because TTL information from `$info()` is used to
#'   align browser cookie max age in `oauth_module_server()`
#'
#' @return An R6 object exposing cachem-like `$get/$set/$remove/$info` methods
#'
#' @example inst/examples/custom_cache.R
#'
#' @export
custom_cache <- function(get, set, remove, info = NULL) {
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
  # Validate optional info hook if provided
  if (is.null(info)) {
    info <- function() list()
  } else if (!is.function(info)) {
    err_input(
      "cache_backend: `info` must be a function() -> list(max_age = seconds, ...) (see `?custom_cache`)"
    )
  }

  CacheCls <- R6::R6Class(
    classname = "shinyOAuthCustomCache",
    public = list(
      initialize = function(.get, .set, .remove, .info) {
        private$.get <- .get
        private$.set <- .set
        private$.remove <- .remove
        private$.info <- .info
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

  CacheCls$new(get, set, remove, info)
}
