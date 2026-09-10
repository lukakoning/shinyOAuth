# A reference resolves current credentials on every operation. P3 can supply an
# owner-scoped store resolver; the initial adapter resolves one Shiny module's
# reactive token in the session that created it.
OAuthConnectionRef <- R6::R6Class(
  "OAuthConnectionRef",
  cloneable = FALSE,
  lock_class = TRUE,
  private = list(
    .id = NULL,
    .target = NULL,
    .resolve = NULL,
    record = function() {
      record <- tryCatch(private$.resolve(), error = function(...) {
        err_token("Connection is unavailable")
      })
      if (
        !is.list(record) ||
          !identical(record$target, private$.target) ||
          (!is.null(record$token) && !S7::S7_inherits(record$token, OAuthToken))
      ) {
        err_token("Connection is unavailable")
      }
      record
    }
  ),
  active = list(
    id = function(value) {
      if (!missing(value)) {
        err_input("Connection IDs are read-only")
      }
      private$.id
    }
  ),
  public = list(
    initialize = function(id, target, resolve) {
      if (!is.null(private$.id)) {
        err_input("Connection references are read-only")
      }
      private$.id <- id
      private$.target <- target
      private$.resolve <- resolve
      invisible(self)
    },
    is_usable = function() {
      tryCatch(
        connection_record_status(private$record()) %in% c("active", "limited"),
        error = function(...) FALSE
      )
    },
    summary = function() {
      record <- private$record()
      list(
        connection_id = private$.id,
        target_label = record$target$label,
        status = connection_record_status(record),
        expires_at = if (is.null(record$token)) {
          NA_real_
        } else {
          record$token@expires_at
        },
        resource_ids = names(record$target$resource_bases)
      )
    },
    request = function(
      resource_id,
      path = "",
      query = NULL,
      method = "GET",
      required_scopes = character()
    ) {
      connection_record_request(
        private$record(),
        resource_id,
        path,
        query,
        method,
        required_scopes
      )
    },
    print = function(...) {
      cat(
        "<OAuthConnectionRef: session-bound reference; credentials redacted>\n"
      )
      invisible(self)
    }
  )
)
