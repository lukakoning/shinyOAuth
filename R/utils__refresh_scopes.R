# Explicit managed refresh requests use the target's existing scope evaluator.
# The request is bounded plain data so the same policy can run in async workers.
refresh_scope_request <- function(client, token, scopes, required_scopes = character()) {
  if (!is.character(scopes) || !length(scopes) || length(scopes) > 128L ||
      anyNA(scopes) || sum(nchar(scopes, type = "bytes")) > 8192L) {
    err_input("Refresh scopes must be a non-empty, bounded character vector")
  }
  validate_scopes(scopes)
  scopes <- normalize_scope_tokens(scopes)
  if (length(scopes) > 128L) err_input("Too many refresh scope tokens")
  covered <- function(requested, granted) {
    identical(client_scope_coverage(client, requested, granted)$status, "covered")
  }
  if (!covered(scopes, token@granted_scopes) ||
      !covered(scopes, effective_client_scopes(client))) {
    err_token("Refresh scopes must be covered by the current grant and target configuration")
  }
  required_scopes <- normalize_scope_tokens(c(required_scopes, client@required_scopes))
  if (!covered(required_scopes, scopes)) {
    err_token("Refresh scopes must retain the target's required permissions")
  }
  list(scopes = scopes, required_scopes = required_scopes)
}

validate_refresh_scope_request <- function(client, token, request) {
  if (is.null(request)) return(NULL)
  if (!is.list(request) || !identical(names(request), c("scopes", "required_scopes")) ||
      !is.character(request$required_scopes)) {
    err_config("Invalid internal refresh scope request")
  }
  checked <- refresh_scope_request(client, token, request$scopes, request$required_scopes)
  if (!identical(request, checked)) err_config("Invalid internal refresh scope request")
  request
}

validate_refresh_scope_grant <- function(client, granted, request) {
  if (is.null(request)) return(invisible(NULL))
  if (!identical(client_scope_coverage(client, granted, request$scopes)$status, "covered")) {
    err_token("Refreshed grant exceeds or cannot be compared with the requested scope limit")
  }
  if (!identical(client_scope_coverage(client, request$required_scopes, granted)$status, "covered")) {
    err_token("Refreshed grant does not retain the target's required permissions")
  }
  invisible(NULL)
}
