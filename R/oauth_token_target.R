#' Declare an API token target
#'
#' Build one entry for [oauth_client()]'s `token_targets`. Give the entry a name
#' in that list, such as `calendar`, then select it with a connection method's
#' `target` argument. Plain named lists with the same fields are also accepted.
#'
#' @param resource Exact API identifier sent to the authorization provider: an
#'   absolute URI, such as `"urn:example:calendar"`, or a Microsoft application
#'   GUID. This identifies the token's audience; HTTP destinations are configured
#'   separately through client `resource_bases`.
#' @param scopes Non-empty character vector of requested API permissions. A
#'   space-separated string is also accepted. Identity and refresh-consent scopes
#'   belong in client `scopes`.
#' @param required_scopes Minimum permissions for this API, default `character()`.
#'   The default permits reduced grants; specify the permissions that every usable
#'   token for this target must cover.
#' @param resource_ids Names of approved client `resource_bases` associated with
#'   this target. Optional when only exporting tokens to another R package.
#' @param scope_aliases Optional Microsoft short permission names used in token
#'   responses. See [oauth_client()] for provider-specific restrictions.
#'
#' @details
#' This helper checks field syntax and size limits. Client construction checks
#' provider support, scope coverage, API associations and relationships between
#' targets. It preserves the resource identifier exactly and normalizes scopes
#' into distinct tokens.
#'
#' @return A plain named list suitable for an entry in `token_targets`.
#' @examples
#' oauth_token_target(
#'   "urn:example:calendar",
#'   c("calendar.read", "calendar.write"),
#'   required_scopes = "calendar.read",
#'   resource_ids = "calendar_api"
#' )
#' @export
oauth_token_target <- function(
  resource,
  scopes,
  required_scopes = character(),
  resource_ids = character(),
  scope_aliases = character()
) {
  if (
    !is_valid_string(resource) || nchar(resource, type = "bytes") > 2048L ||
      (!is_guid_like(resource) && !is.null(resource_indicator_problem(resource)))
  ) {
    err_input("resource must be an absolute URI or Microsoft GUID of at most 2048 bytes")
  }
  fields <- list(
    scopes = scopes,
    required_scopes = required_scopes %||% character(),
    scope_aliases = scope_aliases %||% character()
  )
  for (name in names(fields)) {
    value <- fields[[name]]
    if (!is.character(value) || anyNA(value)) {
      err_input(paste0(name, " must be a character vector without NA"))
    }
    value <- connection_scope_arguments(value)
    if (!authorization_scopes_bounded(value)) {
      err_input(paste0(name, " exceeds 128 distinct scopes or 8192 scope bytes"))
    }
    fields[[name]] <- value
  }
  if (!length(fields[["scopes"]])) {
    err_input("scopes must include at least one API permission")
  }
  resource_ids <- resource_ids %||% character()
  if (
    !is.character(resource_ids) || anyNA(resource_ids) ||
      length(resource_ids) > 64L || anyDuplicated(resource_ids) ||
      !all(grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", resource_ids))
  ) {
    err_input("resource_ids must contain distinct approved API base names")
  }
  target <- list(resource = resource, scopes = fields[["scopes"]])
  if (length(fields[["required_scopes"]])) {
    target[["required_scopes"]] <- fields[["required_scopes"]]
  }
  if (length(resource_ids)) {
    target[["resource_ids"]] <- unname(resource_ids)
  }
  if (length(fields[["scope_aliases"]])) {
    target[["scope_aliases"]] <- fields[["scope_aliases"]]
  }
  target
}
