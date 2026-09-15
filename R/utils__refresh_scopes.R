# Explicit managed refresh requests use the target's existing scope evaluator.
# The request is bounded plain data so the same policy can run in async workers.
refresh_scope_request <- function(
  client,
  token,
  scopes,
  required_scopes = character()
) {
  if (
    !is.character(scopes) ||
      !length(scopes) ||
      length(scopes) > 128L ||
      anyNA(scopes) ||
      sum(nchar(scopes, type = "bytes")) > 8192L
  ) {
    err_input("Refresh scopes must be a non-empty, bounded character vector")
  }
  validate_scopes(scopes)
  scopes <- normalize_scope_tokens(scopes)
  if (length(scopes) > 128L) {
    err_input("Too many refresh scope tokens")
  }
  covered <- function(requested, granted) {
    identical(
      client_scope_coverage(client, requested, granted)[["status"]],
      "covered"
    )
  }
  configured <- effective_client_scopes(client)
  # Retain accepted SMART persistence negotiation when narrowing permissions.
  # Only extend this ceiling with explicit opt-in and a current offline grant.
  if (
    client_uses_smart(client) &&
      identical(client@smart[["online_access_policy"]], "allow_offline") &&
      "online_access" %in% configured &&
      "offline_access" %in% token@granted_scopes
  ) {
    configured <- union(configured, "offline_access")
  }
  if (
    !covered(scopes, token@granted_scopes) ||
      !covered(scopes, configured)
  ) {
    err_token(
      "Refresh scopes must be covered by the current grant and target configuration"
    )
  }
  required_scopes <- normalize_scope_tokens(c(
    required_scopes,
    client@required_scopes
  ))
  # Refresh still performs the provider's required UserInfo request. Reject
  # removal of its OIDC permission before a rotating refresh token is used.
  if (
    provider_uses_oidc(client@provider) &&
      isTRUE(client@provider@userinfo_required)
  ) {
    if (!"openid" %in% scopes) {
      err_token(
        "Refresh scopes must retain openid while OIDC UserInfo is required"
      )
    }
    required_scopes <- normalize_scope_tokens(c(required_scopes, "openid"))
  }
  if (!covered(required_scopes, scopes)) {
    err_token("Refresh scopes must retain the target's required permissions")
  }
  list(scopes = scopes, required_scopes = required_scopes)
}

validate_refresh_scope_request <- function(client, token, request) {
  if (is.null(request)) {
    return(NULL)
  }
  if (
    !is.list(request) ||
      !identical(names(request), c("scopes", "required_scopes")) ||
      !is.character(request[["required_scopes"]])
  ) {
    err_config("Invalid internal refresh scope request")
  }
  checked <- refresh_scope_request(
    client,
    token,
    request[["scopes"]],
    request[["required_scopes"]]
  )
  if (!identical(request, checked)) {
    err_config("Invalid internal refresh scope request")
  }
  request
}

validate_refresh_scope_grant <- function(client, granted, request) {
  if (is.null(request)) {
    return(invisible(NULL))
  }
  if (
    !identical(
      client_scope_coverage(client, granted, request[["scopes"]])[["status"]],
      "covered"
    )
  ) {
    err_token(
      "Refreshed grant exceeds or cannot be compared with the requested scope limit"
    )
  }
  if (
    !identical(
      client_scope_coverage(client, request[["required_scopes"]], granted)[[
        "status"
      ]],
      "covered"
    )
  ) {
    err_token(
      "Refreshed grant does not retain the target's required permissions"
    )
  }
  invisible(NULL)
}

# SMART 2.2 permits explicit scope only for a strict subset of the original
# launch grant. Compare permissions, including equivalent SMART spellings.
smart_refresh_request_scopes <- function(client, token, request = NULL) {
  scopes <- request[["scopes"]] %||% token@granted_scopes
  original <- token@original_granted_scopes
  if (!length(scopes) || !length(original)) {
    err_token(
      "SMART refresh requires a non-empty grant and its original scope evidence; authorize again"
    )
  }
  covered <- function(need, grant) {
    identical(client_scope_coverage(client, need, grant)[["status"]], "covered")
  }
  if (!covered(scopes, original)) {
    err_token("SMART refresh scopes cannot exceed the original grant")
  }
  if (covered(original, scopes)) NULL else scopes
}
