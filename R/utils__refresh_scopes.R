# Explicit managed refresh requests use the target's existing scope evaluator.
# The request is bounded plain data so the same policy can run in async workers.
authorization_scopes_bounded <- function(scopes) {
  scopes <- normalize_scope_tokens(scopes)
  length(scopes) <= 128L && sum(nchar(scopes, type = "bytes")) <= 8192L
}

# Consent to issue a refresh token is an authorization request property. OIDC
# providers need not repeat offline_access in the access token's scope evidence.
# Pass the previous policy on automatic refresh, or the explicit scope request
# when narrowing, so a deliberately removed consent is never restored.
authorization_retained_scopes <- function(client, token, requested) {
  # Standalone launch context is requested on the next authorization, not
  # established by access-token scope evidence. Automatic refresh carries this
  # policy forward; an explicit scope list replaces optional context requests.
  context <- if (
    client_uses_smart(client) &&
      identical(client@smart[["launch"]], "standalone")
  ) {
    intersect(
      normalize_scope_tokens(requested),
      intersect(client@scopes, c("launch/patient", "launch/encounter"))
    )
  } else {
    character()
  }
  union(
    setdiff(token@granted_scopes, authorization_extra_scopes(client, token)),
    union(authorization_refresh_consent(client, requested), context)
  )
}

# Only authenticated authorization history can supply consent omitted from an
# ordinary OIDC access token. It is never evidence of an API permission.
authorization_refresh_consent <- function(client, scopes) {
  if (
    !provider_uses_oidc(client@provider) ||
      client_uses_smart(client) ||
      token_targets_configured(client)
  ) {
    return(character())
  }
  intersect(scopes, "offline_access")
}

# Ordinary OAuth accepts provider evidence beyond the configured permissions.
# Keep it as evidence, never as an outgoing request or an operation permission.
# SMART scopes can overlap semantically, so retain their stricter grant policy.
authorization_extra_scopes <- function(client, token) {
  if (client_uses_smart_scopes(client) || token_targets_configured(client)) {
    return(character())
  }
  setdiff(token@granted_scopes, effective_client_scopes(client))
}

authorization_extra_scope_limit <- function(client, scopes, requested) {
  if (is.null(scopes)) {
    return(character())
  }
  validate_scopes(scopes)
  scopes <- normalize_scope_tokens(scopes)
  if (
    (length(scopes) &&
      (client_uses_smart_scopes(client) || token_targets_configured(client))) ||
      length(intersect(scopes, effective_client_scopes(client))) ||
      !authorization_scopes_bounded(c(requested, scopes))
  ) {
    err_input("Invalid previously accepted extra scope limit")
  }
  scopes
}

authorization_scope_limit <- function(client, scopes) {
  validate_scopes(scopes)
  scopes <- normalize_scope_tokens(scopes)
  if (!length(scopes)) {
    err_input("Reauthorization requires a non-empty retained permission limit")
  }
  # A new OIDC login always needs openid, independently of the previous access
  # token's scope evidence. Optional identity and API permissions stay narrowed.
  scopes <- ensure_openid_scope(scopes, client@provider, warn = FALSE)
  # Standalone patient access needs a new patient selection on each login.
  # Launch context need not appear in the previous access token's scope claim.
  if (
    client_uses_smart(client) &&
      identical(client@smart[["launch"]], "standalone") &&
      any(startsWith(scopes, "patient/")) &&
      "launch/patient" %in% client@scopes
  ) {
    scopes <- union(scopes, "launch/patient")
  }
  required <- client@required_scopes
  if (
    provider_uses_oidc(client@provider) &&
      isTRUE(client@provider@userinfo_required)
  ) {
    required <- union(required, "openid")
  }
  if (
    !length(scopes) ||
      !authorization_scopes_bounded(scopes) ||
      !(if (token_targets_configured(client)) {
        token_target_authorization_allowed(client, scopes)
      } else {
        connection_scope_covered(
          client,
          scopes,
          effective_client_scopes(client)
        )
      }) ||
      !connection_scope_covered(client, required, scopes)
  ) {
    err_input(
      "Reauthorization scopes must retain required permissions within the client configuration"
    )
  }
  scopes
}

refresh_scope_request <- function(
  client,
  token,
  scopes,
  required_scopes = character(),
  accepted_extra_scopes = NULL,
  refresh_consent = character()
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
  if (
    !is.character(refresh_consent) ||
      anyNA(refresh_consent) ||
      !identical(
        refresh_consent,
        authorization_refresh_consent(client, refresh_consent)
      )
  ) {
    err_config("Invalid retained refresh consent")
  }
  refresh_consent <- intersect(refresh_consent, scopes)
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
    !covered(scopes, union(token@granted_scopes, refresh_consent)) ||
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
  request <- list(scopes = scopes, required_scopes = required_scopes)
  extra <- authorization_extra_scope_limit(
    client,
    accepted_extra_scopes,
    scopes
  )
  if (!all(extra %in% authorization_extra_scopes(client, token))) {
    err_token("Extra scopes must have been accepted in the current grant")
  }
  if (length(extra)) {
    request[["accepted_extra_scopes"]] <- extra
  }
  if (length(refresh_consent)) {
    request[["refresh_consent"]] <- refresh_consent
  }
  request
}

validate_refresh_scope_request <- function(client, token, request) {
  if (is.null(request)) {
    return(NULL)
  }
  if (
    !is.list(request) ||
      is.null(names(request)) ||
      anyDuplicated(names(request)) ||
      !all(
        names(request) %in%
          c(
            "scopes",
            "required_scopes",
            "accepted_extra_scopes",
            "refresh_consent"
          )
      ) ||
      !is.character(request[["required_scopes"]])
  ) {
    err_config("Invalid internal refresh scope request")
  }
  checked <- refresh_scope_request(
    client,
    token,
    request[["scopes"]],
    request[["required_scopes"]],
    request[["accepted_extra_scopes"]],
    request[["refresh_consent"]] %||% character()
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
      client_scope_coverage(
        client,
        granted,
        union(
          request[["scopes"]],
          request[["accepted_extra_scopes"]]
        )
      )[["status"]],
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
