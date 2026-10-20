# SMART scope semantics are selected explicitly by a client policy. This file
# never rewrites the scopes sent over the wire or interprets patient identity.

smart_scope_parse <- function(scope, allow_v1_scopes = FALSE) {
  if (!grepl("^(patient|user|system)/", scope)) {
    return(list(kind = "literal", value = scope))
  }
  parts <- regmatches(
    scope,
    regexec(
      "^(patient|user|system)/(\\*|[A-Z][A-Za-z0-9]*)\\.([^?]+)(?:\\?(.*))?$",
      scope,
      perl = TRUE
    )
  )[[1L]]
  if (!length(parts)) {
    return(list(kind = "unknown"))
  }
  interactions <- parts[[4L]]
  if (isTRUE(allow_v1_scopes) && interactions %in% c("read", "write", "*")) {
    interactions <- c(read = "rs", write = "cud", "*" = "cruds")[[interactions]]
  }
  if (!nzchar(interactions) || !grepl("^c?r?u?d?s?$", interactions)) {
    return(list(kind = "unknown"))
  }
  constraint <- parts[[5L]]
  if (grepl("?", scope, fixed = TRUE)) {
    # Only simple search parameters with nonempty values are understood here.
    # Modifiers, chaining, _filter and malformed percent escapes stay unknown.
    # Even supported constraints are compared byte for byte, never decoded or
    # reordered: proving implication between FHIR searches needs a FHIR engine.
    if (
      !grepl(
        "^_?[A-Za-z][A-Za-z0-9-]*=[^&]+(?:&_?[A-Za-z][A-Za-z0-9-]*=[^&]+)*$",
        constraint,
        perl = TRUE
      ) ||
        grepl("(^|&)_filter=", constraint) ||
        grepl("%(?![A-Fa-f0-9]{2})", constraint, perl = TRUE) ||
        grepl("[[:space:]#]", constraint)
    ) {
      return(list(kind = "unknown"))
    }
  }
  list(
    kind = "resource",
    context = parts[[2L]],
    resource = parts[[3L]],
    interactions = strsplit(interactions, "", fixed = TRUE)[[1L]],
    constraint = constraint
  )
}

smart_scope_coverage <- function(requested, granted, allow_v1_scopes = FALSE) {
  requested <- normalize_scope_tokens(requested)
  granted <- normalize_scope_tokens(granted)
  if (
    length(requested) > 256L ||
      length(granted) > 256L ||
      sum(nchar(c(requested, granted), type = "bytes")) > 65536L
  ) {
    err_token("SMART scope comparison exceeds the supported size limit")
  }
  if (!length(requested)) {
    return(list(
      status = "covered",
      missing = character(),
      indeterminate = character()
    ))
  }
  # Index permissions once per comparison. Scanning every grant for every need
  # made granular scope sets quadratic in connection polling and validation.
  # This index is local: changed grants and policies are always re-evaluated.
  action_bits <- c(c = 1L, r = 2L, u = 4L, d = 8L, s = 16L)
  grants <- lapply(
    granted,
    smart_scope_parse,
    allow_v1_scopes = allow_v1_scopes
  )
  unknown_grant <- any(vapply(
    grants,
    function(grant) identical(grant[["kind"]], "unknown"),
    logical(1L)
  ))
  resources <- Filter(
    function(grant) identical(grant[["kind"]], "resource"),
    grants
  )
  resource_key <- function(permission, wildcard = FALSE) {
    if (!identical(permission[["kind"]], "resource")) {
      return("")
    }
    paste0(
      permission[["context"]],
      "/",
      if (wildcard) "*" else permission[["resource"]]
    )
  }
  grant_keys <- vapply(resources, resource_key, character(1L))
  constraints <- vapply(
    resources,
    function(grant) grant[["constraint"]],
    character(1L)
  )
  masks <- vapply(
    resources,
    function(grant) {
      as.integer(sum(action_bits[grant[["interactions"]]]))
    },
    integer(1L)
  )
  # '/' and '?' cannot occur in parsed context/resource names. A key without
  # '?' aggregates all constraints for possible overlap; '?' keys prove only
  # exact constraints (including the empty, unrestricted constraint).
  keys <- c(grant_keys, paste0(grant_keys, "?", constraints, recycle0 = TRUE))
  masks <- rep(masks, 2L)
  distinct_keys <- unique(keys)
  positions <- match(keys, distinct_keys)
  permissions <- integer(length(distinct_keys))
  for (i in seq_along(positions)) {
    position <- positions[[i]]
    permissions[[position]] <- bitwOr(permissions[[position]], masks[[i]])
  }
  # Vectorized match hashes the keys without interning untrusted scope strings
  # as environment names, which also have a 10,000-byte limit in R.
  lookup <- function(queries) {
    c(0L, permissions)[match(queries, distinct_keys, nomatch = 0L) + 1L]
  }
  needs <- lapply(
    requested,
    smart_scope_parse,
    allow_v1_scopes = allow_v1_scopes
  )
  need_keys <- vapply(needs, resource_key, character(1L))
  wildcard_keys <- vapply(needs, resource_key, character(1L), wildcard = TRUE)
  constraints <- vapply(
    needs,
    function(need) need[["constraint"]] %||% "",
    character(1L)
  )
  covered <- bitwOr(
    lookup(paste0(need_keys, "?")),
    lookup(paste0(wildcard_keys, "?"))
  )
  covered <- bitwOr(
    covered,
    bitwOr(
      lookup(paste0(need_keys, "?", constraints)),
      lookup(paste0(wildcard_keys, "?", constraints))
    )
  )
  possible <- bitwOr(lookup(need_keys), lookup(wildcard_keys))
  possible[!nzchar(constraints)] <- 0L
  # Unknown syntax cannot establish coverage, even if spelled identically.
  if (unknown_grant) {
    possible[] <- 31L
  }
  missing <- indeterminate <- character()
  for (i in seq_along(requested)) {
    scope <- requested[[i]]
    need <- needs[[i]]
    if (identical(need[["kind"]], "literal")) {
      if (!scope %in% granted) {
        missing <- c(missing, scope)
      }
      next
    }
    if (identical(need[["kind"]], "unknown")) {
      indeterminate <- c(indeterminate, scope)
      next
    }
    mask <- as.integer(sum(action_bits[need[["interactions"]]]))
    if (bitwAnd(mask, covered[[i]]) == mask) {
      next
    }
    if (bitwAnd(mask, bitwOr(covered[[i]], possible[[i]])) == mask) {
      indeterminate <- c(indeterminate, scope)
    } else {
      missing <- c(missing, scope)
    }
  }
  list(
    status = if (length(missing)) {
      "insufficient"
    } else if (length(indeterminate)) {
      "indeterminate"
    } else {
      "covered"
    },
    missing = missing,
    indeterminate = indeterminate
  )
}

#' Retain SMART permissions within both the request ceiling and actual grant
#'
#' Broader wildcard grants remain token evidence. Replacement requests retain
#' only their intersection with the previous request and client configuration.
#' Compare individual interactions to preserve partial resource permissions.
#' @param client OAuthClient with the SMART scope policy.
#' @param granted Actual accepted scope evidence.
#' @param requested Previous configured or narrowed request ceiling.
#' @return A character vector of retained request scopes.
#' @keywords internal
#' @noRd
smart_authorization_retained_scopes <- function(client, granted, requested) {
  requested <- normalize_scope_tokens(requested)
  configured <- effective_client_scopes(client)
  covered <- function(scope, limit) {
    connection_scope_covered(client, scope, limit)
  }
  if (covered(requested, configured) && covered(requested, granted)) {
    return(requested)
  }
  if (covered(granted, requested) && covered(granted, configured)) {
    return(granted)
  }
  retained <- character()
  for (scope in union(requested, granted)) {
    if (covered(scope, retained)) {
      next
    }
    if (
      covered(scope, requested) &&
        covered(scope, configured) &&
        covered(scope, granted)
    ) {
      retained <- union(retained, scope)
      next
    }
    parsed <- smart_scope_parse(scope, client@scope_policy[["allow_v1_scopes"]])
    if (!identical(parsed[["kind"]], "resource")) {
      next
    }
    prefix <- paste0(parsed[["context"]], "/", parsed[["resource"]], ".")
    suffix <- if (nzchar(parsed[["constraint"]])) {
      paste0("?", parsed[["constraint"]])
    } else {
      ""
    }
    interactions <- Filter(
      function(interaction) {
        atom <- paste0(prefix, interaction, suffix)
        covered(atom, requested) &&
          covered(atom, configured) &&
          covered(atom, granted)
      },
      parsed[["interactions"]]
    )
    if (length(interactions)) {
      retained <- union(
        retained,
        paste0(prefix, paste0(interactions, collapse = ""), suffix)
      )
    }
  }
  retained
}

client_uses_smart_scopes <- function(client) {
  identical(client@scope_policy[["profile"]], "smart")
}

client_scope_coverage <- function(client, requested, granted) {
  if (
    token_targets_configured(client) &&
      identical(client@provider@token_target_mode, "microsoft")
  ) {
    requested <- normalize_scope_tokens(requested)
    missing <- requested[
      !token_target_scope_keys(client, requested) %in%
        token_target_scope_keys(client, granted)
    ]
    return(list(
      status = if (length(missing)) "insufficient" else "covered",
      missing = missing,
      indeterminate = character()
    ))
  }
  policy <- client@scope_policy
  if (!length(policy)) {
    return(evaluate_scope_coverage(requested, granted))
  }
  if (
    client_uses_smart(client) &&
      identical(client@smart[["online_access_policy"]], "allow_offline") &&
      "offline_access" %in% normalize_scope_tokens(granted)
  ) {
    requested <- normalize_scope_tokens(requested)
    requested[requested == "online_access"] <- "offline_access"
  }
  evaluate_scope_coverage(
    requested,
    granted,
    profile = policy[["profile"]],
    version = policy[["version"]],
    allow_v1_scopes = policy[["allow_v1_scopes"]]
  )
}

# This internal policy is installed by the SMART client constructor, not by
# recognizing scope spelling. Keep generic client construction and wire defaults.
validate_client_scope_policy <- function(policy) {
  if (identical(policy, list())) {
    return(NULL)
  }
  if (
    !is.list(policy) ||
      !identical(
        sort(names(policy)),
        sort(c("profile", "version", "allow_v1_scopes"))
      ) ||
      !is_valid_string(policy[["profile"]]) ||
      !policy[["profile"]] %in% c("oauth", "smart") ||
      !identical(policy[["version"]], 1L) ||
      !is.logical(policy[["allow_v1_scopes"]]) ||
      length(policy[["allow_v1_scopes"]]) != 1L ||
      is.na(policy[["allow_v1_scopes"]])
  ) {
    return("OAuthClient: invalid scope policy")
  }
  if (
    identical(policy[["profile"]], "oauth") &&
      isTRUE(policy[["allow_v1_scopes"]])
  ) {
    return("OAuthClient: generic scope policy cannot contain SMART settings")
  }
  NULL
}

smart_verify_scope_grant <- function(client, granted, is_refresh, prior) {
  # Validate even an optional-only grant before a status/request can use it.
  smart_scope_coverage(
    character(),
    granted,
    client@scope_policy[["allow_v1_scopes"]]
  )
  if (
    client_uses_smart(client) &&
      !identical(client@smart[["online_access_policy"]], "allow_offline") &&
      "online_access" %in% effective_client_scopes(client) &&
      !"offline_access" %in% effective_client_scopes(client) &&
      "offline_access" %in% granted
  ) {
    err_token(
      "SMART offline negotiation requires online_access_policy = 'allow_offline'"
    )
  }
  if (
    !identical(
      client_scope_coverage(
        client,
        client@required_scopes,
        granted
      )[["status"]],
      "covered"
    )
  ) {
    err_token("SMART grant does not establish all required permissions")
  }
  if (
    isTRUE(is_refresh) &&
      (is.null(prior) ||
        !identical(
          client_scope_coverage(
            client,
            granted,
            prior
          )[["status"]],
          "covered"
        ))
  ) {
    err_token(
      "SMART refresh grant exceeds or cannot be compared with the prior grant"
    )
  }
  invisible(TRUE)
}
