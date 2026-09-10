# SMART scope semantics are selected explicitly by a client policy. This file
# never rewrites the scopes sent over the wire or interprets patient identity.

smart_scope_parse <- function(scope, allow_v1 = FALSE) {
  if (!grepl("^(patient|user|system)/", scope)) {
    return(list(kind = "literal", value = scope))
  }
  parts <- regmatches(scope, regexec(
    "^(patient|user|system)/(\\*|[A-Z][A-Za-z0-9]*)\\.([^?]+)(?:\\?(.*))?$",
    scope,
    perl = TRUE
  ))[[1L]]
  if (!length(parts)) {
    return(list(kind = "unknown"))
  }
  interactions <- parts[[4L]]
  if (isTRUE(allow_v1) && interactions %in% c("read", "write", "*")) {
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
      !grepl("^[A-Za-z][A-Za-z0-9-]*=[^&]+(?:&[A-Za-z][A-Za-z0-9-]*=[^&]+)*$",
        constraint,
        perl = TRUE
      ) ||
        grepl("%(?![A-Fa-f0-9]{2})", constraint, perl = TRUE) ||
        grepl("[[:space:]#]", constraint)
    ) {
      return(list(kind = "unknown"))
    }
  }
  list(
    kind = "resource", context = parts[[2L]], resource = parts[[3L]],
    interactions = strsplit(interactions, "", fixed = TRUE)[[1L]],
    constraint = constraint
  )
}

smart_scope_coverage <- function(requested, granted, allow_v1 = FALSE) {
  requested <- normalize_scope_tokens(requested)
  granted <- normalize_scope_tokens(granted)
  if (length(requested) > 256L || length(granted) > 256L ||
    sum(nchar(c(requested, granted), type = "bytes")) > 65536L) {
    err_token("SMART scope comparison exceeds the supported size limit")
  }
  grants <- lapply(granted, smart_scope_parse, allow_v1 = allow_v1)
  missing <- indeterminate <- character()
  for (scope in requested) {
    need <- smart_scope_parse(scope, allow_v1)
    if (identical(need$kind, "literal")) {
      if (!scope %in% granted) missing <- c(missing, scope)
      next
    }
    if (identical(need$kind, "unknown")) {
      indeterminate <- c(indeterminate, scope)
      next
    }
    covered <- possible <- character()
    for (grant in grants) {
      if (identical(grant$kind, "unknown")) {
        # Unknown syntax cannot establish coverage, even if spelled identically.
        possible <- union(possible, need$interactions)
        next
      }
      if (
        !identical(grant$kind, "resource") ||
          !identical(need$context, grant$context) ||
          !(identical(grant$resource, "*") ||
            identical(need$resource, grant$resource))
      ) {
        next
      }
      if (!nzchar(grant$constraint) ||
        identical(need$constraint, grant$constraint)) {
        covered <- union(covered, grant$interactions)
      } else if (nzchar(need$constraint)) {
        possible <- union(possible, grant$interactions)
      }
    }
    if (all(need$interactions %in% covered)) next
    if (all(need$interactions %in% union(covered, possible))) {
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
    missing = missing, indeterminate = indeterminate
  )
}

client_uses_smart_scopes <- function(client) {
  identical(client@scope_policy$profile, "smart")
}

client_scope_coverage <- function(client, requested, granted) {
  policy <- client@scope_policy
  if (!length(policy)) return(evaluate_scope_coverage(requested, granted))
  evaluate_scope_coverage(requested, granted,
    profile = policy$profile,
    version = policy$version, allow_v1 = policy$allow_v1
  )
}

# This internal policy is installed by the SMART target constructor, not by
# recognizing scope spelling. Keep generic client construction and wire defaults.
validate_client_scope_policy <- function(policy) {
  if (identical(policy, list())) return(NULL)
  if (
    !is.list(policy) ||
      !identical(
        sort(names(policy)),
        sort(c("profile", "version", "allow_v1", "required_scopes"))
      ) ||
      !is_valid_string(policy$profile) ||
      !policy$profile %in% c("oauth", "smart") ||
      !identical(policy$version, 1L) ||
      !is.logical(policy$allow_v1) || length(policy$allow_v1) != 1L ||
      is.na(policy$allow_v1) || !is.character(policy$required_scopes)
  ) {
    return("OAuthClient: invalid scope policy")
  }
  if (identical(policy$profile, "oauth") &&
    (isTRUE(policy$allow_v1) || length(policy$required_scopes))) {
    return("OAuthClient: generic scope policy cannot contain SMART settings")
  }
  valid <- tryCatch(
    {
      validate_scopes(policy$required_scopes)
      identical(evaluate_scope_coverage(
        policy$required_scopes,
        policy$required_scopes, policy$profile, policy$version,
        policy$allow_v1
      )$status, "covered")
    },
    error = function(e) FALSE
  )
  if (!valid) {
    return("OAuthClient: unsupported required scope syntax")
  }
  NULL
}

smart_verify_scope_grant <- function(client, granted, is_refresh, prior) {
  # Validate even an optional-only grant before a status/request can use it.
  smart_scope_coverage(character(), granted, client@scope_policy$allow_v1)
  if (!identical(client_scope_coverage(
    client,
    client@scope_policy$required_scopes, granted
  )$status, "covered")) {
    err_token("SMART grant does not establish all required permissions")
  }
  if (isTRUE(is_refresh) &&
    (is.null(prior) || !identical(client_scope_coverage(
      client,
      granted, prior
    )$status, "covered"))) {
    err_token("SMART refresh grant exceeds or cannot be compared with the prior grant")
  }
  invisible(TRUE)
}
