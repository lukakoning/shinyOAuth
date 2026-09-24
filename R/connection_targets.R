token_target_oidc_scopes <- function(client) {
  common <- c("openid", "profile", "email", "offline_access")
  if (identical(client@provider@token_target_mode, "microsoft")) {
    common
  } else {
    c(common, "address", "phone")
  }
}

token_targets_configured <- function(client) length(client@token_targets) > 0L

token_target_name <- function(client, target = NULL) {
  if (!token_targets_configured(client)) {
    if (!is.null(target)) {
      connection_access_error("unsupported_target")
    }
    return(NULL)
  }
  target <- target %||% client@default_token_target
  if (!is_valid_string(target) || !target %in% names(client@token_targets)) {
    connection_access_error("unknown_target")
  }
  target
}

token_target_prefix <- function(resource) paste0(resource, "/")

token_target_scopes_allowed <- function(
  client,
  target,
  scopes,
  ceiling = NULL
) {
  declaration <- client@token_targets[[target]]
  scopes <- normalize_scope_tokens(scopes)
  ceiling <- normalize_scope_tokens(
    ceiling %||%
      union(
        declaration[["scopes"]],
        intersect(
          effective_client_scopes(client),
          token_target_oidc_scopes(client)
        )
      )
  )
  if (
    !all(
      intersect(scopes, token_target_oidc_scopes(client)) %in%
        intersect(effective_client_scopes(client), ceiling)
    )
  ) {
    return(FALSE)
  }
  scopes <- setdiff(scopes, token_target_oidc_scopes(client))
  ceiling <- setdiff(ceiling, token_target_oidc_scopes(client))
  if (
    identical(client@provider@token_target_mode, "microsoft") &&
      identical(
        ceiling,
        paste0(token_target_prefix(declaration[["resource"]]), ".default")
      )
  ) {
    return(all(startsWith(
      scopes,
      token_target_prefix(declaration[["resource"]])
    )))
  }
  all(scopes %in% ceiling)
}

validate_token_targets <- function(client) {
  targets <- client@token_targets
  if (!length(targets)) {
    if (length(client@default_token_target)) {
      err_config("default_token_target requires token_targets")
    }
    return(invisible(NULL))
  }
  if (
    length(targets) > 16L ||
      is.null(names(targets)) ||
      anyDuplicated(names(targets)) ||
      anyNA(names(targets)) ||
      !all(grepl("^[A-Za-z][A-Za-z0-9_.-]{0,63}$", names(targets)))
  ) {
    err_config(
      "token_targets must be a named list of at most 16 distinct targets"
    )
  }
  if (!client@provider@token_target_mode %in% c("rfc8707", "microsoft")) {
    err_config(
      "The provider must explicitly enable a supported token_target_mode"
    )
  }
  for (field in c("extra_auth_params", "extra_token_params")) {
    if (
      "resource" %in% tolower(trimws(names(S7::prop(client@provider, field))))
    ) {
      err_config(paste0(
        "resource in provider ",
        field,
        " conflicts with token_targets; declare resources only in token_targets"
      ))
    }
  }
  if (
    !is_valid_string(client@default_token_target) ||
      !client@default_token_target %in% names(targets)
  ) {
    err_config("Several token targets require an explicit default_token_target")
  }
  if (
    length(client@resource) ||
      client_uses_smart(client) ||
      isTRUE(client@provider@userinfo_required)
  ) {
    err_config(
      "Token targets require resource to be unset, a non-SMART client, and userinfo_required = FALSE"
    )
  }
  if (
    length(setdiff(client@required_scopes, token_target_oidc_scopes(client)))
  ) {
    err_config(
      "With token targets, put API required_scopes inside each target declaration"
    )
  }
  if (!authorization_scopes_bounded(effective_client_scopes(client))) {
    err_config(
      "Token target authorizations allow at most 128 distinct scopes and 8192 scope bytes in total"
    )
  }
  if (identical(client@provider@token_target_mode, "microsoft")) {
    api_scopes <- setdiff(client@scopes, token_target_oidc_scopes(client))
    static <- endsWith(api_scopes, "/.default")
    if (any(static) && !all(static)) {
      err_config(
        "Microsoft client scopes cannot mix .default with explicit API permissions"
      )
    }
  }
  for (name in names(targets)) {
    item <- targets[[name]]
    if (
      !is.list(item) ||
        is.null(names(item)) ||
        anyDuplicated(names(item)) ||
        !all(c("resource", "scopes") %in% names(item)) ||
        !all(
          names(item) %in%
            c("resource", "scopes", "required_scopes", "resource_ids")
        )
    ) {
      err_config(
        "Each token target needs resource and scopes; optional fields are required_scopes and resource_ids"
      )
    }
    resource <- item[["resource"]]
    if (
      !is_valid_string(resource) ||
        !is.null(resource_indicator_problem(resource)) ||
        nchar(resource, type = "bytes") > 2048L
    ) {
      err_config(
        "A token target resource must be an absolute URI without a fragment or whitespace"
      )
    }
    scopes <- connection_scope_arguments(item[["scopes"]])
    if (
      !length(scopes) ||
        length(scopes) > 128L ||
        sum(nchar(scopes, type = "bytes")) > 8192L ||
        any(scopes %in% token_target_oidc_scopes(client)) ||
        !all(scopes %in% client@scopes)
    ) {
      err_config(
        "Target scopes must be non-empty API scopes included in the client scopes"
      )
    }
    required <- connection_scope_arguments(
      item[["required_scopes"]] %||% character()
    )
    if (!token_target_scopes_allowed(client, name, required)) {
      err_config(
        "Target required_scopes must be covered by that target's declaration"
      )
    }
    resources <- item[["resource_ids"]] %||% character()
    if (
      !is.character(resources) ||
        anyNA(resources) ||
        anyDuplicated(resources) ||
        !all(resources %in% names(client@resource_bases))
    ) {
      err_config("Target resource_ids must name declared resource_bases")
    }
    if (identical(client@provider@token_target_mode, "microsoft")) {
      prefix <- token_target_prefix(resource)
      static <- endsWith(scopes, "/.default")
      if (
        !all(startsWith(scopes, prefix)) ||
          (any(static) && !identical(scopes, paste0(prefix, ".default")))
      ) {
        err_config(
          "Microsoft target scopes must be qualified by their resource; .default must match that exact resource and be used alone"
        )
      }
    }
  }
  required <- lapply(names(targets), function(target) {
    token_target_required_scopes(client, target)
  })
  if (
    !authorization_scopes_bounded(ensure_openid_scope(
      token_target_authorization_scopes(client, required),
      client@provider,
      warn = FALSE
    ))
  ) {
    err_config(
      "Token target requirements exceed 128 distinct scopes or 8192 scope bytes in total"
    )
  }
  invisible(NULL)
}

token_target_limits <- function(client) {
  lapply(client@token_targets, function(item) {
    union(
      normalize_scope_tokens(item[["scopes"]]),
      intersect(
        effective_client_scopes(client),
        token_target_oidc_scopes(client)
      )
    )
  })
}

token_target_required_scopes <- function(client, target) {
  normalize_scope_tokens(c(
    client@required_scopes,
    client@token_targets[[target]][["required_scopes"]] %||% character()
  ))
}

token_target_reauthorization_limits <- function(client, limits) {
  if (is.null(limits)) {
    return(NULL)
  }
  limits <- validate_token_target_limits(client, limits)
  primary <- client@default_token_target
  if (length(limits[[primary]]) && provider_uses_oidc(client@provider)) {
    # Reauthorization starts a new validated login. Include its mandatory
    # protocol scope in code redemption without restoring optional permissions
    # or changing the retained scope limits of secondary targets.
    limits[[primary]] <- union(limits[[primary]], "openid")
  }
  validate_token_target_limits(client, limits)
}

validate_token_target_limits <- function(client, limits) {
  if (
    !is.list(limits) || !identical(names(limits), names(client@token_targets))
  ) {
    err_config("Invalid token target scope limits")
  }
  for (target in names(limits)) {
    scopes <- connection_scope_arguments(limits[[target]])
    if (
      length(scopes) > 128L ||
        sum(nchar(scopes, type = "bytes")) > 8192L ||
        !token_target_scopes_allowed(client, target, scopes)
    ) {
      err_config("Invalid token target scope limits")
    }
    limits[[target]] <- scopes
  }
  if (
    !authorization_scopes_bounded(ensure_openid_scope(
      token_target_authorization_scopes(client, limits),
      client@provider,
      warn = FALSE
    ))
  ) {
    err_token(
      "Token target scope limits exceed 128 distinct scopes or 8192 scope bytes in total"
    )
  }
  limits
}

token_target_request <- function(
  client,
  target = NULL,
  limits = NULL,
  scopes = NULL
) {
  target <- token_target_name(client, target)
  if (is.null(target)) {
    return(NULL)
  }
  limits <- validate_token_target_limits(
    client,
    limits %||% token_target_limits(client)
  )
  ceiling <- limits[[target]]
  if (!is.null(scopes)) {
    scopes <- connection_scope_arguments(scopes)
    if (
      !length(scopes) ||
        !token_target_scopes_allowed(client, target, scopes, ceiling)
    ) {
      connection_access_error("insufficient_scope")
    }
    ceiling <- scopes
  }
  if (!length(ceiling)) {
    connection_access_error("insufficient_scope")
  }
  required <- token_target_required_scopes(client, target)
  if (!token_target_scopes_allowed(client, target, required, ceiling)) {
    connection_access_error("insufficient_scope")
  }
  list(
    target = target,
    scopes = ceiling,
    required_scopes = required
  )
}

# Microsoft returns the resource's existing consented permissions. Reject an
# explicit API reduction before consuming the shared refresh credential; a
# refresh scope parameter cannot promise a narrower Microsoft access token.
token_target_refresh_request <- function(
  client,
  target,
  limits,
  scopes = NULL
) {
  request <- token_target_request(client, target, limits, scopes)
  if (
    !is.null(scopes) &&
      identical(client@provider@token_target_mode, "microsoft")
  ) {
    previous <- (limits %||% token_target_limits(client))[[request[["target"]]]]
    oidc <- token_target_oidc_scopes(client)
    if (
      !setequal(
        setdiff(normalize_scope_tokens(previous), oidc),
        setdiff(request[["scopes"]], oidc)
      )
    ) {
      connection_access_error("unsupported_scope_narrowing")
    }
  }
  request
}

validate_token_target_request <- function(client, request) {
  if (is.null(request)) {
    return(NULL)
  }
  if (
    !is.list(request) ||
      !identical(names(request), c("target", "scopes", "required_scopes"))
  ) {
    err_config("Invalid internal token target request")
  }
  checked <- token_target_request(
    client,
    request[["target"]],
    scopes = request[["scopes"]]
  )
  if (!identical(checked, request)) {
    err_config("Invalid internal token target request")
  }
  request
}

token_target_parameters <- function(client, request) {
  if (is.null(request)) {
    return(list())
  }
  params <- list(scope = paste(request[["scopes"]], collapse = " "))
  if (identical(client@provider@token_target_mode, "rfc8707")) {
    params[["resource"]] <- client@token_targets[[request[["target"]]]][[
      "resource"
    ]]
  }
  params
}

# Canonicalize only Microsoft's documented resource-qualified scope convention.
# No prefix or .default expansion is applied to ordinary OAuth providers.
token_target_response <- function(client, response, request) {
  if (is.null(request)) {
    return(response)
  }
  if (identical(client@provider@token_target_mode, "microsoft")) {
    if (is.null(response[["scope"]])) {
      err_token(
        "Microsoft target responses must include explicit scope evidence"
      )
    }
    scopes <- normalize_scope_tokens(response[["scope"]])
    if (any(endsWith(scopes, "/.default")) || ".default" %in% scopes) {
      err_token(
        "A .default response must identify the actual granted permissions"
      )
    }
    prefix <- token_target_prefix(client@token_targets[[request[["target"]]]][[
      "resource"
    ]])
    bare <- !scopes %in% token_target_oidc_scopes(client) &
      !grepl("[:/]", scopes)
    scopes[bare] <- paste0(prefix, scopes[bare])
    response[["scope"]] <- paste(scopes, collapse = " ")
  }
  response
}

validate_token_target_grant <- function(client, granted, request) {
  if (is.null(request)) {
    return(invisible(NULL))
  }
  if (
    !authorization_scopes_bounded(ensure_openid_scope(
      granted,
      client@provider,
      warn = FALSE
    )) ||
      !token_target_grant_scopes_allowed(
        client,
        request[["target"]],
        granted,
        request[["scopes"]]
      ) ||
      !all(
        union(client@required_scopes, request[["required_scopes"]]) %in% granted
      )
  ) {
    err_token(
      "Token response does not satisfy the selected target's scope limit"
    )
  }
  invisible(NULL)
}

# Keep full Microsoft grant evidence, including previously consented API scopes,
# but accept it only within the selected resource. This does not expand the
# application's retained operation limit.
token_target_grant_scopes_allowed <- function(
  client,
  target,
  granted,
  ceiling
) {
  if (!identical(client@provider@token_target_mode, "microsoft")) {
    return(token_target_scopes_allowed(client, target, granted, ceiling))
  }
  oidc <- token_target_oidc_scopes(client)
  api <- setdiff(granted, oidc)
  prefix <- token_target_prefix(client@token_targets[[target]][["resource"]])
  all(startsWith(api, prefix)) &&
    all(nchar(api) > nchar(prefix)) &&
    !any(endsWith(api, "/.default")) &&
    token_target_scopes_allowed(
      client,
      target,
      intersect(granted, oidc),
      ceiling
    )
}

# Keep refresh consent separate from access-token permission evidence. Providers
# such as Microsoft omit offline_access from access-token scopes even when they
# issue a refresh token. Carry only an already requested capability forward;
# an explicit request that removes it must never regain it from configuration.
token_target_retained_scopes <- function(client, token, request) {
  granted <- token_target_operation_scopes(
    client,
    request[["target"]],
    token@granted_scopes,
    request[["scopes"]]
  )
  union(
    granted,
    intersect(request[["scopes"]], "offline_access")
  )
}

# A bundle contains secondary token responses and per-target permission ceilings.
# The primary response remains the compatibility token and owns the current RT.
token_target_bundle <- function(client, token, limits = NULL) {
  if (!token_targets_configured(client)) {
    return(NULL)
  }
  limits <- validate_token_target_limits(
    client,
    limits %||% token_target_limits(client)
  )
  request <- token_target_request(client, limits = limits)
  validate_token_target_grant(client, token@granted_scopes, request)
  limits[[client@default_token_target]] <- token_target_retained_scopes(
    client,
    token,
    request
  )
  limits <- validate_token_target_limits(client, limits)
  bundle <- list(tokens = list(), limits = limits)
  validate_token_target_bundle_budget(client, token, bundle)
  bundle
}

token_target_select <- function(record, target = NULL) {
  client <- record[["client"]]
  target <- token_target_name(client, target)
  if (is.null(target)) {
    return(record)
  }
  record[["target"]] <- target
  record[["refresh_token"]] <- if (!is.null(record[["token"]])) {
    record[["token"]]@refresh_token
  } else {
    NA_character_
  }
  if (!identical(target, client@default_token_target)) {
    record[["token"]] <- record[["targets"]][["tokens"]][[target]]
  }
  record[["target_scopes"]] <- normalize_scope_tokens(
    record[["targets"]][["limits"]][[target]] %||%
      token_target_limits(client)[[target]]
  )
  requested <- normalize_scope_tokens(client@token_targets[[target]][[
    "scopes"
  ]])
  if (
    identical(client@provider@token_target_mode, "microsoft") &&
      any(endsWith(requested, "/.default"))
  ) {
    requested <- if (is.null(record[["token"]])) {
      character()
    } else {
      token_target_operation_scopes(
        client,
        target,
        record[["token"]]@granted_scopes,
        record[["target_scopes"]]
      )
    }
  }
  record[["target_requested_scopes"]] <- requested
  record[["target_required_scopes"]] <- token_target_required_scopes(
    client,
    target
  )
  record
}

token_target_commit <- function(client, primary, bundle, fresh, request) {
  validate_token_target_grant(client, fresh@granted_scopes, request)
  target <- request[["target"]]
  bundle[["limits"]][[target]] <- token_target_retained_scopes(
    client,
    fresh,
    request
  )
  bundle[["limits"]] <- validate_token_target_limits(client, bundle[["limits"]])
  refresh <- fresh@refresh_token
  if (identical(target, client@default_token_target)) {
    primary <- fresh
  } else {
    fresh@refresh_token <- NA_character_
    bundle[["tokens"]][[target]] <- fresh
    primary@refresh_token <- refresh
  }
  validate_token_target_bundle_budget(client, primary, bundle)
  list(token = primary, targets = bundle)
}

validate_token_target_bundle_budget <- function(client, primary, bundle) {
  scopes <- c(
    token_target_authorization_scopes(client, bundle[["limits"]]),
    if (!is.null(primary)) primary@granted_scopes,
    unlist(
      lapply(bundle[["tokens"]], function(token) token@granted_scopes),
      use.names = FALSE
    )
  )
  if (
    !authorization_scopes_bounded(ensure_openid_scope(
      scopes,
      client@provider,
      warn = FALSE
    ))
  ) {
    err_token(
      "Token target grants exceed 128 distinct scopes or 8192 scope bytes in total"
    )
  }
  invisible(NULL)
}

token_target_refresh_source <- function(record, request) {
  selected <- token_target_select(record, request[["target"]])[["token"]]
  source <- selected %||% record[["token"]]
  source@refresh_token <- record[["token"]]@refresh_token
  # All acquisitions keep the original validated subject/issuer baseline.
  source@original_id_token <- record[["token"]]@original_id_token
  source
}

token_target_bundle_encode <- function(bundle) {
  if (is.null(bundle)) {
    return(NULL)
  }
  bundle[["tokens"]] <- lapply(bundle[["tokens"]], function(token) {
    stats::setNames(
      lapply(connection_token_fields, function(field) S7::prop(token, field)),
      connection_token_fields
    )
  })
  connection_data_encode(bundle)
}

token_target_bundle_decode <- function(client, encoded) {
  if (is.null(encoded)) {
    if (token_targets_configured(client)) {
      err_token("Missing stored token targets")
    }
    return(NULL)
  }
  if (!token_targets_configured(client)) {
    err_token("Unexpected stored token targets")
  }
  bundle <- connection_data_decode(encoded)
  if (
    !is.list(bundle) ||
      !identical(names(bundle), c("tokens", "limits")) ||
      !is.list(bundle[["tokens"]]) ||
      anyDuplicated(names(bundle[["tokens"]])) ||
      !all(
        names(bundle[["tokens"]]) %in%
          setdiff(names(client@token_targets), client@default_token_target)
      ) ||
      (length(bundle[["tokens"]]) && is.null(names(bundle[["tokens"]])))
  ) {
    err_token("Invalid stored token targets")
  }
  bundle[["limits"]] <- validate_token_target_limits(client, bundle[["limits"]])
  bundle[["tokens"]] <- lapply(bundle[["tokens"]], function(fields) {
    if (
      !is.list(fields) || !identical(names(fields), connection_token_fields)
    ) {
      err_token("Invalid stored target token")
    }
    token <- do.call(OAuthToken, fields)
    if (is_valid_string(token@refresh_token)) {
      err_token("Unexpected target refresh credential")
    }
    token
  })
  for (target in names(bundle[["tokens"]])) {
    validate_token_target_grant(
      client,
      bundle[["tokens"]][[target]]@granted_scopes,
      list(
        target = target,
        scopes = bundle[["limits"]][[target]],
        required_scopes = token_target_required_scopes(client, target)
      )
    )
  }
  validate_token_target_bundle_budget(client, NULL, bundle)
  bundle
}

token_target_authorization_scopes <- function(client, limits) {
  normalize_scope_tokens(unlist(limits, use.names = FALSE))
}

token_target_authorization_allowed <- function(client, scopes) {
  oidc <- intersect(scopes, token_target_oidc_scopes(client))
  all(oidc %in% effective_client_scopes(client)) &&
    all(vapply(
      setdiff(scopes, token_target_oidc_scopes(client)),
      function(scope) {
        any(vapply(
          names(client@token_targets),
          function(target) {
            token_target_scopes_allowed(client, target, scope)
          },
          logical(1)
        ))
      },
      logical(1)
    ))
}

token_target_verification_scopes <- function(client, request, response) {
  if (is.null(request)) {
    return(NULL)
  }
  scopes <- request[["scopes"]]
  if (!is.null(response[["scope"]])) {
    # offline_access requests refresh consent, not an access-token permission.
    # Its omission must not trip strict access-token scope reconciliation.
    scopes <- setdiff(scopes, "offline_access")
  }
  if (
    identical(client@provider@token_target_mode, "microsoft") &&
      any(endsWith(scopes, "/.default"))
  ) {
    return(normalize_scope_tokens(response[["scope"]]))
  }
  scopes
}

token_target_authorization_parameters <- function(client, scopes) {
  if (
    token_targets_configured(client) &&
      identical(client@provider@token_target_mode, "microsoft")
  ) {
    static <- scopes[endsWith(scopes, "/.default")]
    if (length(static)) {
      # One static-consent request covers the application's registered APIs.
      # Code redemption still uses the sealed primary target and its local limit.
      preferred <- intersect(
        normalize_scope_tokens(client@token_targets[[
          client@default_token_target
        ]][["scopes"]]),
        static
      )
      selected <- if (length(preferred)) preferred[[1L]] else static[[1L]]
      return(union(
        intersect(scopes, token_target_oidc_scopes(client)),
        selected
      ))
    }
  }
  scopes
}

connection_record_configured_scopes <- function(record, scopes) {
  if (is.null(record[["target"]])) {
    return(connection_scope_covered(
      record[["client"]],
      scopes,
      effective_client_scopes(record[["client"]])
    ))
  }
  token_target_scopes_allowed(
    record[["client"]],
    record[["target"]],
    scopes
  )
}

connection_record_required_scopes <- function(record) {
  record[["target_required_scopes"]] %||% record[["client"]]@required_scopes
}

token_target_operation_scopes <- function(
  client,
  target,
  granted,
  ceiling = NULL
) {
  granted[vapply(
    granted,
    function(scope) {
      token_target_scopes_allowed(client, target, scope, ceiling)
    },
    logical(1)
  )]
}

connection_record_scope_limit_allows <- function(record, scopes) {
  is.null(record[["target"]]) ||
    token_target_scopes_allowed(
      record[["client"]],
      record[["target"]],
      scopes,
      record[["target_scopes"]]
    )
}

token_target_check_destination <- function(client, target, resource_id) {
  if (
    !is.null(target) &&
      !resource_id %in% client@token_targets[[target]][["resource_ids"]]
  ) {
    err_input(
      "The selected token target is not associated with this resource ID"
    )
  }
  invisible(NULL)
}
