openid_fapi_configuration_check_ids <- function(message_signing) {
  c(
    "client_valid",
    "https_endpoints",
    "https_redirect",
    "oidc_validation",
    "nonce_enabled",
    "pkce_s256",
    "id_token_algorithms",
    "userinfo_algorithms",
    "signature_policy",
    "browser_binding_policy",
    "tls_policy",
    if (message_signing) "par_jar" else "par_parameters",
    "minimal_front_channel",
    if (message_signing) {
      c(
        "jar_audience",
        "jar_signing_algorithm",
        "jar_nbf_present",
        "jar_nbf_past_window",
        "jar_lifetime_window",
        "jwt_response_mode",
        "jarm_signing_algorithm",
        "encryption_not_selected"
      )
    } else {
      c(
        "query_response_mode",
        "callback_issuer_advertised",
        "callback_issuer_required",
        "callback_issuer_compared"
      )
    },
    "token_client_authentication",
    "par_client_authentication",
    "token_assertion_algorithm",
    "par_assertion_algorithm",
    "token_assertion_audience",
    "par_assertion_audience",
    "dpop_key_and_algorithm",
    "dpop_required",
    "mtls_not_selected",
    if (message_signing) "reference_state"
  )
}

openid_fapi_configuration_profile <- function(message_signing) {
  if (message_signing) {
    "oidc-private-key-jwt-es256-dpop-jwt"
  } else {
    "oidc-private-key-jwt-es256-dpop-query"
  }
}

openid_fapi_configuration <- function(client, message_signing) {
  ids <- openid_fapi_configuration_check_ids(message_signing)
  checks <- stats::setNames(rep(FALSE, length(ids)), ids)
  finish <- function() {
    list(
      schema_version = 1L,
      profile = openid_fapi_configuration_profile(message_signing),
      local_configuration_passed = all(checks),
      checks = as.list(checks),
      issues = as.list(names(checks)[!checks]),
      selection_policies = as.list(c(
        if (message_signing) "reference_state",
        "es256_authentication_and_proofs",
        "dpop_only_sender_constraint",
        if (message_signing) "unencrypted_request_and_response"
      )),
      unassessed = list(
        "issuer_authority_and_discovery_provenance",
        "client_registration_and_credential_custody",
        "deployment_tls_dns_and_clock",
        "authorization_initiation_consent_and_browser_behavior",
        "provider_resource_and_refresh_enforcement",
        if (message_signing) {
          "other_message_signing_profiles_and_signed_introspection"
        } else {
          "other_fapi_profiles_and_signed_introspection"
        },
        "runtime_protocol_conformance_and_release_source_qualification"
      ),
      certification_status = "not_assessed"
    )
  }
  safely <- function(expr, otherwise = NULL) {
    tryCatch(expr, error = function(...) otherwise)
  }
  internal <- function(name) getFromNamespace(name, "shinyOAuth")
  check <- function(id, value) {
    checks[[id]] <<- isTRUE(safely(value, FALSE))
  }
  check("client_valid", {
    S7::check_is_S7(client, shinyOAuth::OAuthClient)
    S7::validate(client)
    TRUE
  })
  if (!checks[["client_valid"]]) {
    return(finish())
  }
  provider <- client@provider
  string <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) && nzchar(value)
  }
  finite <- function(value) {
    is.numeric(value) && length(value) == 1L && is.finite(value)
  }
  https <- function(url, issuer = FALSE) {
    if (!string(url)) {
      return(FALSE)
    }
    parsed <- safely(httr2::url_parse(url))
    !is.null(parsed) &&
      identical(tolower(parsed[["scheme"]]), "https") &&
      string(parsed[["hostname"]]) &&
      !string(parsed[["username"]]) &&
      !string(parsed[["password"]]) &&
      !grepl("#", url, fixed = TRUE) &&
      (!issuer || !grepl("?", url, fixed = TRUE))
  }
  fapi_algorithms <- function(values, allow_empty = FALSE) {
    if (!is.character(values) || anyNA(values) || !all(nzchar(values))) {
      return(FALSE)
    }
    if (!length(values)) {
      return(allow_empty)
    }
    all(
      vapply(values, internal("canonicalize_jws_alg"), character(1)) %in%
        c("ES256", "Ed25519", "EdDSA")
    )
  }
  assertion_algorithm <- function(auth_client) {
    configured <- internal("canonicalize_jws_alg")(
      auth_client@client_assertion_alg
    )
    if (nzchar(configured)) {
      return(configured)
    }
    internal("choose_default_alg_for_private_key")(
      internal("normalize_private_key_input")(
        auth_client@client_assertion_private_key
      )
    )
  }
  check("https_endpoints", {
    https(provider@issuer, issuer = TRUE) &&
      all(vapply(
        c(
          provider@auth_url,
          provider@token_url,
          provider@par_url,
          provider@jwks_uri
        ),
        https,
        logical(1)
      )) &&
      (!string(provider@userinfo_url) || https(provider@userinfo_url))
  })
  check("https_redirect", https(client@redirect_uri))
  check("oidc_validation", {
    internal("provider_uses_oidc")(provider) &&
      isTRUE(provider@id_token_validation) &&
      isTRUE(provider@id_token_required) &&
      "openid" %in% client@scopes
  })
  check("nonce_enabled", isTRUE(provider@use_nonce))
  check("pkce_s256", {
    isTRUE(provider@use_pkce) && identical(provider@pkce_method, "S256")
  })
  check("id_token_algorithms", fapi_algorithms(provider@allowed_algs))
  userinfo_algs <- provider@userinfo_allowed_algs
  if (is.null(userinfo_algs)) {
    userinfo_algs <- provider@allowed_algs
  }
  check(
    "userinfo_algorithms",
    fapi_algorithms(
      userinfo_algs,
      allow_empty = !isTRUE(provider@userinfo_signed_jwt_required)
    )
  )
  check("signature_policy", {
    identical(getOption("shinyOAuth.skip_id_sig", FALSE), FALSE) &&
      identical(
        getOption("shinyOAuth.allow_unsigned_userinfo_jwt", FALSE),
        FALSE
      )
  })
  check("browser_binding_policy", {
    identical(getOption("shinyOAuth.skip_browser_token", FALSE), FALSE)
  })
  check("tls_policy", {
    policy <- internal("resolve_effective_tls_policy")()
    is.null(policy[["problem"]]) &&
      policy[["minimum"]] %in% c("1.2", "1.3") &&
      isTRUE(policy[["verification"]])
  })
  check("minimal_front_channel", {
    identical(provider@authorization_request_front_channel_mode, "minimal")
  })
  if (message_signing) {
    check("par_jar", {
      string(provider@par_url) &&
        identical(client@request_object_mode, "request")
    })
    check("jar_audience", {
      identical(
        internal("resolve_request_object_audience")(client),
        provider@issuer
      )
    })
    check("jar_signing_algorithm", {
      identical(internal("resolve_request_object_signing_alg")(client), "ES256")
    })
    ttl <- client@request_object_ttl
    skew <- client@request_object_nbf_skew
    check("jar_nbf_present", finite(skew) && skew >= 0)
    check("jar_nbf_past_window", finite(skew) && skew >= 0 && skew <= 3600)
    check("jar_lifetime_window", {
      finite(ttl) && ttl > 0 && finite(skew) && skew >= 0 && ttl + skew <= 3600
    })
    check("jwt_response_mode", {
      mode <- internal("resolve_oauth_client_response_mode")(client)
      is.null(mode[["error"]]) &&
        identical(mode[["explicit_mode"]], "jwt") &&
        identical(mode[["mode"]], "query.jwt")
    })
    check("jarm_signing_algorithm", {
      identical(
        internal("resolve_authorization_response_signing_alg")(client),
        "ES256"
      )
    })
    check("encryption_not_selected", {
      !string(client@request_object_encryption_alg) &&
        !string(client@jarm_encrypted_response_alg)
    })
    check("reference_state", identical(client@state_transport, "reference"))
  } else {
    check("par_parameters", {
      string(provider@par_url) &&
        identical(client@request_object_mode, "parameters")
    })
    check("query_response_mode", {
      mode <- internal("resolve_oauth_client_response_mode")(client)
      is.null(mode[["error"]]) && identical(mode[["mode"]], "query")
    })
    check(
      "callback_issuer_advertised",
      provider@authorization_response_iss_parameter_supported
    )
    check("callback_issuer_required", client@enforce_callback_issuer)
    check("callback_issuer_compared", client@compare_callback_issuer)
  }
  # The named selection uses DPoP alone. Reuse the runtime predicate so
  # certificate-bound intent and endpoint authentication overrides cannot
  # silently activate an mTLS alias outside the checked base URLs.
  mtls_not_selected <- safely(
    !internal("client_uses_mtls_endpoint")(client),
    FALSE
  )
  for (endpoint in c("token", "par")) {
    auth <- safely(internal("endpoint_auth_client")(client, endpoint))
    mtls_not_selected <- mtls_not_selected &&
      safely(
        !is.null(auth) && !internal("client_uses_mtls_endpoint")(auth),
        FALSE
      )
    url <- if (identical(endpoint, "token")) {
      provider@token_url
    } else {
      provider@par_url
    }
    check(paste0(endpoint, "_client_authentication"), {
      !is.null(auth) &&
        identical(auth@provider@token_auth_style, "private_key_jwt")
    })
    check(paste0(endpoint, "_assertion_algorithm"), {
      !is.null(auth) && identical(assertion_algorithm(auth), "ES256")
    })
    check(paste0(endpoint, "_assertion_audience"), {
      !is.null(auth) &&
        identical(
          internal("resolve_client_assertion_audience_url")(
            auth@provider,
            url,
            auth@client_assertion_audience
          ),
          provider@issuer
        )
    })
  }
  check("dpop_key_and_algorithm", {
    internal("client_has_dpop")(client) &&
      identical(internal("resolve_dpop_alg")(client), "ES256")
  })
  check("dpop_required", {
    isTRUE(client@dpop_require_access_token) &&
      length(provider@allowed_token_types) > 0L &&
      all(tolower(provider@allowed_token_types) == "dpop")
  })
  check("mtls_not_selected", mtls_not_selected)
  finish()
}

openid_message_signing_configuration <- function(client) {
  openid_fapi_configuration(client, message_signing = TRUE)
}

openid_fapi_query_configuration <- function(client) {
  openid_fapi_configuration(client, message_signing = FALSE)
}

openid_fapi_query_configuration_matches <- function(assessment) {
  if (!is.list(assessment)) {
    return(FALSE)
  }
  checks <- assessment[["checks"]]
  ids <- openid_fapi_configuration_check_ids(message_signing = FALSE)
  identical(assessment[["schema_version"]], 1L) &&
    identical(
      assessment[["profile"]],
      openid_fapi_configuration_profile(message_signing = FALSE)
    ) &&
    isTRUE(assessment[["local_configuration_passed"]]) &&
    identical(assessment[["issues"]], list()) &&
    identical(assessment[["certification_status"]], "not_assessed") &&
    is.list(checks) &&
    length(checks) == length(ids) &&
    setequal(names(checks), ids) &&
    all(vapply(checks, isTRUE, logical(1)))
}

openid_assert_fapi_configuration <- function(client, message_signing) {
  assessment <- openid_fapi_configuration(client, message_signing)
  if (!isTRUE(assessment[["local_configuration_passed"]])) {
    label <- if (message_signing) "Message Signing" else "Direct FAPI"
    stop(
      label,
      " configuration failed: ",
      paste(unlist(assessment[["issues"]]), collapse = ", "),
      call. = FALSE
    )
  }
  invisible(assessment)
}

openid_assert_message_signing_configuration <- function(client) {
  openid_assert_fapi_configuration(client, message_signing = TRUE)
}
