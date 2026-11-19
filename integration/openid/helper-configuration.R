openid_message_signing_configuration <- function(client) {
  checks <- stats::setNames(
    rep(FALSE, 31L),
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
      "par_jar",
      "minimal_front_channel",
      "jar_audience",
      "jar_signing_algorithm",
      "jar_nbf_present",
      "jar_nbf_past_window",
      "jar_lifetime_window",
      "jwt_response_mode",
      "jarm_signing_algorithm",
      "encryption_not_selected",
      "token_client_authentication",
      "par_client_authentication",
      "token_assertion_algorithm",
      "par_assertion_algorithm",
      "token_assertion_audience",
      "par_assertion_audience",
      "dpop_key_and_algorithm",
      "dpop_required",
      "mtls_not_selected",
      "reference_state"
    )
  )
  finish <- function() {
    list(
      schema_version = 1L,
      profile = "oidc-private-key-jwt-es256-dpop-jwt",
      local_configuration_passed = all(checks),
      checks = as.list(checks),
      issues = as.list(names(checks)[!checks]),
      selection_policies = list(
        "reference_state",
        "es256_authentication_and_proofs",
        "dpop_only_sender_constraint",
        "unencrypted_request_and_response"
      ),
      unassessed = list(
        "issuer_authority_and_discovery_provenance",
        "client_registration_and_credential_custody",
        "deployment_tls_dns_and_clock",
        "authorization_initiation_consent_and_browser_behavior",
        "provider_resource_and_refresh_enforcement",
        "other_message_signing_profiles_and_signed_introspection",
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
  check("par_jar", {
    string(provider@par_url) && identical(client@request_object_mode, "request")
  })
  check("minimal_front_channel", {
    identical(provider@authorization_request_front_channel_mode, "minimal")
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
  check("reference_state", identical(client@state_transport, "reference"))
  finish()
}

openid_assert_message_signing_configuration <- function(client) {
  assessment <- openid_message_signing_configuration(client)
  if (!isTRUE(assessment[["local_configuration_passed"]])) {
    stop(
      "Message Signing configuration failed: ",
      paste(unlist(assessment[["issues"]]), collapse = ", "),
      call. = FALSE
    )
  }
  invisible(assessment)
}
