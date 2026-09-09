#' Assess an OAuth configuration against a pinned OAuth 2.1 draft
#'
#' This function inspects a configured [OAuthClient] and its [OAuthProvider] for
#' compliance with the OAuth 2.1 draft 16 (ruleset `1.1.0`) specification. It
#' reports configuration gaps, unresolved external prerequisites, and recommendations
#' without changing the configuration or making requests.
#'
#' @param client An [OAuthClient] or [OAuthProvider]. Provider-only assessments
#'   are partial and cannot establish missing client settings.
#' @param draft Implemented target revision. Currently only
#'   `"draft-ietf-oauth-v2-1-16"` is supported (an Internet-Draft, not an RFC).
#' @param context Optional named list with `operations`, a character vector
#'   selecting additional `"userinfo"`, `"introspection"` or `"revocation"`
#'   operations, and `nonce_exception`, a scalar logical declaration. Setting
#'   `nonce_exception = TRUE` declares that the authorization server has the
#'   assurance required by draft section 7.5.1.1 for this confidential deployment
#'   and specific request's correct OIDC nonce use. It does not supply observed
#'   evidence or excuse missing local prerequisites. Prefer S256 PKCE.
#'
#' @details
#' Ruleset `1.1.0` covers code/refresh, enabled PAR, required UserInfo and
#' introspection, and the additional operations selected in `context`. Signing
#' and encryption key retrieval is included when applicable. Future resource URLs, arbitrary
#' request customization, browser/proxy TLS, registered redirect matching, secret
#' custody, and authorization/resource server behavior require separate evidence.
#' Optional DPoP, mTLS, PAR, JAR and JARM are not required as a bundle.
#'
#' `configuration_compliant` is `FALSE` if an applicable mandatory configuration
#' check fails; otherwise `NA` if a mandatory configuration check is unresolved;
#' otherwise `TRUE` when a nonempty set of applicable mandatory checks passes.
#' Recommendations and external unknowns do not change that verdict. In
#' particular, the legacy assertion type `JWT` is a recommendation finding;
#' the assertion audience is a separate mandatory check for JWT authentication.
#' `requirement_source` distinguishes OAuth core, OIDC, extension specifications,
#' security guidance and local package/application policy. Callback capacity
#' thresholds are package recommendations, not draft-defined numeric minima;
#' complete encoded requests still need deployment testing. OAuth 2.1 assessment
#' is opt-in and does not change existing OAuth 2.0 configuration or requests.
#'
#' A positive verdict applies only to the recorded scope and ruleset, with the
#' current configuration, options, runtime and declared context. It is not
#' certification or a test of a live deployment. Rerun after policy changes.
#' Reports contain no client/provider objects, credentials, keys or endpoint
#' URLs. No caches or state stores are read or changed; their method contracts
#' are inspected without invoking them.
#'
#' @return A `shinyOAuth_oauth21_assessment` list with `configuration_compliant`,
#'   `checks`, `draft`, `ruleset_version`, `package_version`, `assessed_at`,
#'   `assessment_scope`, and `operations`. `checks` is a data frame with stable
#'   `id`, `scope`, `status` (`pass`, `fail`, `unknown`, `not_applicable`),
#'   `requirement` (`MUST`, `SHOULD`, `info`), `message`, `remediation`, `reference`,
#'   `evidence_source`, `requirement_source`, and logical `affects_verdict` columns. Only rows with
#'   `affects_verdict = TRUE` enter aggregation; unknown external obligations
#'   remain visible separately.
#' @references
#' \url{https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16}
#'
#' \url{https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11}
#'
#' \url{https://www.rfc-editor.org/rfc/rfc9207.html}
#' @examples
#' provider <- oauth_provider(
#'   name = "Example",
#'   auth_url = "https://auth.example/authorize",
#'   token_url = "https://auth.example/token",
#'   token_auth_style = "public", use_pkce = TRUE, pkce_method = "S256"
#' )
#' client <- oauth_client(
#'   provider, client_id = "example-client",
#'   redirect_uri = "https://app.example/callback"
#' )
#' assessment <- check_oauth21(client)
#' assessment$checks[assessment$checks$status != "pass", ]
#' @export
check_oauth21 <- function(
  client,
  draft = "draft-ietf-oauth-v2-1-16",
  context = list()
) {
  has_client <- S7::S7_inherits(client, OAuthClient)
  if (!has_client && !S7::S7_inherits(client, OAuthProvider)) {
    stop("client must be an OAuthClient or OAuthProvider", call. = FALSE)
  }
  if (!identical(draft, "draft-ietf-oauth-v2-1-16")) {
    stop("Unsupported draft; use 'draft-ietf-oauth-v2-1-16'", call. = FALSE)
  }
  oauth21_validate_context(context)
  provider <- if (has_client) client@provider else client
  checks <- list()
  ref <- function(section) {
    paste0(
      "https://datatracker.ietf.org/doc/html/",
      draft,
      "#section-",
      section
    )
  }
  add <- function(
    id,
    status,
    message,
    remediation = "",
    section = "1.8",
    requirement = "MUST",
    scope = "configuration",
    evidence = "configuration",
    reference = ref(section),
    affects = requirement == "MUST" && scope == "configuration",
    requirement_source = oauth21_requirement_source(reference)
  ) {
    checks[[length(checks) + 1L]] <<- data.frame(
      id = id,
      scope = scope,
      status = status,
      requirement = requirement,
      message = message,
      remediation = remediation,
      reference = reference,
      evidence_source = evidence,
      requirement_source = requirement_source,
      affects_verdict = affects,
      stringsAsFactors = FALSE
    )
  }
  status <- function(ok) {
    if (is.na(ok)) {
      "unknown"
    } else if (ok) {
      "pass"
    } else {
      "fail"
    }
  }
  external <- function(id, message, section, requirement = "MUST") {
    add(
      id,
      "unknown",
      message,
      "Obtain deployment or server evidence.",
      section,
      requirement,
      scope = "external",
      evidence = "not_observed"
    )
  }
  add(
    "grant.code_refresh",
    "pass",
    "The assessed package role uses authorization code and refresh grants.",
    section = "4",
    evidence = "package_contract"
  )
  if (!has_client) {
    add(
      "client.configuration",
      "unknown",
      "Provider-only assessment lacks client credentials, redirect and binding policy.",
      "Assess an OAuthClient for a complete local configuration scope.",
      section = "2"
    )
  }

  response <- if (has_client) {
    resolve_oauth_client_response_mode(client)
  } else {
    NULL
  }
  jarm <- has_client && response$mode %in% c("query.jwt", "form_post.jwt")
  oidc <- provider_uses_oidc(provider)
  validates_id <- isTRUE(provider@id_token_validation) ||
    isTRUE(provider@use_nonce) ||
    !is.null(inspect_auth_max_age(provider@extra_auth_params)$value)
  par <- is_valid_string(provider@par_url) &&
    (isTRUE(provider@par_required) ||
      (has_client && client@request_object_mode != "request_uri"))
  operations <- c("authorization", "code", "refresh")
  if (par) {
    operations <- c(operations, "par")
  }
  if (isTRUE(provider@userinfo_required)) {
    operations <- c(operations, "userinfo")
  }
  if (has_client && isTRUE(client@introspect)) {
    operations <- c(operations, "introspection")
  }
  operations <- unique(c(operations, context$operations))
  endpoints <- c(
    "token",
    intersect(c("par", "userinfo", "introspection", "revocation"), operations)
  )
  key_dependencies <- resolve_oauth_key_dependencies(
    if (has_client) client else NULL,
    provider,
    operations,
    jarm,
    validates_id
  )
  needs_jwks <- any(
    key_dependencies %in% c("configured_jwks", "discovered_jwks")
  )
  if (needs_jwks) {
    operations <- c(operations, "jwks")
  }
  add(
    "https.authorization",
    status(oauth21_https(provider@auth_url)),
    "The configured authorization endpoint must use HTTPS.",
    "Configure an HTTPS authorization endpoint.",
    section = "1.5"
  )
  auth_settings <- list()
  for (endpoint in endpoints) {
    effective <- oauth21_endpoint_settings(
      if (has_client) client else NULL,
      provider,
      endpoint
    )
    auth_settings[[endpoint]] <- effective
    add(
      paste0("https.", endpoint),
      status(oauth21_https(effective$url)),
      paste(
        "The selected",
        endpoint,
        "endpoint must use HTTPS, including any selected mTLS alias."
      ),
      "Configure an HTTPS URL for the selected endpoint.",
      section = "1.5"
    )
    if (effective$mtls) {
      add(
        paste0("mtls.backend.", endpoint),
        status(effective$mtls_backend),
        "The active curl TLS backend must support the configured PEM mTLS credentials.",
        "Select the OpenSSL curl backend before loading curl on Windows, then restart R.",
        evidence = "runtime",
        requirement_source = "package_policy",
        reference = "https://www.rfc-editor.org/rfc/rfc8705.html#section-2"
      )
    }
    if (endpoint == "userinfo") {
      next
    }
    auth_ok <- if (!has_client) {
      NA
    } else {
      effective$credentials && is.null(effective$problem)
    }
    add(
      paste0("client_auth.", endpoint),
      status(auth_ok),
      paste(
        "Effective",
        endpoint,
        "authentication needs a supported method and its credentials."
      ),
      "Check the effective method, endpoint overrides and advertised authentication metadata.",
      section = "2.4"
    )
    add(
      paste0("client_auth.asymmetric.", endpoint),
      if (effective$style == "public") {
        "not_applicable"
      } else if (!has_client) {
        "unknown"
      } else if (!isTRUE(effective$confidential)) {
        "not_applicable"
      } else {
        status(
          effective$style %in%
            c(
              "private_key_jwt",
              "tls_client_auth",
              "self_signed_tls_client_auth"
            )
        )
      },
      "Asymmetric client authentication is recommended where supported; secret-based authentication remains compatible.",
      "Consider private_key_jwt or mTLS for this endpoint, subject to provider registration and deployment support.",
      requirement = "SHOULD",
      reference = "https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5"
    )
    jwt <- effective$style %in% c("client_secret_jwt", "private_key_jwt")
    audience_ok <- if (!jwt) {
      TRUE
    } else if (!has_client || !is_valid_string(provider@issuer)) {
      NA
    } else {
      identical(
        resolve_client_assertion_audience_url(
          provider,
          effective$url,
          effective$audience
        ),
        provider@issuer
      )
    }
    add(
      paste0("jwt_audience.", endpoint),
      if (!jwt) "not_applicable" else status(audience_ok),
      "JWT client authentication requires the sole audience to equal the trusted issuer exactly.",
      "Set client_assertion_audience to the trusted issuer, including applicable endpoint overrides.",
      reference = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4"
    )
    add(
      paste0("jwt_typ.", endpoint),
      if (!jwt) {
        "not_applicable"
      } else if (!has_client) {
        "unknown"
      } else {
        status(identical(effective$typ, "client-authentication+jwt"))
      },
      "Explicit client-authentication+jwt typing is recommended; legacy JWT typing remains supported.",
      "Select client_assertion_typ = 'client-authentication+jwt' when supported by the server.",
      requirement = "SHOULD",
      reference = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4"
    )
  }
  if (needs_jwks) {
    jwks <- provider@jwks_uri
    # An absent URI may be discovered at runtime; do not invent the endpoint.
    add(
      "https.jwks",
      status(if (is_valid_string(jwks)) oauth21_https(jwks) else NA),
      "Applicable signing or encryption key retrieval needs a known HTTPS endpoint.",
      "Configure trusted jwks_uri or assess after obtaining trusted metadata.",
      section = "1.5"
    )
  }
  tls <- resolve_tls_policy()
  runtime <- curl::curl_version()
  old_wolf <- grepl("wolfSSL", runtime$ssl_version, ignore.case = TRUE) &&
    utils::compareVersion(runtime$version, "8.10.0") < 0L
  tls_ok <- if (!is.null(tls$problem) || (!is.null(tls$minimum) && old_wolf)) {
    FALSE
  } else if (
    !is.null(tls$minimum) ||
      utils::compareVersion(runtime$version, "8.16.0") >= 0L
  ) {
    TRUE
  } else {
    NA
  }
  add(
    "tls.minimum",
    status(tls_ok),
    "A configured minimum of TLS 1.2 or later, or a known suitable libcurl default, is required by this ruleset.",
    "Select shinyOAuth.tls_min_version = '1.2' or '1.3' on a supporting TLS backend.",
    reference = "https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1",
    evidence = if (is.null(tls$minimum)) {
      "runtime_default"
    } else {
      "configuration_and_runtime"
    }
  )
  add(
    "tls.verification",
    "pass",
    "Default package requests retain certificate and hostname verification; later caller customizations require separate inspection.",
    section = "1.5",
    evidence = "package_contract"
  )
  external(
    "tls.connections",
    "Negotiated connections, browser/proxy hops and trust-root deployment were not observed.",
    "1.5"
  )

  pkce <- isTRUE(provider@use_pkce)
  s256 <- pkce && identical(normalize_pkce_method(provider@pkce_method), "S256")
  confidential <- has_client && isTRUE(auth_settings$token$confidential)
  exception_local <- confidential &&
    oidc &&
    isTRUE(provider@use_nonce) &&
    validates_id
  pkce_ok <- if (pkce) {
    s256
  } else if (!has_client) {
    NA
  } else if (!exception_local) {
    FALSE
  } else {
    context$nonce_exception %||% NA
  }
  add(
    "pkce.method",
    status(pkce_ok),
    if (pkce) {
      "Authorization requests must select S256 PKCE."
    } else {
      "Omitting PKCE requires confidential OIDC nonce prerequisites and server assurance for the deployment and request."
    },
    "Enable use_pkce = TRUE and pkce_method = 'S256'; otherwise establish every section 7.5.1.1 prerequisite.",
    section = "7.5.1.1",
    evidence = if (!pkce && isTRUE(pkce_ok)) {
      "configuration_and_declared_context"
    } else {
      "configuration"
    }
  )
  add(
    "pkce.recommended",
    status(s256),
    "S256 remains recommended even when the conditional nonce exception applies.",
    "Prefer S256 PKCE.",
    section = "7.5.1.1",
    requirement = "SHOULD"
  )
  if (!pkce) {
    external(
      "pkce.exception_assurance",
      "The server's assurance of correct nonce use in this deployment and request was not independently verified.",
      "7.5.1.1"
    )
  }

  dev <- .is_test_or_interactive()
  skip_signature <- oauth21_test_bypass_active("shinyOAuth.skip_id_sig", dev)
  identity_ok <- if (!oidc && !validates_id) {
    TRUE
  } else {
    validates_id && !skip_signature
  }
  add(
    "identity.validation",
    if (!oidc && !validates_id) "not_applicable" else status(identity_ok),
    "Applicable OIDC identity use requires ID token validation without active signature bypass.",
    "Require and validate ID tokens for OIDC identity; disable shinyOAuth.skip_id_sig.",
    reference = "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"
  )
  add(
    "identity.nonce",
    if (!isTRUE(provider@use_nonce)) {
      "not_applicable"
    } else {
      status(!skip_signature)
    },
    "Configured nonce use is checked against the transaction's validated ID token.",
    "Retain nonce and ID token validation together.",
    section = "7.5.1.1",
    evidence = "configuration_and_package_contract"
  )
  if ("userinfo" %in% operations && oidc) {
    # Login requires an ID token whenever validates_id is effective. Runtime
    # always compares UserInfo with that validated baseline, even with the
    # explicit matching flag disabled. Standalone UserInfo needs caller context.
    userinfo_subject_ok <- isTRUE(provider@userinfo_id_token_match) ||
      (isTRUE(provider@userinfo_required) && validates_id && !skip_signature)
    if (
      !isTRUE(provider@userinfo_id_token_match) &&
        "userinfo" %in% context$operations &&
        !isFALSE(validates_id && !skip_signature)
    ) {
      userinfo_subject_ok <- NA
    }
    add(
      "identity.userinfo_subject",
      status(userinfo_subject_ok),
      "OIDC UserInfo is compared with every available validated ID token; required validated login baselines or explicit matching enforce subject binding.",
      "Require validated ID tokens for managed UserInfo; for separately selected UserInfo calls supply a validated token baseline or enable userinfo_id_token_match.",
      reference = "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse",
      evidence = "configuration_and_package_contract"
    )
    add(
      "identity.userinfo_signature",
      if (!isTRUE(provider@userinfo_signed_jwt_required)) {
        "not_applicable"
      } else {
        status(
          !(dev &&
            isTRUE(getOption("shinyOAuth.allow_unsigned_userinfo_jwt", FALSE)))
        )
      },
      "Required signed UserInfo must not accept an active unsigned-JWT relaxation.",
      "Disable shinyOAuth.allow_unsigned_userinfo_jwt.",
      reference = "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse"
    )
  }

  if (has_client) {
    query <- oauth21_authorization_settings(client)
    token_params <- oauth_extra_params_resolution(
      list(redirect_uri = client@redirect_uri),
      provider@extra_token_params
    )
    add(
      "parameters.token",
      status(
        is.null(token_params$problem) &&
          identical(token_params$params$redirect_uri, client@redirect_uri)
      ),
      "Token parameter overrides must preserve the code transaction and its redirect URI.",
      "Keep transaction parameters managed and retain the registered redirect URI.",
      section = "10.2"
    )
    add(
      "parameters.authorization",
      query$status,
      "Known authorization fields use the shared singleton composition rules; dynamic transaction fields cannot be precomputed.",
      "Remove conflicting fixed managed fields and keep transaction values package-managed.",
      section = "4.1.1"
    )
    add(
      "redirect.uri",
      status(oauth21_redirect_ok(query$redirect_uri)),
      "The selected callback URI must be absolute HTTPS or an HTTP loopback URI without a fragment or credentials.",
      "Configure the intended HTTPS callback URI or a supported loopback redirect.",
      section = "2.3"
    )
    mixup <- switch(
      client@authorization_server_mode,
      single = TRUE,
      multi_issuer = jarm ||
        (isTRUE(client@enforce_callback_issuer) &&
          isTRUE(provider@authorization_response_iss_parameter_supported)),
      multi_redirect_uri = length(client@authorization_server_redirect_uris) >=
        2L,
      FALSE
    )
    add(
      "issuer.mixup",
      status(mixup),
      "Declared topology uses a single server, issuer validation/JARM, or distinct callback routes.",
      "Configure authorization_server_mode and its issuer or distinct-route defense.",
      section = "2.3.4"
    )
    add(
      "issuer.identification_recommended",
      if (client@authorization_server_mode == "single") {
        "not_applicable"
      } else {
        status(
          jarm ||
            (isTRUE(client@enforce_callback_issuer) &&
              isTRUE(provider@authorization_response_iss_parameter_supported))
        )
      },
      "Issuer identification is preferred for multi-server clients; distinct registered callback routes remain a valid defense.",
      "Prefer RFC 9207 issuer identification or JARM when supported; document legacy-provider reasons for distinct routes.",
      section = "7.15.2",
      requirement = "SHOULD"
    )
    redirect_host <- tolower(
      oauth21_url_parts(client@redirect_uri)$hostname %||% ""
    )
    add(
      "redirect.loopback_literal",
      if (!redirect_host %in% c("localhost", "127.0.0.1", "::1", "[::1]")) {
        "not_applicable"
      } else {
        status(redirect_host != "localhost")
      },
      "Loopback deployments should prefer an IP literal; existing localhost callbacks remain supported.",
      "Register and use a matching 127.0.0.1 or [::1] callback where the deployment supports it.",
      section = "8.4.2",
      requirement = "SHOULD"
    )
    compares <- isTRUE(client@compare_callback_issuer) ||
      isTRUE(client@enforce_callback_issuer)
    issuer_ok <- !compares ||
      jarm ||
      !isTRUE(provider@authorization_response_iss_parameter_supported) ||
      isTRUE(client@enforce_callback_issuer)
    add(
      "issuer.participation",
      if (jarm || !compares) "not_applicable" else status(issuer_ok),
      "RFC 9207 participation compares a present issuer and requires it when support is advertised; validated JARM supplies its own issuer.",
      "Require callback issuer presence for advertised RFC 9207 participation, or explicitly configure the applicable alternative.",
      reference = "https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4"
    )
    add(
      "state.browser_binding",
      status(
        !oauth21_test_bypass_active("shinyOAuth.skip_browser_token", dev)
      ),
      "Pending logins bind callback state to the initiating browser unless the development bypass is active.",
      "Disable shinyOAuth.skip_browser_token.",
      section = "2.3.3"
    )
    atomic <- inherits(client@state_store, "cache_mem") ||
      is.function(client@state_store$take)
    add(
      "state.consume",
      status(atomic),
      "Pending state requires process-local memory or a declared atomic take method for one-time consumption.",
      "Use cache_mem in one process or a shared store implementing atomic take.",
      section = "2.3.3"
    )
  } else {
    query <- authorization_query_resolution(provider@auth_url)
    add(
      "parameters.authorization",
      if (is.null(query$problem)) "unknown" else "fail",
      "Provider query syntax is inspectable; generated client fields are absent.",
      "Assess a client to resolve managed authorization fields.",
      section = "4.1.1"
    )
  }
  external(
    "redirect.registration",
    "Exact registered redirect matching and actual callback/proxy routing require deployment evidence.",
    "2.3.1"
  )
  external(
    "state.deployment",
    "Shared-store atomicity, session isolation and coordination across processes require deployment evidence.",
    "2.3.3"
  )
  external(
    "client.secret_custody",
    "Configured credentials do not establish that a deployed client can keep them confidential.",
    "2.1"
  )
  external(
    "issuer.trust",
    "Issuer/endpoint provenance and the declared authorization-server topology were not independently established.",
    "2.3.4"
  )
  add(
    "resource.header_transport",
    "pass",
    "Resource builders manage Authorization and reject competing query or supported form access_token transport.",
    section = "5.1",
    evidence = "package_contract"
  )
  add(
    "resource.future_requests",
    "unknown",
    "Future resource URLs, opaque bodies and request mutations after construction are outside this assessment.",
    "Review the final request and use HTTPS without competing token transports.",
    section = "5.1",
    scope = "request",
    evidence = "not_supplied"
  )
  add(
    "refresh.replacement",
    "pass",
    "Successful refreshes replace rotated credentials. Errors report credential consumption; the module retires consumed, rejected or uncertain credentials even when retaining the session.",
    "Direct callers must store successful replacements and discard the old refresh credential after consumed, rejected or uncertain outcomes; coordinate separate processes.",
    section = "4.3.2",
    evidence = "package_contract"
  )
  external(
    "refresh.server_protection",
    "The authorization server must maintain refresh-token binding to the issuing client.",
    "4.3"
  )
  external(
    "refresh.scope_resource_binding",
    "Issued refresh tokens must remain bound to consented scope and resource servers.",
    "3.2.3"
  )
  add(
    "refresh.public_client_protection",
    if (has_client && confidential) "not_applicable" else "unknown",
    "Refresh tokens issued to public clients require server-enforced rotation or sender constraints; configuring a local key or certificate does not prove enforcement.",
    "Obtain server evidence for refresh tokens issued to public clients, or establish that no refresh tokens are issued.",
    section = "4.3.1",
    scope = "external",
    evidence = "not_observed"
  )
  add(
    "tokens.validation",
    "pass",
    "The package validates response scope syntax and token type, supports opaque tokens, and distinguishes granted scopes and estimated expiry.",
    section = "3.2.3",
    requirement = "info",
    evidence = "package_contract"
  )
  add(
    "tokens.application_policy",
    "unknown",
    "The application's required scopes and authorization decisions depend on its own access policy.",
    "Define application-specific access rules and inspect granted scopes where those rules need them.",
    section = "1.4.1",
    requirement = "info",
    scope = "external",
    evidence = "not_observed",
    requirement_source = "application_policy"
  )
  external(
    "tokens.resource_server_validation",
    "Resource servers must validate token validity, scope and permission for each protected resource.",
    "5.2"
  )
  external(
    "tokens.early_invalidation",
    "Clients must account for access tokens becoming invalid before their reported expiry; application recovery behavior was not observed.",
    "3.2.3"
  )
  limits <- oauth_callback_limits()
  local_capacity_baseline <- c(
    code = 8192,
    state = 8192,
    error = 256,
    error_description = 4096,
    error_uri = 2048,
    iss = 2048,
    browser_token = 256,
    form_post_handle = 128,
    form_post_id = 256,
    query = 8000,
    form_post_body = 8000
  )
  add(
    "callback.capacity",
    status(all(
      unlist(limits[names(local_capacity_baseline)]) >= local_capacity_baseline
    )),
    "Package capacity advice compares each decoded field cap with its local default and encoded query/form envelopes with an 8000-byte floor; these are not draft-defined minima.",
    "Review every field cap and the entire encoded callback, including percent encoding, fixed parameters, state, issuer and JARM; aggregate floors do not guarantee simultaneous field maxima.",
    section = "1.7.1",
    requirement = "SHOULD",
    requirement_source = "package_policy"
  )
  external(
    "callback.deployment_capacity",
    "Encoded callbacks, JARM envelopes and proxy/browser limits require interoperability testing.",
    "1.7.1",
    "SHOULD"
  )
  add(
    "transport.redirects",
    status(!isTRUE(getOption("shinyOAuth.allow_redirect", FALSE))),
    "Package back-channel redirect hardening protects credential confidentiality; this is separate from browser redirect requirements.",
    "Review each redirect target and credential handling before enabling redirects.",
    section = "1.4",
    requirement = "SHOULD",
    requirement_source = "package_policy"
  )
  add(
    "extensions.selection",
    "pass",
    "Manual OAuth-only providers and configurations without optional DPoP, mTLS, PAR, JAR or JARM can be assessed.",
    requirement = "info",
    evidence = "assessment_scope"
  )
  external(
    "server.protocol",
    "Authorization-server PKCE enforcement, one-time codes, client registration and optional extension interoperability were not tested.",
    "7.5"
  )
  checks <- do.call(rbind, checks)
  structure(
    list(
      configuration_compliant = oauth21_verdict(checks),
      checks = checks,
      draft = draft,
      ruleset_version = "1.1.0",
      package_version = as.character(utils::packageVersion("shinyOAuth")),
      assessed_at = Sys.time(),
      assessment_scope = if (has_client) {
        "client configuration; code/refresh and listed operations"
      } else {
        "partial provider configuration; client settings unresolved"
      },
      operations = operations
    ),
    class = "shinyOAuth_oauth21_assessment"
  )
}

#' @export
print.shinyOAuth_oauth21_assessment <- function(x, ...) {
  verdict <- if (is.na(x$configuration_compliant)) {
    "Mandatory configuration checks are unresolved"
  } else if (x$configuration_compliant) {
    "Mandatory configuration checks passed"
  } else {
    "Mandatory configuration checks failed"
  }
  cat(verdict, "\n", sep = "")
  cat(x$draft, "; ruleset ", x$ruleset_version, "\n", sep = "")
  cat("Scope: ", x$assessment_scope, "\n", sep = "")
  cat(
    "Unmet recommendations: ",
    sum(x$checks$requirement == "SHOULD" & x$checks$status == "fail"),
    "; unknown external/request checks: ",
    sum(
      x$checks$scope %in%
        c("external", "request") &
        x$checks$status == "unknown"
    ),
    "\n",
    sep = ""
  )
  invisible(x)
}
