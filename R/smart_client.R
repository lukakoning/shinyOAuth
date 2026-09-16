#' Configure a SMART on FHIR app registration
#'
#' @description
#' `r lifecycle::badge("experimental")`
#'
#' Combine a reviewed [smart_discover()] snapshot with an existing app
#' registration. The result is an [OAuthClient] for [oauth_connections()], with
#' the resource ID `"fhir"`. Discovery does not register the app or grant access.
#'
#' @details
#' This constructor selects SMART 2.2 scope rules, S256 PKCE and the exact FHIR
#' base as the authorization request's `aud`. Identity is opt-in: `"openid"`
#' requests and requires `openid`, signed ID-token validation and nonce binding.
#' `"fhirUser"` additionally requests and requires the `fhirUser` scope and claim.
#' `"none"` does not enable OIDC because an issuer happens to be present.
#' A patient in context is independent of the authenticated user and local owner.
#'
#' Only direct authorization requests and query/form POST callbacks are supported.
#' Claims requests (including `auth_time`), JAR, PAR, JARM, DPoP, mTLS and remote
#' freshness requirements are not supported by this constructor.
#' EHR clients require a fresh registered launch transaction.
#' Configure standalone and EHR registrations as separate clients when both are
#' needed. No launch handle is stored in shared provider configuration.
#' Local usability policy requires a positive lifetime. An initial response may
#' omit `expires_in` only when `initial_expires_in_fallback` is configured explicitly;
#' refresh responses must include it. The generic assumed lifetime is not used.
#' SMART back-channel and resource requests require TLS 1.2 or newer. A stronger
#' configured TLS minimum is preserved; ordinary clients keep their defaults.
#'
#' @param discovery A plain snapshot returned by [smart_discover()]. Its metadata
#'   and endpoint policy are revalidated locally; this performs no network calls.
#' @param client_id,redirect_uri App registration values. The callback must use
#'   HTTPS, except for the snapshot's explicit HTTP loopback development policy.
#' @param scopes Permissions to request, without automatic wildcard/offline
#'   access. Standalone patient scopes require `launch/patient`. EHR clients add
#'   `launch`. `online_access` requires EHR launch and `permission-online`;
#'   `offline_access` requires `permission-offline` in either launch mode.
#'   Each resource scope spelling must be advertised through
#'   `permission-v2` or, for v1 spellings, `permission-v1` with `allow_v1_scopes = TRUE`.
#'   A SMART scope comparison supports at most 256 distinct scopes on each side
#'   and 64 KiB (65,536 bytes) of combined scope text. Larger comparisons fail
#'   closed, including during token acceptance and refresh.
#' @param required_scopes Minimum permissions, defaulting to `scopes`. Pass a
#'   subset to accept reduced grants as limited connections. Identity scopes are
#'   always required when identity is enabled. Unsupported comparisons fail closed.
#' @param token_auth_style Registration type: `"public"`, `"header"` for a
#'   symmetric secret using HTTP Basic, or `"private_key_jwt"`. Selection must
#'   agree with advertised capabilities. Confidential methods must also agree
#'   with authentication metadata; public clients do not authenticate and need
#'   no `"none"` entry in that metadata.
#'   Later property edits must retain a supported SMART token authentication
#'   method. Asymmetric assertions require `typ = "JWT"`, a key ID, an explicit
#'   RS384/ES384 algorithm, and the token endpoint as their audience.
#' @param client_secret Secret for a symmetric registration; otherwise omit.
#' @param client_assertion_private_key,client_assertion_private_key_kid Private
#'   signing key and registered key ID for asymmetric authentication; see
#'   [oauth_client()]. Required for `"private_key_jwt"`.
#' @param client_assertion_alg `"RS384"` (default) or `"ES384"`; the key and server
#'   metadata must support the selected algorithm. Other styles omit assertions.
#' @param launch `"standalone"` or `"ehr"`, matching the registered app flow.
#' @param identity `"none"` (default), `"openid"` for a validated OIDC subject, or
#'   `"fhirUser"` to also require the user's FHIR reference. `"openid"` does not
#'   interpret a `fhirUser` claim or populate `smart_context()[["fhirUser"]]`.
#'   A validated `fhirUser`
#'   claim may be an absolute URL or a supported resource instance reference
#'   relative to this client's FHIR base, such as `"Practitioner/example"` or
#'   `"Practitioner/example/_history/2"`. Versioned references retain their version.
#' @param allow_v1_scopes Explicit compatibility flag enabling `.read`, `.write` and
#'   `.*`. Requesting these spellings requires `permission-v1`; requesting v2
#'   spellings requires `permission-v2`, including when this flag is enabled.
#'   Default `FALSE`.
#' @param authorization_method `"GET"` (default) or `"POST"` for the outgoing
#'   browser request. POST requires the discovered `authorize-post` capability
#'   and uses the module's `request_login()` or [prepare_authorization_request()].
#'   POST supports longer browser requests but retains the scope comparison
#'   limits described under `scopes`.
#' @param response_mode `NULL`, `"query"`, or `"form_post"`. Advertised response
#'   modes, when present, must allow the selection.
#' @param authorization_server_mode,authorization_server_redirect_uris See
#'   [oauth_client()]. Multiple clients use distinct registered callback routes.
#' @param state_store,state_key,state_payload_max_age See [oauth_client()].
#' @param label Display label, default `"FHIR server"`; no credentials or context.
#' @param initial_expires_in_fallback Optional positive lifetime in seconds, supplied by
#'   the authorization server out of band for initial access tokens. Used only
#'   when an initial response omits `expires_in`; an explicit response value
#'   takes precedence. Default `NULL` requires the response to include a lifetime.
#'   This does not apply to refresh responses or change ordinary OAuth defaults.
#' @param online_access_policy `"online_only"` (default) or `"allow_offline"`.
#'   SMART permits an `online_access` request to negotiate `offline_access`.
#'   Opt in to `"allow_offline"` to accept that longer-lived permission in place
#'   of required `online_access`. The default rejects this substitution, even
#'   when `online_access` is optional. Explicitly requesting `offline_access`
#'   also authorizes offline persistence. Granted scopes retain their actual
#'   spelling; refresh responses cannot escalate an existing online grant.
#' @return An [OAuthClient], usable by the existing module or the separate
#'   connection manager. `@resource_bases` contains the approved `fhir` base;
#'   `@required_scopes` and `@label` use the ordinary client properties. `@smart`
#'   describes the selected profile. The client contains registration settings,
#'   never a user's token or launch context. Configure it outside `server()`.
#' @references
#' [SMART 2.2 launch](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html)
#' and [client authentication](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html).
#' @examples
#' \dontrun{
#' site <- smart_discover("https://ehr.example/fhir/R4")
#' client <- smart_client(site, "registered-app", "https://app.example/callback",
#'   scopes = c("launch/patient", "patient/Patient.r"),
#'   required_scopes = "patient/Patient.r", token_auth_style = "public")
#' client@smart[["launch"]]
#' }
#' @export
smart_client <- function(
  discovery,
  client_id,
  redirect_uri,
  scopes,
  required_scopes = scopes,
  launch = c("standalone", "ehr"),
  identity = c("none", "openid", "fhirUser"),
  allow_v1_scopes = FALSE,
  online_access_policy = c("online_only", "allow_offline"),
  token_auth_style = c("public", "header", "private_key_jwt"),
  client_secret = character(),
  client_assertion_private_key = NULL,
  client_assertion_private_key_kid = NULL,
  client_assertion_alg = "RS384",
  authorization_method = "GET",
  response_mode = NULL,
  authorization_server_mode = "single",
  authorization_server_redirect_uris = character(),
  initial_expires_in_fallback = NULL,
  label = "FHIR server",
  state_store = cachem::cache_mem(max_age = 300),
  state_key = random_urlsafe(128),
  state_payload_max_age = 300
) {
  online_access_policy <- match.arg(online_access_policy)
  token_auth_style <- match.arg(token_auth_style)
  launch <- match.arg(launch)
  identity <- match.arg(identity)
  connection_manager_flag(allow_v1_scopes, "allow_v1_scopes")
  if (
    !is.list(discovery) ||
      !identical(discovery[["smart_version"]], "2.2.0") ||
      !is.list(discovery[["metadata"]])
  ) {
    err_config("smart_client requires a SMART 2.2 discovery snapshot")
  }
  connection_manager_flag(
    discovery[["allow_http_loopback"]],
    "allow_http_loopback"
  )
  smart_discovery_url(
    discovery[["fhir_base"]],
    "fhir_base",
    discovery[["allow_http_loopback"]],
    identifier = TRUE
  )
  # Callbacks may contain registered fixed queries. The generic constructor
  # validates reserved query names and preserves the exact registration value.
  smart_discovery_url(
    redirect_uri,
    "redirect_uri",
    discovery[["allow_http_loopback"]]
  )
  hosts <- smart_discovery_hosts(discovery[["endpoint_hosts"]])
  metadata <- discovery[["metadata"]]
  # Keep reads exact after validation: an unrecognized extension must never
  # supply an endpoint, issuer or policy flag through R's partial $ matching.
  smart_discovery_validate(metadata, hosts, discovery[["allow_http_loopback"]])
  smart_validate_authorization_query(metadata[["authorization_endpoint"]])
  capabilities <- unlist(metadata[["capabilities"]], use.names = FALSE)
  require_capability <- function(value) {
    if (!value %in% capabilities) {
      err_config(paste("SMART capability required:", value))
    }
  }
  require_capability(paste0("launch-", launch))
  if (identical(authorization_method, "POST")) {
    require_capability("authorize-post")
  }
  require_capability(c(
    public = "client-public",
    header = "client-confidential-symmetric",
    private_key_jwt = "client-confidential-asymmetric"
  )[[token_auth_style]])
  methods <- smart_discovery_array(
    metadata,
    "token_endpoint_auth_methods_supported"
  )
  method <- c(
    public = "none",
    header = "client_secret_basic",
    private_key_jwt = "private_key_jwt"
  )[[token_auth_style]]
  # SMART lists confidential authentication methods here. Public-client support
  # comes from client-public; the SMART metadata contract does not require none.
  if (
    !identical(token_auth_style, "public") &&
      "token_endpoint_auth_methods_supported" %in% names(metadata) &&
      !method %in% methods
  ) {
    err_config("SMART registration authentication method is not advertised")
  }
  validate_scopes(scopes)
  validate_scopes(required_scopes)
  scopes <- normalize_scope_tokens(scopes)
  required_scopes <- normalize_scope_tokens(required_scopes)
  if (identical(launch, "ehr")) {
    scopes <- union(scopes, "launch")
  }
  if (identical(launch, "standalone") && "launch" %in% scopes) {
    err_config("Standalone SMART clients cannot request EHR launch scope")
  }
  identity_scopes <- smart_identity_scopes(identity)
  if (length(identity_scopes)) {
    require_capability("sso-openid-connect")
    scopes <- union(scopes, identity_scopes)
    required_scopes <- union(required_scopes, identity_scopes)
  }
  if (
    length(setdiff(intersect(c("openid", "fhirUser"), scopes), identity_scopes))
  ) {
    err_config(
      "Identity scopes require a matching identity mode ('openid' or 'fhirUser')"
    )
  }
  if (!length(scopes)) {
    err_config("SMART authorization requires at least one requested scope")
  }
  if (any(startsWith(scopes, "patient/"))) {
    require_capability("permission-patient")
    if (identical(launch, "standalone") && !"launch/patient" %in% scopes) {
      err_config("Standalone patient access requires launch/patient")
    }
  }
  if (identical(launch, "standalone") && "launch/patient" %in% scopes) {
    require_capability("context-standalone-patient")
  }
  if (identical(launch, "standalone") && "launch/encounter" %in% scopes) {
    require_capability("context-standalone-encounter")
  }
  if ("offline_access" %in% scopes) {
    require_capability("permission-offline")
  }
  if ("online_access" %in% scopes) {
    if (!identical(launch, "ehr")) {
      err_config("SMART online_access requires EHR launch")
    }
    require_capability("permission-online")
  }
  if (any(startsWith(scopes, "user/"))) {
    require_capability("permission-user")
  }
  if (any(startsWith(scopes, "system/"))) {
    err_config("SMART app launch does not support backend system scopes")
  }
  if (
    !identical(
      smart_scope_coverage(scopes, scopes, allow_v1_scopes)[["status"]],
      "covered"
    )
  ) {
    err_config("SMART client contains unsupported scope syntax")
  }
  resource_scopes <- scopes[grepl("^(patient|user)/", scopes)]
  v1_scopes <- grepl("\\.(read|write|\\*)(\\?|$)", resource_scopes)
  if (any(v1_scopes)) {
    require_capability("permission-v1")
  }
  if (!all(v1_scopes)) {
    require_capability("permission-v2")
  }
  if (identical(token_auth_style, "private_key_jwt")) {
    if (
      !is_valid_string(client_assertion_alg) ||
        !client_assertion_alg %in% c("RS384", "ES384") ||
        !client_assertion_alg %in%
          metadata[["token_endpoint_auth_signing_alg_values_supported"]] ||
        is.null(client_assertion_private_key) ||
        !is_valid_string(client_assertion_private_key_kid)
    ) {
      err_config(
        "SMART asymmetric registration requires a key, key ID and advertised RS384 or ES384"
      )
    }
  } else if (
    !is.null(client_assertion_private_key) ||
      !is.null(client_assertion_private_key_kid)
  ) {
    err_config("Assertion keys require a SMART asymmetric registration")
  }
  if (!identical(token_auth_style, "header") && length(client_secret)) {
    err_config("Client secrets require a SMART symmetric registration")
  }
  if (
    !is.null(response_mode) &&
      (!is_valid_string(response_mode) ||
        !response_mode %in% c("query", "form_post"))
  ) {
    err_config("SMART currently supports query and form_post callbacks")
  }
  if (
    isTRUE(metadata[["require_pushed_authorization_requests"]]) ||
      isTRUE(metadata[["require_signed_request_object"]])
  ) {
    err_config("SMART required PAR/JAR composition is not supported")
  }
  response_modes <- smart_discovery_array(metadata, "response_modes_supported")
  if (
    length(response_modes) && !(response_mode %||% "query") %in% response_modes
  ) {
    err_config("SMART callback response mode is not advertised")
  }
  oidc <- !identical(identity, "none")
  provider <- oauth_provider(
    name = label,
    auth_url = metadata[["authorization_endpoint"]],
    token_url = metadata[["token_endpoint"]],
    issuer = metadata[["issuer"]] %||% NA_character_,
    infer_oidc_from_issuer = oidc,
    issuer_match = "url",
    token_auth_style = token_auth_style,
    use_pkce = TRUE,
    pkce_method = "S256",
    use_nonce = oidc,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    id_token_required = oidc,
    id_token_validation = oidc,
    jwks_uri = if (oidc) metadata[["jwks_uri"]] else NA_character_,
    jwks_host_issuer_match = FALSE,
    jwks_host_allow_only = if (oidc) metadata[["jwks_uri"]] else NULL,
    revocation_url = metadata[["revocation_endpoint"]] %||% NA_character_,
    extra_auth_params = list(aud = discovery[["fhir_base"]]),
    response_modes_supported = response_modes,
    authorization_response_iss_parameter_supported = isTRUE(metadata[[
      "authorization_response_iss_parameter_supported"
    ]]),
    token_endpoint_auth_signing_alg_values_supported = smart_discovery_array(
      metadata,
      "token_endpoint_auth_signing_alg_values_supported"
    )
  )
  client <- oauth_client(
    provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = redirect_uri,
    scopes = scopes,
    response_mode = response_mode,
    authorization_method = authorization_method,
    authorization_server_mode = authorization_server_mode,
    authorization_server_redirect_uris = authorization_server_redirect_uris,
    client_assertion_private_key = client_assertion_private_key,
    client_assertion_private_key_kid = client_assertion_private_key_kid,
    client_assertion_alg = if (identical(token_auth_style, "private_key_jwt")) {
      client_assertion_alg
    } else {
      NULL
    },
    state_store = state_store,
    state_key = state_key,
    state_payload_max_age = state_payload_max_age
  )
  smart_policy <- list(
    version = "2.2.0",
    fhir_base = discovery[["fhir_base"]],
    launch = launch,
    identity = identity,
    allow_http_loopback = discovery[["allow_http_loopback"]],
    discovery_digest = state_policy_digest(discovery),
    discovery = discovery
  )
  if (identical(authorization_method, "POST")) {
    smart_policy[["authorization_method"]] <- "POST"
  }
  if (!is.null(initial_expires_in_fallback)) {
    smart_policy[["initial_expires_in_fallback"]] <- initial_expires_in_fallback
  }
  smart_policy[["online_access_policy"]] <- online_access_policy
  S7::props(client) <- list(
    scope_policy = list(
      profile = "smart",
      version = 1L,
      allow_v1_scopes = allow_v1_scopes
    ),
    smart = smart_policy,
    resource_bases = normalize_resource_bases(c(
      fhir = discovery[["fhir_base"]]
    )),
    required_scopes = required_scopes
  )
  client
}

client_uses_smart <- function(client) length(client@smart) > 0L

smart_identity_scopes <- function(identity) {
  switch(
    identity,
    none = character(),
    openid = "openid",
    fhirUser = c("openid", "fhirUser")
  )
}

smart_assert_client_policy <- function(client) {
  problem <- smart_validate_client(client)
  if (!is.null(problem)) {
    err_config(problem)
  }
  invisible(NULL)
}

smart_validate_client <- function(client) {
  if (!client_uses_smart(client)) {
    return(NULL)
  }
  if (!length(client@scopes)) {
    return(
      "OAuthClient: SMART authorization requires at least one requested scope"
    )
  }
  policy <- client@smart
  if (
    !identical(
      sort(setdiff(
        names(policy),
        c(
          "authorization_method",
          "initial_expires_in_fallback",
          "online_access_policy"
        )
      )),
      sort(c(
        "version",
        "fhir_base",
        "launch",
        "identity",
        "allow_http_loopback",
        "discovery_digest",
        "discovery"
      ))
    ) ||
      !identical(
        policy[["authorization_method"]] %||% "GET",
        client@authorization_method
      ) ||
      !identical(policy[["version"]], "2.2.0") ||
      !is_valid_string(policy[["fhir_base"]]) ||
      !is_valid_string(policy[["launch"]]) ||
      !policy[["launch"]] %in% c("standalone", "ehr") ||
      !is_valid_string(policy[["identity"]]) ||
      !policy[["identity"]] %in% c("none", "openid", "fhirUser") ||
      !client_uses_smart_scopes(client)
  ) {
    return("OAuthClient: invalid SMART policy")
  }
  online_policy <- policy[["online_access_policy"]] %||% "online_only"
  if (
    !is_valid_string(online_policy) ||
      !online_policy %in% c("online_only", "allow_offline")
  ) {
    return("OAuthClient: invalid SMART online_access_policy")
  }
  lifetime <- policy[["initial_expires_in_fallback"]]
  if (
    !is.null(lifetime) &&
      (!is.numeric(lifetime) ||
        length(lifetime) != 1L ||
        !is.finite(lifetime) ||
        lifetime <= 0)
  ) {
    return(
      "OAuthClient: SMART initial_expires_in_fallback must be a finite positive number of seconds"
    )
  }
  if (
    !identical(
      client@resource_bases,
      normalize_resource_bases(c(fhir = policy[["fhir_base"]]))
    )
  ) {
    return("OAuthClient: SMART client must retain its configured FHIR base")
  }
  provider <- client@provider
  style <- normalize_token_auth_style(provider@token_auth_style)
  if (!style %in% c("public", "header", "private_key_jwt")) {
    return(
      "OAuthClient: SMART token authentication requires public, header or private_key_jwt"
    )
  }
  if (identical(style, "private_key_jwt")) {
    if (
      !identical(client@client_assertion_typ, "JWT") ||
        !is_valid_string(client@client_assertion_private_key_kid) ||
        !is_valid_string(client@client_assertion_alg) ||
        !client@client_assertion_alg %in% c("RS384", "ES384")
    ) {
      return(
        "OAuthClient: SMART asymmetric authentication requires typ JWT, a key ID and explicit RS384 or ES384"
      )
    }
    audience <- client@client_assertion_audience
    if (is_valid_string(audience) && !identical(audience, provider@token_url)) {
      return(
        "OAuthClient: SMART client assertion audience must equal the token endpoint"
      )
    }
  }
  if (
    !identical(policy[["launch"]], "ehr") &&
      "online_access" %in% effective_client_scopes(client)
  ) {
    return("OAuthClient: SMART online_access requires EHR launch")
  }
  if (!is.null(client@claims)) {
    return("OAuthClient: SMART claims requests are not supported")
  }
  if (
    !isTRUE(provider@use_pkce) ||
      !identical(provider@pkce_method, "S256") ||
      !identical(client@request_object_mode, "parameters") ||
      is_valid_string(provider@par_url) ||
      !is.null(resolve_jarm_callback_transport(client)) ||
      !identical(
        provider@extra_auth_params,
        list(aud = policy[["fhir_base"]])
      ) ||
      !identical(provider@allowed_token_types, "Bearer") ||
      length(client@resource) ||
      !is.null(client@dpop_private_key) ||
      is_valid_string(client@mtls_client_cert_file)
  ) {
    return("OAuthClient: unsupported SMART request composition")
  }
  oidc <- !identical(policy[["identity"]], "none")
  if (
    !identical(provider_uses_oidc(provider), oidc) ||
      !all(
        smart_identity_scopes(policy[["identity"]]) %in% client@required_scopes
      ) ||
      !identical(provider@use_nonce, oidc) ||
      !identical(provider@id_token_validation, oidc) ||
      !identical(provider@id_token_required, oidc)
  ) {
    return("OAuthClient: SMART identity validation policy cannot be weakened")
  }
  tryCatch(
    {
      smart_validate_registration_policy(client)
      NULL
    },
    error = function(e) paste0("OAuthClient: ", conditionMessage(e))
  )
}

# Recheck the reviewed discovery policy after supported S7 property edits and
# before requests. A digest alone cannot validate newly selected endpoints or
# capabilities; retain the snapshot that established this registration.
smart_validate_registration_policy <- function(client) {
  policy <- client@smart
  discovery <- policy[["discovery"]]
  if (
    !is.list(discovery) ||
      !identical(
        state_policy_digest(discovery),
        policy[["discovery_digest"]]
      ) ||
      !identical(discovery[["fhir_base"]], policy[["fhir_base"]]) ||
      !identical(
        discovery[["allow_http_loopback"]],
        policy[["allow_http_loopback"]]
      )
  ) {
    err_config("SMART discovery policy must retain its reviewed snapshot")
  }
  allow_http <- discovery[["allow_http_loopback"]]
  connection_manager_flag(allow_http, "allow_http_loopback")
  hosts <- smart_discovery_hosts(discovery[["endpoint_hosts"]])
  metadata <- discovery[["metadata"]]
  smart_discovery_validate(metadata, hosts, allow_http)
  for (url in c(
    client@redirect_uri,
    client@authorization_server_redirect_uris
  )) {
    smart_discovery_url(url, "redirect_uri", allow_http)
  }
  provider <- client@provider
  smart_validate_authorization_query(provider@auth_url)
  endpoints <- c(
    authorization_endpoint = provider@auth_url,
    token_endpoint = provider@token_url,
    issuer = provider@issuer,
    jwks_uri = provider@jwks_uri,
    userinfo_endpoint = provider@userinfo_url,
    revocation_endpoint = provider@revocation_url,
    introspection_endpoint = provider@introspection_url
  )
  for (field in names(endpoints)) {
    if (!is_valid_string(endpoints[[field]])) {
      next
    }
    parsed <- smart_discovery_url(
      endpoints[[field]],
      field,
      allow_http,
      identifier = identical(field, "issuer")
    )
    if (!sub("^\\[::1\\]$", "::1", parsed[["host"]]) %in% hosts) {
      err_config(paste0("SMART ", field, " host is outside endpoint_hosts"))
    }
  }
  capabilities <- unlist(metadata[["capabilities"]], use.names = FALSE)
  require_capability <- function(value) {
    if (!value %in% capabilities) {
      err_config(paste("SMART capability required:", value))
    }
  }
  launch <- policy[["launch"]]
  require_capability(paste0("launch-", launch))
  if (identical(client@authorization_method, "POST")) {
    require_capability("authorize-post")
  }
  style <- normalize_token_auth_style(provider@token_auth_style)
  require_capability(c(
    public = "client-public",
    header = "client-confidential-symmetric",
    private_key_jwt = "client-confidential-asymmetric"
  )[[style]])
  methods <- smart_discovery_array(
    metadata,
    "token_endpoint_auth_methods_supported"
  )
  method <- c(
    public = "none",
    header = "client_secret_basic",
    private_key_jwt = "private_key_jwt"
  )[[style]]
  if (
    style != "public" &&
      "token_endpoint_auth_methods_supported" %in% names(metadata) &&
      !method %in% methods
  ) {
    err_config("SMART registration authentication method is not advertised")
  }
  if (
    style == "private_key_jwt" &&
      !client@client_assertion_alg %in%
        smart_discovery_array(
          metadata,
          "token_endpoint_auth_signing_alg_values_supported"
        )
  ) {
    err_config("SMART client assertion algorithm is not advertised")
  }
  modes <- smart_discovery_array(metadata, "response_modes_supported")
  if (length(modes) && !(client@response_mode %||% "query") %in% modes) {
    err_config("SMART callback response mode is not advertised")
  }
  scopes <- effective_client_scopes(client, warn = FALSE)
  if (launch == "ehr" && !"launch" %in% scopes) {
    err_config("SMART EHR clients require launch scope")
  }
  if (launch == "standalone" && "launch" %in% scopes) {
    err_config("Standalone SMART clients cannot request EHR launch scope")
  }
  if (any(startsWith(scopes, "system/"))) {
    err_config("SMART app launch does not support backend system scopes")
  }
  identity_scopes <- smart_identity_scopes(policy[["identity"]])
  if (length(identity_scopes)) {
    require_capability("sso-openid-connect")
    if (!all(identity_scopes %in% scopes)) {
      err_config("SMART identity scopes are required")
    }
  }
  if (
    length(setdiff(intersect(c("openid", "fhirUser"), scopes), identity_scopes))
  ) {
    err_config(
      "Identity scopes require a matching identity mode ('openid' or 'fhirUser')"
    )
  }
  if (any(startsWith(scopes, "patient/"))) {
    require_capability("permission-patient")
    if (launch == "standalone" && !"launch/patient" %in% scopes) {
      err_config("Standalone patient access requires launch/patient")
    }
  }
  if (any(startsWith(scopes, "user/"))) {
    require_capability("permission-user")
  }
  for (context in c("patient", "encounter")) {
    if (launch == "standalone" && paste0("launch/", context) %in% scopes) {
      require_capability(paste0("context-standalone-", context))
    }
  }
  if ("online_access" %in% scopes) {
    require_capability("permission-online")
  }
  if ("offline_access" %in% scopes) {
    require_capability("permission-offline")
  }
  allow_v1_scopes <- client@scope_policy[["allow_v1_scopes"]]
  if (
    smart_scope_coverage(scopes, scopes, allow_v1_scopes)[["status"]] !=
      "covered"
  ) {
    err_config("SMART client contains unsupported scope syntax")
  }
  resource_scopes <- scopes[grepl("^(patient|user)/", scopes)]
  v1 <- grepl("\\.(read|write|\\*)(\\?|$)", resource_scopes)
  if (any(v1)) {
    require_capability("permission-v1")
  }
  if (!all(v1)) {
    require_capability("permission-v2")
  }
  invisible(NULL)
}

smart_validate_authorization_query <- function(url) {
  fields <- decode_form_pairs(
    url_raw_query(url),
    "SMART authorization endpoint query"
  )
  # aud and launch belong to the current sealed SMART transaction. The other
  # fields would enable compositions this SMART client does not implement.
  forbidden <- c(
    "aud",
    "launch",
    "request",
    "request_uri",
    "max_age",
    "claims",
    "resource",
    "dpop_jkt"
  )
  if (any(names(fields) %in% forbidden)) {
    err_config(
      "SMART authorization endpoint query contains a reserved transaction or unsupported composition parameter"
    )
  }
  invisible(NULL)
}

smart_verify_token_response <- function(client, token_set, is_refresh = FALSE) {
  if (!client_uses_smart(client)) {
    return(token_set)
  }
  if (
    !is_valid_string(token_set[["token_type"]]) ||
      !identical(tolower(token_set[["token_type"]]), "bearer")
  ) {
    err_token("SMART app launch requires a Bearer token_type")
  }
  if (
    !isTRUE(is_refresh) &&
      !"expires_in" %in% names(token_set) &&
      !is.null(client@smart[["initial_expires_in_fallback"]])
  ) {
    token_set[["expires_in"]] <- client@smart[["initial_expires_in_fallback"]]
  }
  expires <- token_set[["expires_in"]]
  if (
    !is.numeric(expires) ||
      length(expires) != 1L ||
      !is.finite(expires) ||
      expires <= 0
  ) {
    err_token("SMART connections require an explicit positive expires_in")
  }
  token_set
}

smart_verify_identity <- function(client, token_set, is_refresh) {
  if (
    !client_uses_smart(client) ||
      !identical(client@smart[["identity"]], "fhirUser")
  ) {
    return(invisible(NULL))
  }
  if (isTRUE(is_refresh) && is.null(token_set[["id_token"]])) {
    return(invisible(NULL))
  }
  if (!isTRUE(token_set[[".id_token_validated"]])) {
    err_id_token("SMART fhirUser requires a validated ID token")
  }
  claims <- parse_jwt_payload(token_set[["id_token"]])
  # A valid signature does not make extension claims aliases of fhirUser.
  reference <- claims[["fhirUser"]]
  if (!is_valid_string(reference) || nchar(reference, type = "bytes") > 2048L) {
    err_id_token("SMART ID token requires a scalar fhirUser reference")
  }
  tryCatch(
    {
      if (
        grepl(
          paste0(
            "^(Patient|Practitioner|PractitionerRole|RelatedPerson|Person)/",
            "[A-Za-z0-9.-]{1,64}(/_history/[A-Za-z0-9.-]{1,64})?$"
          ),
          reference
        )
      ) {
        # SMART 2.2 explicitly permits references relative to the launch FHIR base.
        # The existing resource resolver also rejects dot segments and path escape.
        resolve_bound_resource(client@smart[["fhir_base"]], reference)
      } else {
        smart_discovery_url(
          reference,
          "fhirUser",
          client@smart[["allow_http_loopback"]]
        )
      }
    },
    error = function(...) {
      err_id_token("SMART ID token contains an invalid fhirUser reference")
    }
  )
  invisible(NULL)
}
