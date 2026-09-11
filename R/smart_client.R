#' Configure a SMART on FHIR app registration
#'
#' Combine a reviewed [smart_discover()] snapshot with an existing app
#' registration. The result is an [OAuthClient] for [oauth_connections()], with
#' the resource ID `"fhir"`. Discovery does not register the app or grant access.
#'
#' This constructor selects SMART 2.2 scope rules, S256 PKCE and the exact FHIR
#' base as the authorization request's `aud`. Identity is opt-in: `"fhirUser"`
#' requests and requires `openid fhirUser`, signed ID-token validation and nonce
#' binding. `"none"` does not enable OIDC because an issuer happens to be present.
#' A patient in context is independent of the authenticated user and local owner.
#'
#' Only direct authorization requests and query/form POST callbacks are currently
#' supported. JAR, PAR, JARM, DPoP, mTLS and remote freshness requirements need
#' separate SMART composition work; this constructor provides no overrides for
#' those features. EHR clients require a fresh registered launch transaction.
#' Configure standalone and EHR registrations as separate clients when both are
#' needed. No launch handle is stored in shared provider configuration.
#' Local usability policy requires a positive `expires_in` in initial and
#' refresh responses; the generic assumed lifetime is not used for SMART.
#'
#' @param discovery A plain snapshot returned by [smart_discover()]. Its metadata
#'   and endpoint policy are revalidated locally; this performs no network calls.
#' @param client_id,redirect_uri App registration values. The callback must use
#'   HTTPS, except for the snapshot's explicit HTTP loopback development policy.
#' @param scopes Permissions to request, without automatic wildcard/offline
#'   access. Standalone patient scopes require `launch/patient`. EHR clients add
#'   `launch`. Supported scope syntax must be advertised through `permission-v2`
#'   (or the explicit v1 compatibility selection).
#' @param required_scopes Minimum permissions, defaulting to `scopes`. Pass a
#'   subset to accept reduced grants as limited connections. Identity scopes are
#'   always required when identity is enabled. Unsupported comparisons fail closed.
#' @param token_auth_style Registration type: `"public"`, `"header"` for a
#'   symmetric secret using HTTP Basic, or `"private_key_jwt"`. Selection must
#'   agree with advertised capabilities. Confidential methods must also agree
#'   with authentication metadata; public clients do not authenticate and need
#'   no `"none"` entry in that metadata.
#' @param client_secret Secret for a symmetric registration; otherwise omit.
#' @param client_assertion_private_key,client_assertion_private_key_kid Private
#'   signing key and registered key ID for asymmetric authentication; see
#'   [oauth_client()]. Required for `"private_key_jwt"`.
#' @param client_assertion_alg `"RS384"` (default) or `"ES384"`; the key and server
#'   metadata must support the selected algorithm. Other styles omit assertions.
#' @param launch `"standalone"` or `"ehr"`, matching the registered app flow.
#' @param identity `"none"` (default) or `"fhirUser"`. A validated `fhirUser`
#'   claim may be an absolute URL or a supported resource instance reference
#'   relative to this client's FHIR base, such as `"Practitioner/example"`.
#' @param allow_v1 Explicit compatibility flag enabling `.read`, `.write` and
#'   `.*`; requires the advertised `permission-v1` capability. Default `FALSE`.
#' @param authorization_method `"GET"` (default) or `"POST"` for the outgoing
#'   browser request. POST requires the discovered `authorize-post` capability
#'   and uses the module's `request_login()` or [prepare_authorization_request()].
#' @param response_mode `NULL`, `"query"`, or `"form_post"`. Advertised response
#'   modes, when present, must allow the selection.
#' @param authorization_server_mode,authorization_server_redirect_uris See
#'   [oauth_client()]. Multiple clients use distinct registered callback routes.
#' @param state_store,state_key,state_payload_max_age See [oauth_client()].
#' @param label Display label, default `"FHIR server"`; no credentials or context.
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
#' client@smart$launch
#' }
#' @export
smart_client <- function(
  discovery, client_id, redirect_uri, scopes, required_scopes = scopes,
  token_auth_style = c("public", "header", "private_key_jwt"),
  client_secret = character(), client_assertion_private_key = NULL,
  client_assertion_private_key_kid = NULL, client_assertion_alg = "RS384",
  launch = c("standalone", "ehr"), identity = c("none", "fhirUser"),
  allow_v1 = FALSE, response_mode = NULL,
  authorization_server_mode = "single",
  authorization_server_redirect_uris = character(),
  state_store = cachem::cache_mem(max_age = 300),
  state_key = random_urlsafe(128), state_payload_max_age = 300,
  label = "FHIR server", authorization_method = "GET"
) {
  token_auth_style <- match.arg(token_auth_style)
  launch <- match.arg(launch)
  identity <- match.arg(identity)
  connection_manager_flag(allow_v1, "allow_v1")
  if (!is.list(discovery) || !identical(discovery$smart_version, "2.2.0") ||
      !is.list(discovery$metadata)) {
    err_config("smart_client requires a SMART 2.2 discovery snapshot")
  }
  connection_manager_flag(discovery$allow_http_loopback, "allow_http_loopback")
  smart_discovery_url(discovery$fhir_base, "fhir_base",
    discovery$allow_http_loopback, identifier = TRUE)
  smart_discovery_url(redirect_uri, "redirect_uri",
    discovery$allow_http_loopback, identifier = TRUE)
  hosts <- smart_discovery_hosts(discovery$endpoint_hosts)
  metadata <- discovery$metadata
  smart_discovery_validate(metadata, hosts, discovery$allow_http_loopback)
  capabilities <- unlist(metadata$capabilities, use.names = FALSE)
  require_capability <- function(value) {
    if (!value %in% capabilities) err_config(paste("SMART capability required:", value))
  }
  require_capability(paste0("launch-", launch))
  if (identical(authorization_method, "POST")) require_capability("authorize-post")
  require_capability(c(public = "client-public", header = "client-confidential-symmetric",
    private_key_jwt = "client-confidential-asymmetric")[[token_auth_style]])
  methods <- smart_discovery_array(metadata, "token_endpoint_auth_methods_supported")
  method <- c(public = "none", header = "client_secret_basic",
    private_key_jwt = "private_key_jwt")[[token_auth_style]]
  # SMART lists confidential authentication methods here. Public-client support
  # comes from client-public; the SMART metadata contract does not require none.
  if (!identical(token_auth_style, "public") && length(methods) && !method %in% methods) {
    err_config("SMART registration authentication method is not advertised")
  }
  require_capability(if (allow_v1) "permission-v1" else "permission-v2")
  validate_scopes(scopes)
  validate_scopes(required_scopes)
  scopes <- normalize_scope_tokens(scopes)
  required_scopes <- normalize_scope_tokens(required_scopes)
  if (identical(launch, "ehr")) scopes <- union(scopes, "launch")
  if (identical(launch, "standalone") && "launch" %in% scopes) {
    err_config("Standalone SMART clients cannot request EHR launch scope")
  }
  if (identical(identity, "fhirUser")) {
    require_capability("sso-openid-connect")
    scopes <- union(scopes, c("openid", "fhirUser"))
    required_scopes <- union(required_scopes, c("openid", "fhirUser"))
  } else if (any(c("openid", "fhirUser") %in% scopes)) {
    err_config("Identity scopes require identity = 'fhirUser'")
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
  if ("offline_access" %in% scopes) require_capability("permission-offline")
  if ("online_access" %in% scopes) require_capability("permission-online")
  if (any(startsWith(scopes, "user/"))) require_capability("permission-user")
  if (any(startsWith(scopes, "system/"))) {
    err_config("SMART app launch does not support backend system scopes")
  }
  if (!identical(smart_scope_coverage(scopes, scopes, allow_v1)$status, "covered")) {
    err_config("SMART client contains unsupported scope syntax")
  }
  if (identical(token_auth_style, "private_key_jwt")) {
    if (!is_valid_string(client_assertion_alg) ||
        !client_assertion_alg %in% c("RS384", "ES384") ||
        !client_assertion_alg %in% metadata$token_endpoint_auth_signing_alg_values_supported ||
        is.null(client_assertion_private_key) ||
        !is_valid_string(client_assertion_private_key_kid)) {
      err_config("SMART asymmetric registration requires a key, key ID and advertised RS384 or ES384")
    }
  } else if (!is.null(client_assertion_private_key) ||
      !is.null(client_assertion_private_key_kid)) {
    err_config("Assertion keys require a SMART asymmetric registration")
  }
  if (!identical(token_auth_style, "header") && length(client_secret)) {
    err_config("Client secrets require a SMART symmetric registration")
  }
  if (!is.null(response_mode) &&
      (!is_valid_string(response_mode) || !response_mode %in% c("query", "form_post"))) {
    err_config("SMART currently supports query and form_post callbacks")
  }
  if (isTRUE(metadata$require_pushed_authorization_requests) ||
      isTRUE(metadata$require_signed_request_object)) {
    err_config("SMART required PAR/JAR composition is not supported")
  }
  response_modes <- smart_discovery_array(metadata, "response_modes_supported")
  if (length(response_modes) && !(response_mode %||% "query") %in% response_modes) {
    err_config("SMART callback response mode is not advertised")
  }
  oidc <- identical(identity, "fhirUser")
  provider <- oauth_provider(
    name = label, auth_url = metadata$authorization_endpoint,
    token_url = metadata$token_endpoint, issuer = metadata$issuer %||% NA_character_,
    issuer_thus_oidc = oidc, issuer_match = "url", token_auth_style = token_auth_style,
    use_pkce = TRUE, pkce_method = "S256", use_nonce = oidc,
    userinfo_required = FALSE, userinfo_id_token_match = FALSE,
    id_token_required = oidc, id_token_validation = oidc,
    jwks_uri = if (oidc) metadata$jwks_uri else NA_character_,
    jwks_host_issuer_match = FALSE,
    jwks_host_allow_only = if (oidc) metadata$jwks_uri else NULL,
    revocation_url = metadata$revocation_endpoint %||% NA_character_,
    extra_auth_params = list(aud = discovery$fhir_base),
    response_modes_supported = response_modes,
    authorization_response_iss_parameter_supported =
      isTRUE(metadata$authorization_response_iss_parameter_supported),
    token_endpoint_auth_signing_alg_values_supported =
      smart_discovery_array(metadata, "token_endpoint_auth_signing_alg_values_supported")
  )
  client <- oauth_client(provider, client_id = client_id, client_secret = client_secret,
    redirect_uri = redirect_uri, scopes = scopes, response_mode = response_mode,
    authorization_method = authorization_method,
    authorization_server_mode = authorization_server_mode,
    authorization_server_redirect_uris = authorization_server_redirect_uris,
    client_assertion_private_key = client_assertion_private_key,
    client_assertion_private_key_kid = client_assertion_private_key_kid,
    client_assertion_alg = if (identical(token_auth_style, "private_key_jwt")) {
      client_assertion_alg
    } else NULL,
    state_store = state_store, state_key = state_key,
    state_payload_max_age = state_payload_max_age)
  smart_policy <- list(version = "2.2.0", fhir_base = discovery$fhir_base,
    launch = launch, identity = identity, allow_http_loopback = discovery$allow_http_loopback,
    discovery_digest = state_policy_digest(discovery))
  if (identical(authorization_method, "POST")) smart_policy$authorization_method <- "POST"
  S7::props(client) <- list(
    scope_policy = list(profile = "smart", version = 1L, allow_v1 = allow_v1),
    smart = smart_policy,
    resource_bases = normalize_resource_bases(c(fhir = discovery$fhir_base)),
    required_scopes = required_scopes
  )
  client
}

client_uses_smart <- function(client) length(client@smart) > 0L

smart_validate_client <- function(client) {
  if (!client_uses_smart(client)) return(NULL)
  policy <- client@smart
  if (!identical(sort(setdiff(names(policy), "authorization_method")), sort(c("version", "fhir_base", "launch",
      "identity", "allow_http_loopback", "discovery_digest"))) ||
      !identical(policy$authorization_method %||% "GET", client@authorization_method) ||
      !identical(policy$version, "2.2.0") ||
      !is_valid_string(policy$fhir_base) ||
      !is_valid_string(policy$launch) || !policy$launch %in% c("standalone", "ehr") ||
      !is_valid_string(policy$identity) || !policy$identity %in% c("none", "fhirUser") ||
      !client_uses_smart_scopes(client)) return("OAuthClient: invalid SMART policy")
  if (!identical(client@resource_bases,
      normalize_resource_bases(c(fhir = policy$fhir_base)))) {
    return("OAuthClient: SMART client must retain its configured FHIR base")
  }
  provider <- client@provider
  if (!isTRUE(provider@use_pkce) || !identical(provider@pkce_method, "S256") ||
      !identical(client@request_object_mode, "parameters") ||
      is_valid_string(provider@par_url) ||
      !is.null(resolve_jarm_callback_transport(client)) ||
      !identical(provider@extra_auth_params, list(aud = policy$fhir_base)) ||
      !identical(provider@allowed_token_types, "Bearer") ||
      length(client@resource) || !is.null(client@dpop_private_key) ||
      is_valid_string(client@mtls_client_cert_file)) {
    return("OAuthClient: unsupported SMART request composition")
  }
  oidc <- identical(policy$identity, "fhirUser")
  if (!identical(provider_uses_oidc(provider), oidc) ||
      (oidc && !all(c("openid", "fhirUser") %in% client@required_scopes)) ||
      !identical(provider@use_nonce, oidc) ||
      !identical(provider@id_token_validation, oidc) ||
      !identical(provider@id_token_required, oidc)) {
    return("OAuthClient: SMART identity validation policy cannot be weakened")
  }
  NULL
}

smart_verify_token_response <- function(client, token_set) {
  if (!client_uses_smart(client)) return(invisible(NULL))
  if (!is_valid_string(token_set$token_type) ||
      !identical(tolower(token_set$token_type), "bearer")) {
    err_token("SMART app launch requires a Bearer token_type")
  }
  expires <- token_set$expires_in
  if (!is.numeric(expires) || length(expires) != 1L ||
      !is.finite(expires) || expires <= 0) {
    err_token("SMART connections require an explicit positive expires_in")
  }
  invisible(NULL)
}

smart_verify_identity <- function(client, token_set, is_refresh) {
  if (!client_uses_smart(client) || !identical(client@smart$identity, "fhirUser")) {
    return(invisible(NULL))
  }
  if (isTRUE(is_refresh) && is.null(token_set$id_token)) return(invisible(NULL))
  if (!isTRUE(token_set$.id_token_validated)) {
    err_id_token("SMART fhirUser requires a validated ID token")
  }
  claims <- parse_jwt_payload(token_set$id_token)
  reference <- claims$fhirUser
  if (!is_valid_string(reference) || nchar(reference, type = "bytes") > 2048L) {
    err_id_token("SMART ID token requires a scalar fhirUser reference")
  }
  tryCatch({
    if (grepl("^(Patient|Practitioner|PractitionerRole|RelatedPerson|Person)/[A-Za-z0-9.-]{1,64}$", reference)) {
      # SMART 2.2 explicitly permits references relative to the launch FHIR base.
      # The existing resource resolver also rejects dot segments and path escape.
      resolve_bound_resource(client@smart$fhir_base, reference)
    } else {
      smart_discovery_url(reference, "fhirUser", client@smart$allow_http_loopback)
    }
  }, error = function(...) err_id_token("SMART ID token contains an invalid fhirUser reference"))
  invisible(NULL)
}
