#' Discover SMART on FHIR server metadata
#'
#' @description
#' Read and validate the SMART App Launch STU 2.2 discovery document for a
#' configured FHIR server. This returns server metadata for application setup;
#' it does not register an app, choose client credentials, or start authorization.
#'
#' @details
#' Call once during application setup, outside `server()`. The request appends
#' `/.well-known/smart-configuration` to the full FHIR base, removing its terminal
#' slash first. The supplied base and returned endpoint/issuer strings are
#' retained exactly, so discovery does not change protocol identifiers.
#'
#' This is separate from [oauth_provider_oidc_discover()]. OAuth-only SMART
#' metadata need not contain OIDC issuer or signing-key information. Advertised
#' `sso-openid-connect` requires both `issuer` and `jwks_uri`; their presence
#' does not validate an identity or fetch OIDC metadata or keys.
#'
#' Required SMART fields, conditional launch/SSO fields, and advertised
#' asymmetric-authentication metadata are checked. S256 must be advertised and
#' plain PKCE is rejected. Client-specific capability, scope, key and algorithm
#' selection belongs to the application's registration configuration.
#' `scopes_supported` is informative, not an exhaustive permission allowlist.
#'
#' @section Network and trust policy:
#' Supply a trusted, deployment-configured base, never an arbitrary browser
#' query parameter. The base must be an absolute HTTPS URL without userinfo,
#' query, fragment, or ambiguous path syntax. Discovered URLs must be absolute;
#' this reader does not repair relative URLs from legacy servers.
#'
#' `endpoint_hosts` applies to the issuer and these top-level URL fields when
#' present: `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
#' `registration_endpoint`, `management_endpoint`, `introspection_endpoint`,
#' `revocation_endpoint`, `userinfo_endpoint`,
#' `pushed_authorization_request_endpoint`, `smart_app_state_endpoint`, and
#' `user_access_brand_bundle`. Matching uses exact hostnames, independently of
#' port. This is a discovery policy; it does not authorize resource requests.
#' The generic `shinyOAuth.allowed_hosts` option can further restrict these URLs.
#'
#' The request carries no OAuth credentials. Redirects are refused even when
#' the generic redirect option is enabled. Existing package TLS, timeout,
#' response-size, and retry protections apply. JSON must be an object with no
#' duplicate members; arrays and recognized URL fields have bounded validation.
#' Errors do not include response bodies or returned metadata values.
#'
#' Unknown extensions, including `associated_endpoints`, are retained as data
#' only. Their URLs are not fetched or approved for credential use. No automatic
#' metadata cache is used: every call reads a new snapshot. Applications should
#' review metadata changes before replacing configuration; do not rediscover
#' endpoints during a pending authorization or to reinterpret a retained grant.
#'
#' @param fhir_base Trusted FHIR base URL, including its complete path, for
#'   example `"https://ehr.example/fhir/R4"`.
#' @param endpoint_hosts Character vector of exact permitted hostnames for
#'   recognized metadata URLs. `NULL` defaults to the FHIR base hostname.
#'   An explicit vector replaces that default; include every permitted host.
#'   Hostnames are case-insensitive. Wildcards, URLs, and ports are not accepted.
#' @param allow_http_loopback Logical, default `FALSE`. Explicit development
#'   exception permitting HTTP only at `localhost`, `127.0.0.1`, or `::1`.
#'   This applies to the base and metadata URLs and does not change global
#'   options. It does not establish production TLS interoperability.
#'
#' @return A plain named list with `fhir_base` (the supplied identifier),
#'   `discovery_url` (the requested URL), `smart_version` (`"2.2.0"`, the
#'   validation baseline, not a detected server version), `metadata` (the parsed
#'   document, with JSON arrays as lists), `endpoint_hosts` (the normalized
#'   policy), and `allow_http_loopback`. No client, token, or live cache is stored
#'   in the result. Invalid input or endpoint policy raises a
#'   `shinyOAuth_config_error`; malformed metadata raises a
#'   `shinyOAuth_parse_error`; failed HTTP requests raise a
#'   `shinyOAuth_http_error`.
#'
#' @seealso [oauth_provider_oidc_discover()], [oauth_target()]
#' @references
#' [SMART STU 2.2 discovery](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html)
#' and [asymmetric client metadata](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html).
#' @examples
#' \dontrun{
#' site <- smart_discover(
#'   "https://ehr.example/fhir/R4",
#'   endpoint_hosts = c("ehr.example", "login.example")
#' )
#' site$metadata$token_endpoint
#' site$metadata$capabilities
#'
#' }
#' @export
smart_discover <- function(
  fhir_base,
  endpoint_hosts = NULL,
  allow_http_loopback = FALSE
) {
  if (
    !is.logical(allow_http_loopback) ||
      length(allow_http_loopback) != 1L ||
      is.na(allow_http_loopback)
  ) {
    err_config("allow_http_loopback must be TRUE or FALSE")
  }
  base <- smart_discovery_url(
    fhir_base,
    "fhir_base",
    allow_http_loopback,
    identifier = TRUE
  )
  hosts <- smart_discovery_hosts(endpoint_hosts %||% base$host)
  discovery_url <- paste0(
    sub("/$", "", fhir_base),
    "/.well-known/smart-configuration"
  )
  req <- httr2::request(discovery_url) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    add_req_defaults() |>
    httr2::req_options(followlocation = FALSE)
  resp <- tryCatch(req_with_retry(req), error = function(e) {
    if (inherits(e, "shinyOAuth_parse_error")) {
      stop(e)
    }
    # Transport errors can include URLs and server-controlled diagnostic text.
    err_http("Failed to fetch SMART discovery document")
  })
  if (httr2::resp_status(resp) != 200L) {
    err_http("SMART discovery requires HTTP 200; redirects are not accepted")
  }
  metadata <- smart_discovery_parse(resp)
  smart_discovery_validate(metadata, hosts, allow_http_loopback)
  list(
    fhir_base = fhir_base,
    discovery_url = discovery_url,
    smart_version = "2.2.0",
    metadata = metadata,
    endpoint_hosts = hosts,
    allow_http_loopback = allow_http_loopback
  )
}

smart_discovery_url <- function(
  url,
  field,
  allow_http_loopback,
  identifier = FALSE
) {
  parsed <- tryCatch(
    resource_binding_components(url, base = identifier, canonicalize = FALSE),
    error = function(...) NULL
  )
  if (is.null(parsed)) {
    err_config(paste0(
      "SMART ",
      field,
      " must be an absolute URL with unambiguous syntax"
    ))
  }
  if (parsed$scheme != "https" && !allow_http_loopback) {
    err_config(paste0(
      "SMART ",
      field,
      " requires HTTPS; HTTP loopback needs explicit opt-in"
    ))
  }
  parsed
}

smart_discovery_hosts <- function(hosts) {
  if (
    !is.character(hosts) ||
      !length(hosts) ||
      length(hosts) > 64L ||
      anyNA(hosts) ||
      !is.null(names(hosts))
  ) {
    err_config("endpoint_hosts must contain 1 to 64 exact hostnames")
  }
  hosts <- tolower(hosts)
  valid <- vapply(
    hosts,
    function(host) {
      if (host %in% c("::1", "[::1]")) {
        return(TRUE)
      }
      nchar(host, type = "bytes") <= 253L &&
        grepl("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host) &&
        !grepl("(^|\\.)(-|$)|-\\.|\\.\\.", host)
    },
    logical(1)
  )
  if (!all(valid)) {
    err_config(
      "endpoint_hosts must use exact hostnames without wildcards, ports or URL syntax"
    )
  }
  sort(unique(sub("^\\[::1\\]$", "::1", hosts)))
}

smart_discovery_parse <- function(resp) {
  check_resp_body_size(resp, context = "smart_discovery")
  content_type <- tolower(httr2::resp_header(resp, "content-type") %||% "")
  if (!grepl("^application/json(?:\\s*;|$)", content_type, perl = TRUE)) {
    err_parse("SMART discovery response must use application/json")
  }
  body <- httr2::resp_body_string(resp)
  reject_duplicate_json_object_members(
    body,
    "SMART discovery JSON",
    on_error = function(...) {
      err_parse(
        "SMART discovery JSON has duplicate members or excessive nesting"
      )
    }
  )
  metadata <- tryCatch(
    jsonlite::fromJSON(body, simplifyVector = FALSE),
    error = function(...) err_parse("Invalid SMART discovery JSON")
  )
  if (
    !grepl("^[\\t\\r\\n ]*\\{", body) ||
      !is.list(metadata) ||
      is.null(names(metadata))
  ) {
    err_parse("SMART discovery JSON must be an object")
  }
  metadata
}

smart_discovery_array <- function(metadata, field, required = FALSE) {
  if (!field %in% names(metadata) && !required) {
    return(character())
  }
  value <- metadata[[field]]
  if (
    !is.list(value) ||
      !length(value) ||
      length(value) > 4096L ||
      !is.null(names(value)) ||
      !all(vapply(
        value,
        function(item) {
          is_valid_string(item) &&
            nchar(item, type = "bytes") <= 8192L &&
            identical(trimws(item), item) &&
            !grepl("[[:cntrl:]]", item) &&
            (field == "response_types_supported" || !grepl("[[:space:]]", item))
        },
        logical(1)
      ))
  ) {
    err_parse(paste0(
      "SMART ",
      field,
      " must be a non-empty JSON array of non-empty strings"
    ))
  }
  unlist(value, use.names = FALSE)
}

smart_discovery_validate <- function(metadata, hosts, allow_http_loopback) {
  capabilities <- smart_discovery_array(
    metadata,
    "capabilities",
    required = TRUE
  )
  grants <- smart_discovery_array(
    metadata,
    "grant_types_supported",
    required = TRUE
  )
  pkce <- smart_discovery_array(
    metadata,
    "code_challenge_methods_supported",
    required = TRUE
  )
  if (!"S256" %in% pkce || "plain" %in% pkce) {
    err_parse(
      "SMART code_challenge_methods_supported must include S256 and exclude plain"
    )
  }
  launch <- any(c("launch-standalone", "launch-ehr") %in% capabilities)
  sso <- "sso-openid-connect" %in% capabilities
  if (launch && !"authorization_code" %in% grants) {
    err_parse(
      "SMART launch capabilities require authorization_code in grant_types_supported"
    )
  }
  required_urls <- c(
    "token_endpoint",
    if (launch) "authorization_endpoint",
    if (sso) c("issuer", "jwks_uri")
  )
  for (field in required_urls) {
    if (!field %in% names(metadata) || is.null(metadata[[field]])) {
      err_parse(paste0(
        "SMART discovery requires ",
        field,
        " for the advertised capabilities"
      ))
    }
  }
  if (!sso && "issuer" %in% names(metadata)) {
    err_parse("SMART issuer requires the sso-openid-connect capability")
  }
  url_fields <- c(
    "issuer",
    "jwks_uri",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "management_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "userinfo_endpoint",
    "pushed_authorization_request_endpoint",
    "smart_app_state_endpoint",
    "user_access_brand_bundle"
  )
  for (field in intersect(url_fields, names(metadata))) {
    if (!is_valid_string(metadata[[field]])) {
      err_parse(paste0("SMART ", field, " must be a non-empty URL string"))
    }
    endpoint <- smart_discovery_url(
      metadata[[field]],
      field,
      allow_http_loopback,
      identifier = identical(field, "issuer")
    )
    host <- sub("^\\[::1\\]$", "::1", endpoint$host)
    if (!host %in% hosts) {
      err_config(paste0("SMART ", field, " host is outside endpoint_hosts"))
    }
  }
  for (field in c(
    "scopes_supported",
    "response_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported"
  )) {
    smart_discovery_array(metadata, field)
  }
  if (
    launch &&
      "response_types_supported" %in% names(metadata) &&
      !"code" %in% metadata$response_types_supported
  ) {
    err_parse("SMART response_types_supported must include code for app launch")
  }
  if ("client-confidential-asymmetric" %in% capabilities) {
    methods <- smart_discovery_array(
      metadata,
      "token_endpoint_auth_methods_supported",
      TRUE
    )
    algorithms <- smart_discovery_array(
      metadata,
      "token_endpoint_auth_signing_alg_values_supported",
      TRUE
    )
    smart_discovery_array(metadata, "scopes_supported", TRUE)
    if (
      !"private_key_jwt" %in% methods ||
        !any(c("RS384", "ES384") %in% algorithms)
    ) {
      err_parse(
        "SMART asymmetric capability requires private_key_jwt and RS384 or ES384 metadata"
      )
    }
  }
  invisible(TRUE)
}
