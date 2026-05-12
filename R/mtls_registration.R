# This file builds RFC 8705 mTLS registration metadata from an OAuthClient
# Used for manual onboarding or dynamic client-registration payloads

# 1 mTLS registration metadata -----------------------------------------------

## 1.1 Build client registration metadata ------------------------------------

#' Build RFC 8705 mTLS registration metadata
#'
#' @description
#' Returns a JSON-ready list of client metadata for registering an
#' [OAuthClient] that uses RFC 8705 mutual TLS.
#'
#' For `token_auth_style = "tls_client_auth"`, this helper returns
#' `token_endpoint_auth_method = "tls_client_auth"` plus exactly one RFC 8705
#' certificate identifier field:
#' `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`,
#' `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, or
#' `tls_client_auth_san_email`.
#'
#' For `token_auth_style = "self_signed_tls_client_auth"`, this helper returns
#' `token_endpoint_auth_method = "self_signed_tls_client_auth"` plus either an
#' inline `jwks` document built from the configured client certificate and
#' certificate chain (published via `x5c`), or a caller-supplied `jwks_uri`.
#'
#' This helper prepares metadata only. It does not make a registration HTTP
#' call.
#'
#' @param oauth_client [OAuthClient] configured for `tls_client_auth` or
#'   `self_signed_tls_client_auth`.
#' @param tls_client_auth_type For `tls_client_auth`, which RFC 8705
#'   certificate identifier field to emit. One of `"subject_dn"`, `"san_dns"`,
#'   `"san_uri"`, `"san_ip"`, or `"san_email"`.
#' @param tls_client_auth_value Optional explicit value for the selected
#'   `tls_client_auth_type`. When omitted, shinyOAuth derives the subject DN
#'   or, when possible, a unique matching SAN value from the configured client
#'   certificate. If the certificate exposes no unambiguous SAN for the chosen
#'   type, pass the exact registration value explicitly.
#' @param jwks_uri Optional absolute URL of a JWKS document to publish for
#'   `self_signed_tls_client_auth`. When omitted, the helper returns an inline
#'   `jwks` object with the configured client certificate chain in `x5c`.
#'
#' @return A JSON-ready list of RFC 7591/RFC 8705 client metadata.
#' @export
oauth_client_mtls_registration <- function(
  oauth_client,
  tls_client_auth_type = c(
    "subject_dn",
    "san_dns",
    "san_uri",
    "san_ip",
    "san_email"
  ),
  tls_client_auth_value = NULL,
  jwks_uri = NULL
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)
  tls_client_auth_type <- match.arg(tls_client_auth_type)

  if (
    !is.null(tls_client_auth_value) && !is_valid_string(tls_client_auth_value)
  ) {
    err_input(
      "{.arg tls_client_auth_value} must be NULL or a single non-empty string."
    )
  }
  if (!is.null(jwks_uri) && !is_valid_string(jwks_uri)) {
    err_input(
      "{.arg jwks_uri} must be NULL or a single non-empty string."
    )
  }

  token_auth_style <- normalize_token_auth_style(
    oauth_client@provider@token_auth_style %||% "header"
  )
  if (!(token_auth_style %in% MTLS_TOKEN_AUTH_STYLES)) {
    err_input(
      paste(
        "{.arg oauth_client} must use provider@token_auth_style =",
        "'tls_client_auth' or 'self_signed_tls_client_auth'."
      )
    )
  }
  if (!client_has_mtls_certificate(oauth_client)) {
    err_input(
      paste(
        "{.arg oauth_client} must include tls_client_cert_file and",
        "tls_client_key_file to build mTLS registration metadata."
      )
    )
  }

  if (identical(token_auth_style, "self_signed_tls_client_auth")) {
    if (!is.null(tls_client_auth_value)) {
      err_input(
        paste(
          "{.arg tls_client_auth_value} only applies when token_auth_style =",
          "'tls_client_auth'."
        )
      )
    }

    metadata <- list(token_endpoint_auth_method = token_auth_style)
    if (is.null(jwks_uri)) {
      metadata$jwks <- build_self_signed_mtls_registration_jwks(oauth_client)
      return(metadata)
    }

    validate_mtls_registration_jwks_uri(jwks_uri)
    metadata$jwks_uri <- jwks_uri
    return(metadata)
  }

  if (!is.null(jwks_uri)) {
    err_input(
      paste(
        "{.arg jwks_uri} only applies when token_auth_style =",
        "'self_signed_tls_client_auth'."
      )
    )
  }

  field_name <- mtls_registration_field_name(tls_client_auth_type)
  field_value <- resolve_mtls_registration_identifier_value(
    oauth_client = oauth_client,
    tls_client_auth_type = tls_client_auth_type,
    tls_client_auth_value = tls_client_auth_value
  )

  metadata <- list(token_endpoint_auth_method = token_auth_style)
  metadata[[field_name]] <- field_value
  metadata
}


# 2 Registration support helpers ----------------------------------------------

## 2.1 Resolve tls_client_auth identifiers ------------------------------------

#' Resolve an RFC 8705 registration field name
#'
#' @description
#' Maps a helper-friendly identifier type to the exact RFC 8705 client
#' metadata field name.
#'
#' @param tls_client_auth_type Identifier type selected for registration.
#' @return Character scalar field name.
#' @keywords internal
#' @noRd
mtls_registration_field_name <- function(tls_client_auth_type) {
  switch(
    tls_client_auth_type,
    subject_dn = "tls_client_auth_subject_dn",
    san_dns = "tls_client_auth_san_dns",
    san_uri = "tls_client_auth_san_uri",
    san_ip = "tls_client_auth_san_ip",
    san_email = "tls_client_auth_san_email",
    err_input(paste0(
      "Unsupported tls_client_auth_type: ",
      tls_client_auth_type
    ))
  )
}

#' Resolve an RFC 8705 tls_client_auth registration value
#'
#' @description
#' Resolves the value for the requested `tls_client_auth_*` registration field
#' from an explicit caller override or from the configured certificate.
#'
#' @param oauth_client OAuthClient carrying the certificate material.
#' @param tls_client_auth_type Identifier type selected for registration.
#' @param tls_client_auth_value Optional explicit registration value.
#' @return Character scalar registration value.
#' @keywords internal
#' @noRd
resolve_mtls_registration_identifier_value <- function(
  oauth_client,
  tls_client_auth_type,
  tls_client_auth_value = NULL
) {
  if (is_valid_string(tls_client_auth_value)) {
    return(trimws(tls_client_auth_value))
  }

  cert_info <- read_mtls_registration_certificate_info(oauth_client)
  if (identical(tls_client_auth_type, "subject_dn")) {
    subject <- cert_info$subject %||% NA_character_
    if (!is_valid_string(subject)) {
      err_config(
        "tls_client_cert_file does not expose a subject DN for tls_client_auth registration"
      )
    }
    return(subject)
  }

  resolve_certificate_alt_name_value(cert_info, tls_client_auth_type)
}

#' Read the keyed client certificate info for registration metadata
#'
#' @description
#' Loads the certificate that matches the configured private key and converts it
#' to the list form used by the registration helpers.
#'
#' @param oauth_client OAuthClient carrying the certificate material.
#' @return Certificate info list.
#' @keywords internal
#' @noRd
read_mtls_registration_certificate_info <- function(oauth_client) {
  cert <- read_keyed_client_certificate(
    oauth_client@tls_client_cert_file,
    key_file = oauth_client@tls_client_key_file,
    key_password = oauth_client@tls_client_key_password
  )
  info <- as.list(cert)
  if (!is.list(info)) {
    err_config(
      "Failed to inspect tls_client_cert_file for mTLS registration metadata"
    )
  }

  info
}

#' Resolve a SAN-derived registration value from certificate info
#'
#' @description
#' Selects a single matching SAN value for the requested RFC 8705 registration
#' field. When the certificate does not expose exactly one candidate, callers
#' must pass `tls_client_auth_value` explicitly.
#'
#' @param cert_info Certificate info list from `as.list(cert)`.
#' @param tls_client_auth_type Identifier type selected for registration.
#' @return Character scalar registration value.
#' @keywords internal
#' @noRd
resolve_certificate_alt_name_value <- function(
  cert_info,
  tls_client_auth_type
) {
  alt_names <- cert_info$alt_names %||% character(0)
  parsed <- Filter(
    Negate(is.null),
    lapply(alt_names, parse_certificate_alt_name)
  )
  matches <- Filter(
    function(entry) {
      identical(entry$type, tls_client_auth_type)
    },
    parsed
  )
  values <- unique(vapply(matches, function(entry) entry$value, character(1)))
  field_name <- mtls_registration_field_name(tls_client_auth_type)

  if (length(values) == 1L) {
    return(values[[1]])
  }
  if (length(values) == 0L) {
    err_input(paste(
      "Could not derive",
      field_name,
      "from tls_client_cert_file; pass tls_client_auth_value explicitly."
    ))
  }

  err_input(paste(
    "tls_client_cert_file exposes multiple candidate values for",
    field_name,
    "; pass tls_client_auth_value explicitly."
  ))
}

#' Parse one certificate alt name for RFC 8705 registration
#'
#' @description
#' Classifies a certificate alt name as DNS, URI, IP, or email so the
#' registration helper can map it to the corresponding RFC 8705 field.
#'
#' @param alt_name One SAN entry from the certificate info list.
#' @return List with `type` and `value`, or `NULL` when the entry is empty.
#' @keywords internal
#' @noRd
parse_certificate_alt_name <- function(alt_name) {
  value <- trimws(as.character(alt_name %||% ""))
  if (!nzchar(value)) {
    return(NULL)
  }

  prefixed_types <- list(
    san_dns = "^DNS:\\s*",
    san_uri = "^URI:\\s*",
    san_ip = "^(IP Address|IP):\\s*",
    san_email = "^(email|rfc822):\\s*"
  )
  for (type in names(prefixed_types)) {
    pattern <- prefixed_types[[type]]
    if (grepl(pattern, value, ignore.case = TRUE, perl = TRUE)) {
      return(list(
        type = type,
        value = trimws(sub(
          pattern,
          "",
          value,
          ignore.case = TRUE,
          perl = TRUE
        ))
      ))
    }
  }

  if (grepl("://", value, fixed = TRUE)) {
    return(list(type = "san_uri", value = value))
  }
  if (grepl("@", value, fixed = TRUE)) {
    return(list(type = "san_email", value = value))
  }
  if (
    grepl("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", value, perl = TRUE) ||
      grepl(":", value, fixed = TRUE)
  ) {
    return(list(type = "san_ip", value = value))
  }

  list(type = "san_dns", value = value)
}

## 2.2 Build self-signed registration JWKS ------------------------------------

#' Validate a self-signed mTLS JWKS URI
#'
#' @description
#' Ensures a caller-supplied `jwks_uri` is an absolute URL accepted by
#' shinyOAuth's host policy.
#'
#' @param jwks_uri Candidate JWKS URI.
#' @return Invisibly returns `jwks_uri` on success.
#' @keywords internal
#' @noRd
validate_mtls_registration_jwks_uri <- function(jwks_uri) {
  parsed <- try(httr2::url_parse(jwks_uri), silent = TRUE)
  if (
    inherits(parsed, "try-error") ||
      !nzchar(parsed$scheme %||% "") ||
      !nzchar(parsed$hostname %||% "")
  ) {
    err_input(
      "{.arg jwks_uri} must be an absolute URL (including scheme and hostname)."
    )
  }
  if (nzchar(parsed$fragment %||% "")) {
    err_input("{.arg jwks_uri} must not contain a URI fragment.")
  }
  if (!is_ok_host(jwks_uri)) {
    err_input(paste0(
      "jwks_uri not accepted as a host ",
      "(see `?is_ok_host` for details)"
    ))
  }

  invisible(jwks_uri)
}

#' Build inline JWKS metadata for self-signed mTLS registration
#'
#' @description
#' Builds a public JWKS payload from the configured client certificate and
#' matching private key, and publishes the certificate chain via `x5c`.
#'
#' @param oauth_client OAuthClient carrying the self-signed certificate.
#' @return JWKS list suitable for RFC 8705 client registration metadata.
#' @keywords internal
#' @noRd
build_self_signed_mtls_registration_jwks <- function(oauth_client) {
  certs <- read_client_certificates(oauth_client@tls_client_cert_file)
  leaf_cert <- read_keyed_client_certificate(
    oauth_client@tls_client_cert_file,
    key_file = oauth_client@tls_client_key_file,
    key_password = oauth_client@tls_client_key_password
  )
  leaf_fingerprint <- as.list(leaf_cert)$pubkey$fingerprint %||% NULL
  ordered_certs <- c(
    list(leaf_cert),
    Filter(
      function(cert) {
        cert_fingerprint <- as.list(cert)$pubkey$fingerprint %||% NULL
        !identical(cert_fingerprint, leaf_fingerprint)
      },
      certs
    )
  )

  pubkey <- try(openssl::read_pubkey(leaf_cert), silent = TRUE)
  if (inherits(pubkey, "try-error")) {
    err_config(
      paste(
        "Failed to extract a public key from tls_client_cert_file for",
        "self_signed_tls_client_auth registration"
      )
    )
  }

  jwk_json <- try(jose::jwk_write(pubkey), silent = TRUE)
  if (inherits(jwk_json, "try-error")) {
    err_config(
      paste(
        "Failed to serialize the self-signed TLS client certificate as a JWK"
      )
    )
  }
  jwk <- try(
    jsonlite::fromJSON(jwk_json, simplifyVector = FALSE),
    silent = TRUE
  )
  if (inherits(jwk, "try-error") || !is.list(jwk)) {
    err_parse("Failed to parse serialized self-signed mTLS JWK")
  }

  private_members <- intersect(
    names(jwk),
    c("d", "p", "q", "dp", "dq", "qi", "oth", "k")
  )
  if (length(private_members) > 0L) {
    err_config(
      "Serialized self-signed mTLS JWK unexpectedly contained private key material"
    )
  }

  x5c <- vapply(
    ordered_certs,
    function(cert) {
      der <- try(openssl::write_der(cert), silent = TRUE)
      if (inherits(der, "try-error")) {
        err_config(
          "Failed to serialize tls_client_cert_file for self-signed x5c metadata"
        )
      }

      as.character(openssl::base64_encode(der))
    },
    character(1)
  )
  jwk$x5c <- I(unname(x5c))

  jwks <- list(keys = list(jwk))
  validate_jwks(jwks)
  jwks
}
