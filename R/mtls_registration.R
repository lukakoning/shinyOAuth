# This file builds RFC 8705 mTLS registration metadata from an OAuthClient
# Used for manual onboarding or dynamic client-registration payloads

# 1 mTLS registration metadata -----------------------------------------------

## 1.1 Build client registration metadata ------------------------------------

#' Build RFC 8705 mTLS registration metadata
#'
#' @description
#' Returns a JSON-ready list of client metadata for registering an
#' [OAuthClient] that uses RFC 8705 mutual TLS or requests
#' certificate-bound access tokens.
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
#' For clients that request RFC 8705 certificate-bound access tokens without
#' mTLS OAuth client authentication, this helper returns the runtime
#' `token_auth_style` mapped back to the dynamic-registration metadata value
#' (for example, `public` becomes `none`) and emits
#' `tls_client_certificate_bound_access_tokens = TRUE`.
#'
#' This helper prepares metadata only. It does not make a registration HTTP
#' call.
#'
#' @param oauth_client [OAuthClient] configured for RFC 8705 mutual TLS client
#'   authentication or for certificate-bound access tokens.
#' @param tls_client_auth_type For `tls_client_auth`, which RFC 8705
#'   certificate identifier field to emit. One of `"subject_dn"`, `"san_dns"`,
#'   `"san_uri"`, `"san_ip"`, or `"san_email"`.
#' @param tls_client_auth_value Optional explicit value for the selected
#'   `tls_client_auth_type`. When omitted, shinyOAuth derives the subject DN
#'   or, when possible, a unique matching SAN value from the configured client
#'   certificate. Auto-derived IP SAN values are normalized to dotted-decimal
#'   IPv4 or RFC 5952 IPv6 text. If the certificate exposes no unambiguous SAN
#'   for the chosen type, pass the exact registration value explicitly.
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
  requests_certificate_bound_tokens <- client_requests_certificate_bound_tokens(
    oauth_client
  )

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
  if (
    !(token_auth_style %in% MTLS_TOKEN_AUTH_STYLES) &&
      !isTRUE(requests_certificate_bound_tokens)
  ) {
    err_input(
      paste(
        "{.arg oauth_client} must use an RFC 8705 mTLS token_auth_style or",
        "set mtls_certificate_bound_access_tokens = TRUE."
      )
    )
  }
  if (!client_has_mtls_certificate(oauth_client)) {
    err_input(
      paste(
        "{.arg oauth_client} must include mtls_client_cert_file and",
        "mtls_client_key_file to build mTLS registration metadata."
      )
    )
  }

  metadata <- compact_list(list(
    token_endpoint_auth_method = mtls_registration_token_endpoint_auth_method(
      token_auth_style
    ),
    tls_client_certificate_bound_access_tokens = if (
      isTRUE(requests_certificate_bound_tokens)
    ) {
      TRUE
    } else {
      NULL
    }
  ))

  if (identical(token_auth_style, "self_signed_tls_client_auth")) {
    if (!is.null(tls_client_auth_value)) {
      err_input(
        paste(
          "{.arg tls_client_auth_value} only applies when token_auth_style =",
          "'tls_client_auth'."
        )
      )
    }

    if (is.null(jwks_uri)) {
      metadata[["jwks"]] <- build_self_signed_mtls_registration_jwks(
        oauth_client
      )
      return(metadata)
    }

    validate_mtls_registration_jwks_uri(jwks_uri)
    metadata[["jwks_uri"]] <- jwks_uri
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

  if (!identical(token_auth_style, "tls_client_auth")) {
    if (!is.null(tls_client_auth_value)) {
      err_input(
        paste(
          "{.arg tls_client_auth_value} only applies when token_auth_style =",
          "'tls_client_auth'."
        )
      )
    }

    return(metadata)
  }

  field_name <- mtls_registration_field_name(tls_client_auth_type)
  field_value <- resolve_mtls_registration_identifier_value(
    oauth_client = oauth_client,
    tls_client_auth_type = tls_client_auth_type,
    tls_client_auth_value = tls_client_auth_value
  )

  metadata[[field_name]] <- field_value
  metadata
}


# 2 Registration support helpers ----------------------------------------------

## 2.1 Resolve tls_client_auth identifiers ------------------------------------

#' Map a runtime token auth style to registration metadata
#'
#' @description
#' Converts shinyOAuth's normalized runtime auth styles to the corresponding
#' `token_endpoint_auth_method` values used by OAuth dynamic registration.
#'
#' @param token_auth_style Normalized runtime token auth style.
#' @return Character scalar registration auth method value.
#' @keywords internal
#' @noRd
mtls_registration_token_endpoint_auth_method <- function(token_auth_style) {
  switch(
    token_auth_style,
    header = "client_secret_basic",
    body = "client_secret_post",
    public = "none",
    tls_client_auth = "tls_client_auth",
    self_signed_tls_client_auth = "self_signed_tls_client_auth",
    client_secret_jwt = "client_secret_jwt",
    private_key_jwt = "private_key_jwt",
    err_input(paste0(
      "Unsupported token_auth_style for mTLS registration: ",
      token_auth_style
    ))
  )
}

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
    subject <- cert_info[["subject"]] %||% NA_character_
    if (!is_valid_string(subject)) {
      err_config(
        "mtls_client_cert_file does not expose a subject DN for tls_client_auth registration"
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
    oauth_client@mtls_client_cert_file,
    key_file = oauth_client@mtls_client_key_file,
    key_password = oauth_client@mtls_client_key_password
  )
  info <- as.list(cert)
  if (!is.list(info)) {
    err_config(
      "Failed to inspect mtls_client_cert_file for mTLS registration metadata"
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
  alt_names <- cert_info[["alt_names"]] %||% character(0)
  parsed <- Filter(
    Negate(is.null),
    lapply(alt_names, parse_certificate_alt_name)
  )
  matches <- Filter(
    function(entry) {
      identical(entry[["type"]], tls_client_auth_type)
    },
    parsed
  )
  values <- unique(vapply(
    matches,
    function(entry) entry[["value"]],
    character(1)
  ))
  field_name <- mtls_registration_field_name(tls_client_auth_type)

  if (length(values) == 1L) {
    return(values[[1]])
  }
  if (length(values) == 0L) {
    err_input(paste(
      "Could not derive",
      field_name,
      "from mtls_client_cert_file; pass tls_client_auth_value explicitly."
    ))
  }

  err_input(paste(
    "mtls_client_cert_file exposes multiple candidate values for",
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
      parsed_value <- trimws(sub(
        pattern,
        "",
        value,
        ignore.case = TRUE,
        perl = TRUE
      ))
      if (!nzchar(parsed_value)) {
        return(NULL)
      }

      return(list(
        type = type,
        value = normalize_mtls_registration_alt_name_value(
          type,
          parsed_value
        )
      ))
    }
  }

  ip_value <- try(normalize_mtls_registration_ip_literal(value), silent = TRUE)
  if (!inherits(ip_value, "try-error")) {
    return(list(type = "san_ip", value = ip_value))
  }
  if (grepl("^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:]]+$", value, perl = TRUE)) {
    return(list(type = "san_uri", value = value))
  }
  if (grepl("^[^@[:space:]]+@[^@[:space:]]+$", value, perl = TRUE)) {
    return(list(type = "san_email", value = value))
  }
  if (grepl("^[A-Za-z0-9*.-]+$", value, perl = TRUE)) {
    return(list(type = "san_dns", value = value))
  }

  NULL
}

#' Normalize a parsed SAN value for RFC 8705 registration
#'
#' @description
#' Normalizes SAN values after type detection so auto-derived registration
#' metadata uses the RFC-required IP text representation while preserving the
#' original DNS, URI, and email strings.
#'
#' @param type Parsed SAN type.
#' @param value Parsed SAN value.
#' @return Character scalar SAN value.
#' @keywords internal
#' @noRd
normalize_mtls_registration_alt_name_value <- function(type, value) {
  normalized <- trimws(as.character(value %||% ""))
  if (!nzchar(normalized)) {
    err_input("Certificate SAN values must be non-empty strings")
  }

  if (!identical(type, "san_ip")) {
    return(normalized)
  }

  normalize_mtls_registration_ip_literal(normalized)
}

#' Normalize a SAN IP literal for RFC 8705 registration
#'
#' @description
#' Converts IPv4 literals to dotted-decimal form and IPv6 literals to RFC 5952
#' text so `tls_client_auth_san_ip` values are serialized consistently.
#'
#' @param value Candidate SAN IP literal.
#' @return Character scalar IP literal.
#' @keywords internal
#' @noRd
normalize_mtls_registration_ip_literal <- function(value) {
  normalized <- trimws(as.character(value %||% ""))
  if (!nzchar(normalized)) {
    err_input("Certificate SAN IP values must be non-empty strings")
  }

  ipv4 <- try(
    normalize_mtls_registration_ipv4_literal(normalized),
    silent = TRUE
  )
  if (!inherits(ipv4, "try-error")) {
    return(ipv4)
  }

  ipv6 <- try(
    normalize_mtls_registration_ipv6_literal(normalized),
    silent = TRUE
  )
  if (!inherits(ipv6, "try-error")) {
    return(ipv6)
  }

  err_input(paste(
    "Could not normalize certificate SAN IP value to dotted-decimal IPv4 or",
    "RFC 5952 IPv6 text; pass tls_client_auth_value explicitly."
  ))
}

#' Normalize an IPv4 literal for RFC 8705 registration
#'
#' @description
#' Parses a dotted-quad IPv4 literal and rewrites it without leading zeros.
#'
#' @param value Candidate IPv4 literal.
#' @return Character scalar IPv4 literal.
#' @keywords internal
#' @noRd
normalize_mtls_registration_ipv4_literal <- function(value) {
  parts <- strsplit(value, ".", fixed = TRUE)[[1]]
  if (length(parts) != 4L || !all(grepl("^[0-9]{1,3}$", parts, perl = TRUE))) {
    err_input("Invalid IPv4 SAN literal")
  }

  octets <- as.integer(parts)
  if (any(is.na(octets) | octets < 0L | octets > 255L)) {
    err_input("Invalid IPv4 SAN literal")
  }

  paste(octets, collapse = ".")
}

#' Normalize an IPv6 literal for RFC 5952 registration
#'
#' @description
#' Parses an IPv6 literal, expands it to eight 16-bit fields, and rewrites it
#' using RFC 5952 zero-compression and lowercase rules.
#'
#' @param value Candidate IPv6 literal.
#' @return Character scalar IPv6 literal.
#' @keywords internal
#' @noRd
normalize_mtls_registration_ipv6_literal <- function(value) {
  normalized <- tolower(trimws(as.character(value %||% "")))
  if (!nzchar(normalized) || grepl("%", normalized, fixed = TRUE)) {
    err_input("Invalid IPv6 SAN literal")
  }

  normalized <- expand_mtls_registration_ipv6_embedded_ipv4(normalized)
  has_compression <- grepl("::", normalized, fixed = TRUE)
  if (has_compression && grepl("::.*::", normalized, perl = TRUE)) {
    err_input("Invalid IPv6 SAN literal")
  }

  if (has_compression) {
    sides <- strsplit(normalized, "::", fixed = TRUE)[[1]]
    if (length(sides) != 2L) {
      err_input("Invalid IPv6 SAN literal")
    }

    left <- parse_mtls_registration_ipv6_hextets(sides[[1]])
    right <- parse_mtls_registration_ipv6_hextets(sides[[2]])
    zero_count <- 8L - length(left) - length(right)
    if (zero_count < 1L) {
      err_input("Invalid IPv6 SAN literal")
    }

    hextets <- c(left, rep.int(0L, zero_count), right)
  } else {
    hextets <- parse_mtls_registration_ipv6_hextets(normalized)
    if (length(hextets) != 8L) {
      err_input("Invalid IPv6 SAN literal")
    }
  }

  if (length(hextets) != 8L) {
    err_input("Invalid IPv6 SAN literal")
  }

  canonical <- vapply(
    hextets,
    function(hextet) as.character(as.hexmode(hextet)),
    character(1)
  )
  zero_run <- locate_mtls_registration_ipv6_zero_run(hextets)
  build_mtls_registration_ipv6_literal(canonical, zero_run)
}

#' Expand an embedded IPv4 suffix inside an IPv6 literal
#'
#' @description
#' Converts mixed IPv6/IPv4 notation to pure 16-bit IPv6 fields so the caller
#' can apply RFC 5952 compression rules consistently.
#'
#' @param value Candidate IPv6 literal.
#' @return IPv6 literal with any embedded IPv4 suffix expanded to hexadecimal.
#' @keywords internal
#' @noRd
expand_mtls_registration_ipv6_embedded_ipv4 <- function(value) {
  if (!grepl("\\.", value)) {
    return(value)
  }
  if (!grepl(":", value, fixed = TRUE)) {
    err_input("Invalid IPv6 SAN literal")
  }

  ipv4_suffix <- sub("^.*:", "", value, perl = TRUE)
  ipv4_normalized <- normalize_mtls_registration_ipv4_literal(ipv4_suffix)
  octets <- as.integer(strsplit(ipv4_normalized, ".", fixed = TRUE)[[1]])
  hex_tail <- c(
    sprintf("%x", octets[[1]] * 256L + octets[[2]]),
    sprintf("%x", octets[[3]] * 256L + octets[[4]])
  )

  paste0(sub("[^:]*$", "", value, perl = TRUE), paste(hex_tail, collapse = ":"))
}

#' Parse the explicit hextets from one side of an IPv6 literal
#'
#' @description
#' Parses the non-compressed portion of an IPv6 literal into 16-bit integers.
#'
#' @param value One side of an IPv6 literal split around `::`.
#' @return Integer vector of parsed hextets.
#' @keywords internal
#' @noRd
parse_mtls_registration_ipv6_hextets <- function(value) {
  if (!nzchar(value)) {
    return(integer(0))
  }

  parts <- strsplit(value, ":", fixed = TRUE)[[1]]
  if (!all(nzchar(parts))) {
    err_input("Invalid IPv6 SAN literal")
  }

  vapply(
    parts,
    parse_mtls_registration_ipv6_hextet,
    integer(1)
  )
}

#' Parse a single IPv6 hextet
#'
#' @description
#' Validates and parses one hexadecimal 16-bit field from an IPv6 literal.
#'
#' @param value Candidate IPv6 hextet.
#' @return Integer scalar hextet value.
#' @keywords internal
#' @noRd
parse_mtls_registration_ipv6_hextet <- function(value) {
  if (!grepl("^[0-9a-f]{1,4}$", value, perl = TRUE)) {
    err_input("Invalid IPv6 SAN literal")
  }

  parsed <- strtoi(value, base = 16L)
  if (is.na(parsed) || parsed < 0L || parsed > 65535L) {
    err_input("Invalid IPv6 SAN literal")
  }

  as.integer(parsed)
}

#' Locate the zero run to compress in an RFC 5952 IPv6 literal
#'
#' @description
#' Finds the longest run of zero 16-bit fields and keeps the first run when
#' there is a tie, matching RFC 5952 Section 4.2.3.
#'
#' @param hextets Integer vector of eight IPv6 hextets.
#' @return `NULL` when no run should be compressed; otherwise a list with
#'   `start` and `end` indices.
#' @keywords internal
#' @noRd
locate_mtls_registration_ipv6_zero_run <- function(hextets) {
  best_start <- NA_integer_
  best_length <- 0L
  current_start <- NA_integer_
  current_length <- 0L

  for (index in seq_along(hextets)) {
    if (identical(hextets[[index]], 0L)) {
      if (identical(current_length, 0L)) {
        current_start <- index
      }
      current_length <- current_length + 1L
      next
    }

    if (current_length > best_length) {
      best_start <- current_start
      best_length <- current_length
    }
    current_start <- NA_integer_
    current_length <- 0L
  }

  if (current_length > best_length) {
    best_start <- current_start
    best_length <- current_length
  }

  if (best_length < 2L) {
    return(NULL)
  }

  list(start = best_start, end = best_start + best_length - 1L)
}

#' Build an RFC 5952 IPv6 literal from parsed hextets
#'
#' @description
#' Serializes canonicalized IPv6 hextets, applying `::` compression only to the
#' zero run selected by `locate_mtls_registration_ipv6_zero_run()`.
#'
#' @param hextets Character vector of canonicalized IPv6 hextets.
#' @param zero_run Optional zero-run metadata.
#' @return Character scalar IPv6 literal.
#' @keywords internal
#' @noRd
build_mtls_registration_ipv6_literal <- function(hextets, zero_run = NULL) {
  if (is.null(zero_run)) {
    return(paste(hextets, collapse = ":"))
  }

  left <- if (zero_run[["start"]] > 1L) {
    paste(
      hextets[seq_len(zero_run[["start"]] - 1L)],
      collapse = ":"
    )
  } else {
    ""
  }
  right <- if (zero_run[["end"]] < length(hextets)) {
    paste(
      hextets[(zero_run[["end"]] + 1L):length(hextets)],
      collapse = ":"
    )
  } else {
    ""
  }

  if (nzchar(left) && nzchar(right)) {
    return(paste0(left, "::", right))
  }
  if (nzchar(left)) {
    return(paste0(left, "::"))
  }
  if (nzchar(right)) {
    return(paste0("::", right))
  }

  "::"
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
      !nzchar(parsed[["scheme"]] %||% "") ||
      !nzchar(parsed[["hostname"]] %||% "")
  ) {
    err_input(
      "{.arg jwks_uri} must be an absolute URL (including scheme and hostname)."
    )
  }
  if (nzchar(parsed[["fragment"]] %||% "")) {
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
  certs <- read_client_certificates(oauth_client@mtls_client_cert_file)
  leaf_cert <- read_keyed_client_certificate(
    oauth_client@mtls_client_cert_file,
    key_file = oauth_client@mtls_client_key_file,
    key_password = oauth_client@mtls_client_key_password
  )
  leaf_fingerprint <- tryCatch(
    {
      as.list(leaf_cert)[["pubkey"]][[
        "fingerprint",
        exact = TRUE
      ]] %||%
        NULL
    },
    error = function(...) NULL
  )
  ordered_certs <- c(
    list(leaf_cert),
    Filter(
      function(cert) {
        cert_fingerprint <- tryCatch(
          {
            as.list(cert)[["pubkey"]][[
              "fingerprint",
              exact = TRUE
            ]] %||%
              NULL
          },
          error = function(...) NULL
        )
        !identical(cert_fingerprint, leaf_fingerprint)
      },
      certs
    )
  )

  pubkey <- try(openssl::read_pubkey(leaf_cert), silent = TRUE)
  if (inherits(pubkey, "try-error")) {
    err_config(
      paste(
        "Failed to extract a public key from mtls_client_cert_file for",
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
          "Failed to serialize mtls_client_cert_file for self-signed x5c metadata"
        )
      }

      as.character(openssl::base64_encode(der))
    },
    character(1)
  )
  jwk[["x5c"]] <- I(unname(x5c))

  jwks <- list(keys = list(jwk))
  validate_jwks(jwks)
  jwks
}
