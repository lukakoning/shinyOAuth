# This file contains the low-level helpers that parse compact JWTs and verify
# generic JWS signatures.
# Use them when code needs strict JWT segment decoding, JOSE header checks, or
# algorithm-specific signature verification without yet applying ID-token rules.

# 1 JWT parsing helpers ----------------------------------------------------

## 1.1 Parse payload and header -------------------------------------------

#' Parse JWT payload (unsigned validation only)
#'
#' @keywords internal
#' @noRd
parse_jwt_payload <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  payload_text <- strict_decode_jwt_json_text(parts$payload_raw, "payload")
  reject_duplicate_json_object_members(payload_text, "JWT payload")
  # Normalize JSON parse failures to a consistent parse error class
  tryCatch(
    jsonlite::fromJSON(payload_text, simplifyVector = TRUE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWT payload JSON",
        "i" = conditionMessage(e)
      ))
    }
  )
}

#' Internal: Parse JWT header (no validation)
#'
#' @keywords internal
#' @noRd
parse_jwt_header <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  header_text <- strict_decode_jwt_json_text(parts$header_raw, "header")
  reject_duplicate_json_object_members(header_text, "JWT header")
  # Normalize JSON parse failures to a consistent parse error class
  tryCatch(
    jsonlite::fromJSON(header_text, simplifyVector = FALSE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWT header JSON",
        "i" = conditionMessage(e)
      ))
    }
  )
}

## 1.2 Compact JWT parsing and JSON decoding ------------------------------

strict_decode_jwt_segment <- function(
  segment,
  field_name,
  allow_empty = FALSE
) {
  if (
    !is.character(segment) ||
      length(segment) != 1L ||
      is.na(segment)
  ) {
    err_parse(paste0("JWT ", field_name, " segment invalid"))
  }

  if (!nzchar(segment)) {
    if (isTRUE(allow_empty)) {
      return(raw())
    }
    err_parse(paste0("JWT ", field_name, " segment must not be empty"))
  }

  if (!grepl("^[A-Za-z0-9_-]+$", segment)) {
    err_parse(paste0(
      "JWT ",
      field_name,
      " segment must use strict base64url alphabet without padding"
    ))
  }

  if ((nchar(segment) %% 4L) == 1L) {
    err_parse(paste0(
      "JWT ",
      field_name,
      " segment has invalid base64url length"
    ))
  }

  decoded <- tryCatch(base64url_decode_raw(segment), error = function(...) NULL)
  if (is.null(decoded) || !is.raw(decoded)) {
    err_parse(paste0("JWT ", field_name, " segment could not be decoded"))
  }

  decoded
}

# Split a compact JWT into its three decoded segments and signing input.
# Used by parse and verification helpers. Input: compact JWT string. Output:
# list of raw and character parts.
jwt_compact_parts <- function(jwt, allow_empty_signature = TRUE) {
  if (!is.character(jwt) || length(jwt) != 1L || is.na(jwt)) {
    err_parse(
      "Invalid JWT format: expected a single compact serialization string"
    )
  }

  dot_pos <- gregexpr(".", jwt, fixed = TRUE)[[1]]
  if (length(dot_pos) != 2L || identical(dot_pos[[1]], -1L)) {
    err_parse("Invalid JWT format: expected 3 dot-separated parts")
  }

  list(
    header = substr(jwt, 1L, dot_pos[1] - 1L),
    payload = substr(jwt, dot_pos[1] + 1L, dot_pos[2] - 1L),
    signature = substr(jwt, dot_pos[2] + 1L, nchar(jwt)),
    signing_input = substr(jwt, 1L, dot_pos[2] - 1L),
    header_raw = strict_decode_jwt_segment(
      substr(jwt, 1L, dot_pos[1] - 1L),
      "header"
    ),
    payload_raw = strict_decode_jwt_segment(
      substr(jwt, dot_pos[1] + 1L, dot_pos[2] - 1L),
      "payload"
    ),
    signature_raw = strict_decode_jwt_segment(
      substr(jwt, dot_pos[2] + 1L, nchar(jwt)),
      "signature",
      allow_empty = allow_empty_signature
    )
  )
}

# Decode one raw JWT segment into validated JSON text.
# Used by header and payload parsing. Input: raw segment bytes and field name.
# Output: JSON text string.
strict_decode_jwt_json_text <- function(segment_raw, field_name) {
  stopifnot(is.raw(segment_raw))

  if (any(segment_raw == as.raw(0))) {
    err_parse(paste0(
      "JWT ",
      field_name,
      " segment contains embedded NUL byte"
    ))
  }

  text <- tryCatch(rawToChar(segment_raw), error = function(e) {
    err_parse(c(
      paste0("Failed to decode JWT ", field_name, " JSON text"),
      "i" = conditionMessage(e)
    ))
  })

  if (!isTRUE(validUTF8(text))) {
    err_parse(c(
      paste0("Failed to decode JWT ", field_name, " JSON text"),
      "i" = "Segment is not valid UTF-8"
    ))
  }

  text
}

# Reject duplicate top-level JSON object member names.
# Used before parsing JWT headers and payloads. Input: JSON text and label.
# Output: invisible NULL or a parse error.
reject_duplicate_json_object_members <- function(json_text, label) {
  chars <- strsplit(enc2utf8(json_text), "", fixed = TRUE)[[1]]
  if (!length(chars)) {
    return(invisible(NULL))
  }

  # Decode one JSON string token while preserving escape handling.
  # Used only by reject_duplicate_json_object_members(). Input: token string.
  # Output: decoded member name.
  decode_json_string_token <- function(token) {
    tryCatch(
      jsonlite::fromJSON(
        paste0('["', token, '"]'),
        simplifyVector = TRUE
      )[[1]],
      error = function(...) token
    )
  }

  depth <- 0L
  index <- 1L
  seen <- character(0)

  while (index <= length(chars)) {
    ch <- chars[[index]]

    if (identical(ch, '"')) {
      token <- character(0)
      index <- index + 1L
      escaping <- FALSE

      while (index <= length(chars)) {
        ch_inner <- chars[[index]]
        if (isTRUE(escaping)) {
          token <- c(token, ch_inner)
          escaping <- FALSE
        } else if (identical(ch_inner, "\\")) {
          token <- c(token, ch_inner)
          escaping <- TRUE
        } else if (identical(ch_inner, '"')) {
          break
        } else {
          token <- c(token, ch_inner)
        }
        index <- index + 1L
      }

      if (index > length(chars)) {
        return(invisible(NULL))
      }

      lookahead <- index + 1L
      while (
        lookahead <= length(chars) &&
          grepl("[[:space:]]", chars[[lookahead]])
      ) {
        lookahead <- lookahead + 1L
      }

      if (
        depth == 1L &&
          lookahead <= length(chars) &&
          identical(chars[[lookahead]], ":")
      ) {
        key <- decode_json_string_token(paste(token, collapse = ""))
        if (key %in% seen) {
          err_parse(paste0(label, " contains duplicate member name: ", key))
        }
        seen <- c(seen, key)
      }
    } else if (identical(ch, "{") || identical(ch, "[")) {
      depth <- depth + 1L
    } else if (identical(ch, "}") || identical(ch, "]")) {
      depth <- max(0L, depth - 1L)
    }

    index <- index + 1L
  }

  invisible(NULL)
}

## 1.3 JOSE header validation ---------------------------------------------

# Validate the JOSE header fields that shinyOAuth understands.
# Used before JWT signature or claim validation. Input: parsed header object and
# error-signaling function. Output: normalized header fields list.
validate_jose_header_fields <- function(header, signal_error) {
  if (!is.list(header) || is.null(names(header))) {
    signal_error("JWT header must be a JSON object")
  }

  # Validate one optional scalar string JOSE header field.
  # Used only by validate_jose_header_fields(). Input: field value, field name,
  # and whether it is required. Output: normalized value or NULL.
  validate_scalar_string_field <- function(value, field, required = FALSE) {
    if (is.null(value)) {
      if (isTRUE(required)) {
        signal_error(paste0("JWT header missing ", field))
      }
      return(NULL)
    }

    if (
      !is.character(value) ||
        length(value) != 1L ||
        is.na(value) ||
        !nzchar(value)
    ) {
      suffix <- if (isTRUE(required)) "" else " when present"
      signal_error(paste0(
        "JWT ",
        field,
        " header must be a single non-empty string",
        suffix
      ))
    }

    value
  }

  # Validate the JOSE crit header and enforce its expected shape.
  # Used only by validate_jose_header_fields(). Input: crit value. Output:
  # normalized crit vector or NULL.
  validate_crit_field <- function(value) {
    if (is.null(value)) {
      return(NULL)
    }

    crit <- NULL
    if (is.character(value)) {
      crit <- value
    } else if (
      is.list(value) &&
        length(value) > 0L &&
        all(vapply(
          value,
          function(item) {
            is.character(item) && length(item) == 1L
          },
          logical(1)
        ))
    ) {
      crit <- vapply(value, identity, character(1), USE.NAMES = FALSE)
    }

    if (
      is.null(crit) ||
        length(crit) == 0L ||
        anyNA(crit) ||
        !all(nzchar(crit)) ||
        anyDuplicated(crit)
    ) {
      signal_error(
        "JWT crit header must be a non-empty character vector of unique extension names"
      )
    }

    crit
  }

  alg <- validate_scalar_string_field(
    header$alg %||% NULL,
    "alg",
    required = TRUE
  )
  kid <- validate_scalar_string_field(header$kid %||% NULL, "kid")
  typ <- validate_scalar_string_field(header$typ %||% NULL, "typ")
  crit <- validate_crit_field(header$crit %||% NULL)

  list(
    alg = alg,
    kid = kid,
    typ = typ,
    crit = crit
  )
}

# Enforce the shared inbound JWT header policy after structural validation.
# Used by ID token and signed UserInfo JWT validation. Input: normalized header
# fields, error-signaling function, optional supported crit names, and optional
# side-effect callbacks for invalid typ/crit cases. Output: invisible header_fields.
enforce_inbound_jwt_header_policy <- function(
  header_fields,
  signal_error,
  supported_crit = character(),
  on_typ_invalid = NULL,
  on_crit_invalid = NULL
) {
  typ <- header_fields$typ
  if (!is.null(typ)) {
    if (
      !(is.character(typ) &&
        length(typ) == 1L &&
        identical(toupper(typ), "JWT"))
    ) {
      if (is.function(on_typ_invalid)) {
        on_typ_invalid()
      }
      signal_error(paste0(
        "JWT typ header invalid: expected 'JWT' when present, got ",
        paste(as.character(typ), collapse = ", ")
      ))
    }
  }

  crit <- header_fields$crit
  if (!is.null(crit)) {
    unsupported <- setdiff(crit, supported_crit)
    if (length(unsupported) > 0L) {
      if (is.function(on_crit_invalid)) {
        on_crit_invalid()
      }
      signal_error(paste0(
        "JWT contains unsupported critical header parameter(s): ",
        paste(unsupported, collapse = ", ")
      ))
    }
  }

  invisible(header_fields)
}

## 1.4 Signature verification helpers -------------------------------------

# Extract the raw bytes needed for JWS signature verification.
# Used by the generic signature verifiers in this file. Input: compact JWT.
# Output: list with signing input bytes and signature bytes.
jwt_verification_parts <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  list(
    data = charToRaw(parts$signing_input),
    sig = parts$signature_raw
  )
}

# Verify one asymmetric JWS signature without leaking detailed timing errors.
# Used by inbound JWT validation. Input: compact JWT, public key, and alg.
# Output: TRUE or FALSE.
verify_jws_signature_no_time <- function(jwt, key, alg) {
  parts <- tryCatch(jwt_verification_parts(jwt), error = function(...) NULL)
  if (is.null(parts)) {
    return(FALSE)
  }

  alg_upper <- toupper(alg %||% "")

  tryCatch(
    {
      if (alg_upper %in% c("RS256", "RS384", "RS512")) {
        size <- as.integer(substring(alg_upper, 3L))
        digest <- openssl::sha2(parts$data, size = size)
        return(isTRUE(openssl::signature_verify(
          digest,
          parts$sig,
          hash = NULL,
          pubkey = key
        )))
      }

      if (alg_upper %in% c("ES256", "ES384", "ES512")) {
        expected_width <- switch(
          alg_upper,
          ES256 = 64L,
          ES384 = 96L,
          ES512 = 132L,
          NA_integer_
        )
        if (
          is.na(expected_width) ||
            length(parts$sig) != expected_width
        ) {
          return(FALSE)
        }

        bitsize <- expected_width %/% 2L
        sig_der <- openssl::ecdsa_write(
          parts$sig[seq_len(bitsize)],
          parts$sig[seq_len(bitsize) + bitsize]
        )
        digest <- openssl::sha2(
          parts$data,
          size = as.integer(substring(alg_upper, 3L))
        )

        return(isTRUE(openssl::signature_verify(
          digest,
          sig_der,
          hash = NULL,
          pubkey = key
        )))
      }

      if (identical(alg_upper, "EDDSA")) {
        return(isTRUE(openssl::signature_verify(
          parts$data,
          parts$sig,
          hash = NULL,
          pubkey = key
        )))
      }

      FALSE
    },
    error = function(...) FALSE
  )
}

# Verify one HMAC JWS signature using a constant-time comparison path.
# Used by inbound HS* JWT validation. Input: compact JWT, secret, and alg.
# Output: TRUE or FALSE.
verify_hmac_jws_signature_no_time <- function(jwt, secret, alg) {
  parts <- tryCatch(jwt_verification_parts(jwt), error = function(...) NULL)
  if (is.null(parts)) {
    return(FALSE)
  }

  secret_raw <- tryCatch(
    {
      if (is.character(secret)) {
        charToRaw(enc2utf8(secret))
      } else {
        secret
      }
    },
    error = function(...) NULL
  )
  if (is.null(secret_raw) || !is.raw(secret_raw)) {
    return(FALSE)
  }

  tryCatch(
    {
      expected <- openssl::sha2(
        parts$data,
        size = as.integer(substring(toupper(alg), 3L)),
        key = secret_raw
      )
      # Compare HMAC tags as raw bytes through the shared constant-time helper.
      constant_time_compare(
        parts$sig,
        as.raw(expected)
      )
    },
    error = function(...) FALSE
  )
}
