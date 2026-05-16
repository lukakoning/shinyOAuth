# This file contains the low-level helpers that parse compact JWTs and verify
# generic JWS signatures
# A JWT is a compact signed token format used widely in OAuth and OIDC
# Used for decoding token parts, checking headers, and verifying signatures
# before higher-level ID token rules are applied

# 1 JWT parsing helpers --------------------------------------------------------

## 1.1 Parse payload and header ------------------------------------------------

#' Parse JWT payload (unsigned validation only)
#'
#' Used by inbound JWT validators after compact parsing succeeds.
#'
#' @param jwt Compact JWT string.
#' @return Parsed JWT payload object.
#' @keywords internal
#' @noRd
parse_jwt_payload <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  payload_text <- strict_decode_jwt_json_text(parts$payload_raw, "payload")
  reject_duplicate_json_object_members(payload_text, "JWT payload")
  assert_json_text_is_object(payload_text, "JWT payload")
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
#' Used before JOSE header policy checks and key selection.
#'
#' @param jwt Compact JWT string.
#' @return Parsed JOSE header list.
#' @keywords internal
#' @noRd
parse_jwt_header <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  header_text <- strict_decode_jwt_json_text(parts$header_raw, "header")
  reject_duplicate_json_object_members(header_text, "JWT header")
  assert_json_text_is_object(header_text, "JWT header")
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

## 1.2 Compact JWT parsing and JSON decoding -----------------------------------

#' Strictly decode one compact JWT segment
#'
#' Used by compact JWT parsing.
#'
#' @param segment Encoded compact-JWT segment.
#' @param field_name Human-readable segment label.
#' @param allow_empty Whether an empty segment is allowed.
#' @return Raw decoded segment bytes.
#' @keywords internal
#' @noRd
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

#' Split a compact JWT into decoded parts
#'
#' Used by header, payload, and signature helpers.
#'
#' @param jwt Compact JWT string.
#' @param allow_empty_signature Whether an empty signature segment is allowed.
#' @return List containing the encoded segments, decoded raw segments, and
#'   signing input.
#' @keywords internal
#' @noRd
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

#' Decode one JWT JSON segment
#'
#' Used after compact JWT segments are base64url-decoded.
#'
#' @param segment_raw Raw decoded segment bytes.
#' @param field_name Human-readable segment label.
#' @return JSON text string.
#' @keywords internal
#' @noRd
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

  Encoding(text) <- "UTF-8"

  text
}

#' Probe one compact JWT segment without signaling
#'
#' Used by best-effort JWT observation helpers that must treat opaque tokens as
#' ordinary input rather than as reportable parse failures.
#'
#' @param segment Encoded compact-JWT segment.
#' @param allow_empty Whether an empty segment is allowed.
#' @return Raw decoded segment bytes, or `NULL` when the segment is absent or
#'   invalid.
#' @keywords internal
#' @noRd
jwt_probe_segment_raw <- function(segment, allow_empty = FALSE) {
  if (
    !is.character(segment) ||
      length(segment) != 1L ||
      is.na(segment)
  ) {
    return(NULL)
  }

  if (!nzchar(segment)) {
    if (isTRUE(allow_empty)) {
      return(raw())
    }
    return(NULL)
  }

  if (!grepl("^[A-Za-z0-9_-]+$", segment)) {
    return(NULL)
  }

  if ((nchar(segment) %% 4L) == 1L) {
    return(NULL)
  }

  decoded <- tryCatch(base64url_decode_raw(segment), error = function(...) NULL)
  if (is.null(decoded) || !is.raw(decoded)) {
    return(NULL)
  }

  decoded
}

#' Best-effort split of a compact JWT
#'
#' Used by non-validating JWT probes that should return `NULL` instead of
#' signaling parse errors for opaque access tokens.
#'
#' @param jwt Compact JWT candidate string.
#' @param allow_empty_signature Whether an empty signature segment is allowed.
#' @return List matching `jwt_compact_parts()`, or `NULL` when `jwt` is not a
#'   clean compact JWT.
#' @keywords internal
#' @noRd
jwt_compact_parts_or_null <- function(jwt, allow_empty_signature = TRUE) {
  if (!is.character(jwt) || length(jwt) != 1L || is.na(jwt)) {
    return(NULL)
  }

  dot_pos <- gregexpr(".", jwt, fixed = TRUE)[[1]]
  if (length(dot_pos) != 2L || identical(dot_pos[[1]], -1L)) {
    return(NULL)
  }

  header <- substr(jwt, 1L, dot_pos[1] - 1L)
  payload <- substr(jwt, dot_pos[1] + 1L, dot_pos[2] - 1L)
  signature <- substr(jwt, dot_pos[2] + 1L, nchar(jwt))

  header_raw <- jwt_probe_segment_raw(header)
  payload_raw <- jwt_probe_segment_raw(payload)
  signature_raw <- jwt_probe_segment_raw(
    signature,
    allow_empty = allow_empty_signature
  )
  if (
    is.null(header_raw) ||
      is.null(payload_raw) ||
      is.null(signature_raw)
  ) {
    return(NULL)
  }

  list(
    header = header,
    payload = payload,
    signature = signature,
    signing_input = substr(jwt, 1L, dot_pos[2] - 1L),
    header_raw = header_raw,
    payload_raw = payload_raw,
    signature_raw = signature_raw
  )
}

#' Best-effort parse of a compact JWT payload
#'
#' Used by token-binding observation helpers that need to inspect self-
#' contained JWT access tokens without reporting opaque access tokens as parse
#' errors.
#'
#' @param jwt Compact JWT candidate string.
#' @return Parsed payload list, or `NULL` when `jwt` is opaque or malformed.
#' @keywords internal
#' @noRd
parse_jwt_payload_or_null <- function(jwt) {
  parts <- jwt_compact_parts_or_null(jwt)
  if (is.null(parts)) {
    return(NULL)
  }

  if (any(parts$payload_raw == as.raw(0))) {
    return(NULL)
  }

  payload_text <- tryCatch(rawToChar(parts$payload_raw), error = function(...) {
    NULL
  })
  if (
    !is_valid_string(payload_text) ||
      !isTRUE(validUTF8(payload_text)) ||
      !isTRUE(json_text_is_object(payload_text))
  ) {
    return(NULL)
  }

  Encoding(payload_text) <- "UTF-8"

  payload <- tryCatch(
    jsonlite::fromJSON(payload_text, simplifyVector = TRUE),
    error = function(...) NULL
  )
  if (is.data.frame(payload)) {
    payload <- as.list(payload)
  }
  if (!is.list(payload)) {
    return(NULL)
  }

  payload
}

#' Internal: decode one JSON string token
#'
#' Used by `reject_duplicate_json_object_members()` so duplicate-key detection
#' compares decoded member names rather than raw escape sequences.
#'
#' @param token JSON string contents without surrounding quotes.
#' @return Decoded scalar string, or the original token on parse fallback.
#' @keywords internal
#' @noRd
jwt_decode_json_string_token <- function(token) {
  tryCatch(
    jsonlite::fromJSON(
      paste0('["', token, '"]'),
      simplifyVector = TRUE
    )[[1]],
    error = function(...) token
  )
}

#' Internal: check whether JSON text starts with an object
#'
#' Used before parsing inbound JSON payloads that must be top-level objects so
#' arrays, scalars, and other valid-but-wrong JSON values are rejected with
#' typed package errors.
#'
#' @param json_text JSON text to inspect.
#' @return `TRUE` when the first non-whitespace character is `{`; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
json_text_is_object <- function(json_text) {
  if (!is.character(json_text) || length(json_text) != 1L || is.na(json_text)) {
    return(FALSE)
  }

  trimmed <- enc2utf8(json_text)
  if (startsWith(trimmed, "\ufeff")) {
    trimmed <- substring(trimmed, 2L)
  }
  trimmed <- sub("^[[:space:]]+", "", trimmed)

  nzchar(trimmed) && identical(substr(trimmed, 1L, 1L), "{")
}

#' Internal: assert that JSON text uses an object at the top level
#'
#' Used by inbound token, UserInfo, and JWT parsers before field access occurs.
#'
#' @param json_text JSON text to inspect.
#' @param label Human-readable label used in error messages.
#' @param signal_error Function used to report validation failures.
#' @return Invisibly returns `NULL` on success. Otherwise signals via
#'   `signal_error()`.
#' @keywords internal
#' @noRd
assert_json_text_is_object <- function(
  json_text,
  label,
  signal_error = err_parse
) {
  if (!isTRUE(json_text_is_object(json_text))) {
    signal_error(paste0(label, " must be a JSON object"))
  }

  invisible(NULL)
}

#' Internal: validate one scalar string JOSE header field
#'
#' Used by `validate_jose_header_fields()` for shared `alg`, `kid`, and `typ`
#' validation before algorithm-specific JWT checks run.
#'
#' @param value Parsed field value.
#' @param field Field name for error messages.
#' @param signal_error Function used to report validation failures.
#' @param required Whether `NULL` is allowed.
#' @return Scalar string or `NULL`; raises an error via `signal_error()` when
#'   validation fails.
#' @keywords internal
#' @noRd
jwt_validate_scalar_string_field <- function(
  value,
  field,
  signal_error,
  required = FALSE
) {
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

#' Internal: validate the JOSE crit header
#'
#' Used by `validate_jose_header_fields()` to normalize supported `crit`
#' values and reject malformed extension-name vectors early.
#'
#' @param value Parsed `crit` header value.
#' @param signal_error Function used to report validation failures.
#' @return Normalized character vector or `NULL`; otherwise signals through
#'   `signal_error()`.
#' @keywords internal
#' @noRd
jwt_validate_crit_field <- function(value, signal_error) {
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

#' Reject duplicate JSON object members
#'
#' Used before JWT header and payload JSON is parsed.
#'
#' @param json_text JSON text to inspect.
#' @param label Human-readable label used in parse errors.
#' @return Invisibly returns `NULL` on success. Otherwise this function raises a
#'   parse error.
#' @keywords internal
#' @noRd
reject_duplicate_json_object_members <- function(json_text, label) {
  chars <- strsplit(enc2utf8(json_text), "", fixed = TRUE)[[1]]
  if (!length(chars)) {
    return(invisible(NULL))
  }

  index <- 1L
  container_stack <- character(0)
  seen_stack <- list()

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
        length(container_stack) > 0L &&
          identical(container_stack[[length(container_stack)]], "object") &&
          lookahead <= length(chars) &&
          identical(chars[[lookahead]], ":")
      ) {
        key <- jwt_decode_json_string_token(paste(token, collapse = ""))
        level <- length(container_stack)
        seen <- seen_stack[[level]] %||% character(0)
        if (key %in% seen) {
          err_parse(paste0(label, " contains duplicate member name: ", key))
        }
        seen_stack[[level]] <- c(seen, key)
      }
    } else if (identical(ch, "{")) {
      container_stack <- c(container_stack, "object")
      seen_stack[[length(container_stack)]] <- character(0)
    } else if (identical(ch, "[")) {
      container_stack <- c(container_stack, "array")
      seen_stack[[length(container_stack)]] <- NULL
    } else if (identical(ch, "}") || identical(ch, "]")) {
      if (length(container_stack) > 0L) {
        last_index <- length(container_stack)
        container_stack <- container_stack[-last_index]
        seen_stack <- seen_stack[-last_index]
      }
    }

    index <- index + 1L
  }

  invisible(NULL)
}

## 1.3 JOSE header validation --------------------------------------------------

#' Validate JOSE header fields
#'
#' Used by inbound JWT validation before algorithm-specific checks.
#'
#' @param header Parsed JOSE header object.
#' @param signal_error Function used to report validation failures.
#' @return Normalized header fields list.
#' @keywords internal
#' @noRd
validate_jose_header_fields <- function(header, signal_error) {
  if (!is.list(header) || is.null(names(header))) {
    signal_error("JWT header must be a JSON object")
  }
  alg <- jwt_validate_scalar_string_field(
    header$alg %||% NULL,
    "alg",
    signal_error = signal_error,
    required = TRUE
  )
  kid <- jwt_validate_scalar_string_field(
    header$kid %||% NULL,
    "kid",
    signal_error = signal_error
  )
  typ <- jwt_validate_scalar_string_field(
    header$typ %||% NULL,
    "typ",
    signal_error = signal_error
  )
  crit <- jwt_validate_crit_field(header$crit %||% NULL, signal_error)

  list(
    alg = alg,
    kid = kid,
    typ = typ,
    crit = crit
  )
}

#' Enforce the shared inbound JWT header policy
#'
#' Used by ID token and signed UserInfo JWT validation.
#'
#' @param header_fields Normalized JOSE header fields.
#' @param signal_error Function used to report validation failures.
#' @param supported_crit Supported `crit` header names.
#' @param on_typ_invalid Optional callback run before signaling an invalid
#'   `typ`.
#' @param on_crit_invalid Optional callback run before signaling invalid
#'   `crit` usage.
#' @return Invisibly returns `header_fields` on success.
#' @keywords internal
#' @noRd
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

## 1.4 Signature verification helpers ------------------------------------------

#' Extract raw JWS verification parts
#'
#' Used by the generic signature verifiers in this file.
#'
#' @param jwt Compact JWT string.
#' @return List with signing-input bytes and signature bytes.
#' @keywords internal
#' @noRd
jwt_verification_parts <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  list(
    data = charToRaw(parts$signing_input),
    sig = parts$signature_raw
  )
}

#' Verify one asymmetric JWS signature
#'
#' Used by inbound JWT validation.
#'
#' @param jwt Compact JWT string.
#' @param key Public key used for verification.
#' @param alg JOSE algorithm name.
#' @return `TRUE` when the signature verifies; otherwise `FALSE`.
#' @keywords internal
#' @noRd
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

#' Verify one HMAC JWS signature
#'
#' Used by inbound HS* JWT validation.
#'
#' @param jwt Compact JWT string.
#' @param secret Shared HMAC secret.
#' @param alg JOSE algorithm name.
#' @return `TRUE` when the computed HMAC matches the signature; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
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
