#' Parse JWT payload (unsigned validation only)
#'
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

reject_duplicate_json_object_members <- function(json_text, label) {
  chars <- strsplit(enc2utf8(json_text), "", fixed = TRUE)[[1]]
  if (!length(chars)) {
    return(invisible(NULL))
  }

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

validate_jose_header_fields <- function(header, signal_error) {
  if (!is.list(header) || is.null(names(header))) {
    signal_error("JWT header must be a JSON object")
  }

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

jwt_verification_parts <- function(jwt) {
  parts <- jwt_compact_parts(jwt)
  list(
    data = charToRaw(parts$signing_input),
    sig = parts$signature_raw
  )
}

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

is_guid_like <- function(value) {
  is.character(value) &&
    length(value) == 1L &&
    !is.na(value) &&
    grepl(
      "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
      value
    )
}

microsoft_tenant_independent_issuer <- function(issuer) {
  if (!is_valid_string(issuer)) {
    return(NULL)
  }

  parsed <- try(httr2::url_parse(issuer), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(NULL)
  }

  host <- tolower(parsed$hostname %||% "")
  path <- tolower(gsub("^/+|/+$", "", parsed$path %||% ""))

  if (!identical(host, "login.microsoftonline.com")) {
    return(NULL)
  }

  if (path %in% c("common/v2.0", "organizations/v2.0")) {
    return(path)
  }

  NULL
}

resolve_expected_id_token_issuer <- function(provider_issuer, token_payload) {
  if (is.null(microsoft_tenant_independent_issuer(provider_issuer))) {
    return(list(
      expected_issuer = provider_issuer,
      enforce_key_issuer = FALSE,
      token_tid = NULL
    ))
  }

  token_tid <- token_payload$tid %||% NULL
  if (!is_guid_like(token_tid)) {
    err_id_token(c(
      "x" = "Microsoft ID token missing or invalid tid claim",
      "i" = paste(
        "Tenant-independent Microsoft authorities require a GUID tid claim"
      )
    ))
  }

  list(
    expected_issuer = sprintf(
      "https://login.microsoftonline.com/%s/v2.0",
      token_tid
    ),
    enforce_key_issuer = TRUE,
    token_tid = token_tid
  )
}

filter_microsoft_jwks_for_token_issuer <- function(
  keys,
  provider_issuer,
  token_issuer,
  token_tid
) {
  if (
    is.null(microsoft_tenant_independent_issuer(provider_issuer)) ||
      length(keys) == 0L ||
      !is_valid_string(token_issuer) ||
      !is_guid_like(token_tid)
  ) {
    return(keys)
  }

  keep <- vapply(
    keys,
    function(key) {
      key_issuer <- key$issuer %||% NULL
      if (!is_valid_string(key_issuer)) {
        return(FALSE)
      }

      if (grepl("\\{tenantid\\}", key_issuer, ignore.case = TRUE)) {
        key_issuer <- gsub(
          "\\{tenantid\\}",
          token_tid,
          key_issuer,
          ignore.case = TRUE
        )
      }

      identical(key_issuer, token_issuer)
    },
    logical(1)
  )

  keys[keep]
}

#' Internal: validate ID token
#'
#' This function validates an ID token, by checking its signature and claims.
#'
#' @param expected_sub If provided, the `sub` claim MUST match this value.
#'   Used during refresh to ensure the new ID token is for the same user
#'   (OIDC Core section 12.2 requirement).
#' @param expected_access_token If provided and the ID token contains an
#'   `at_hash` claim, the claim is validated against this access token per
#'   OIDC Core section 3.1.3.8. When the claim is present but no access token is
#'   supplied, validation fails.
#' @param max_age If provided (numeric, seconds), validates that the ID token
#'   contains an `auth_time` claim and that the elapsed time since authentication
#'   does not exceed `max_age + leeway` (OIDC Core section 3.1.2.1 / section 2).
#'
#' @keywords internal
#' @noRd
validate_id_token <- function(
  client,
  id_token,
  expected_nonce = NULL,
  expected_sub = NULL,
  expected_access_token = NULL,
  max_age = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)
  stopifnot(is_valid_string(id_token))

  # Detect JWE (encrypted JWT): 5 dot-separated parts per RFC 7516 §3.
  # OIDC Core §3.1.3.7 step 1: "If the ID Token is encrypted, decrypt it..."
  # We do not support JWE decryption; surface a clear error rather than

  # letting a confusing alg/typ/parse failure propagate.
  n_parts <- length(strsplit(id_token, ".", fixed = TRUE)[[1]])
  if (n_parts == 5L) {
    err_id_token(c(
      "x" = "ID token is an encrypted JWT (JWE)",
      "i" = "Encrypted ID tokens (JWE) are not supported by shinyOAuth",
      "i" = "Configure the provider to return signed-only (JWS) ID tokens"
    ))
  }

  prov <- client@provider
  issuer <- prov@issuer
  allowed_algs <- toupper(
    prov@allowed_algs %||%
      c(
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA"
      )
  )
  leeway <- prov@leeway %||% getOption("shinyOAuth.leeway", 30)
  jwks_cache <- prov@jwks_cache
  pins <- prov@jwks_pins %||% character()
  pin_mode <- prov@jwks_pin_mode %||% "any"
  client_id <- client@client_id
  client_secret <- client@client_secret
  skip_signature <- isTRUE(allow_skip_signature())

  # Parse header to inspect alg/kid; map all parse failures to ID token errors
  header <- tryCatch(
    parse_jwt_header(id_token),
    error = function(e) {
      err_id_token(c(
        "Invalid ID token: cannot parse header",
        "i" = conditionMessage(e)
      ))
    }
  )
  header_fields <- validate_jose_header_fields(header, err_id_token)

  # Defense-in-depth: if a typ header is present, require it to be exactly
  # "JWT" per RFC 7519. Many providers omit typ; that's fine. Unknown types
  # (e.g., JWE or vendor-specific values) are rejected to avoid accepting
  # unintended container types.
  typ <- header_fields$typ
  if (!is.null(typ)) {
    if (
      !(is.character(typ) &&
        length(typ) == 1L &&
        identical(toupper(typ), "JWT"))
    ) {
      err_id_token(paste0(
        "JWT typ header invalid: expected 'JWT' when present, got ",
        as.character(typ)
      ))
    }
  }
  # RFC 7515 s4.1.11: reject tokens that carry critical header parameters we
  # do not support.
  # Allowlist of crit values this implementation understands (empty today).
  supported_crit <- character()
  crit <- header_fields$crit
  if (!is.null(crit)) {
    unsupported <- setdiff(crit, supported_crit)
    if (length(unsupported) > 0L) {
      err_id_token(paste0(
        "JWT contains unsupported critical header parameter(s): ",
        paste(unsupported, collapse = ", ")
      ))
    }
  }
  alg <- toupper(header_fields$alg)
  kid <- header_fields$kid
  if (!isTRUE(skip_signature) && !(alg %in% allowed_algs)) {
    err_id_token(paste0("JWT alg not allowed by provider: ", header_fields$alg))
  }

  parsed_payload <- tryCatch(
    parse_jwt_payload(id_token),
    error = function(e) {
      err_id_token(c(
        "Invalid ID token: cannot parse payload",
        "i" = conditionMessage(e)
      ))
    }
  )
  issuer_expectation <- resolve_expected_id_token_issuer(issuer, parsed_payload)

  # Signature verification
  payload <- parsed_payload
  verified_eddsa_curve <- NULL
  if (!isTRUE(skip_signature)) {
    # All asymmetric algs are verified using the provider JWKS (RSA/EC/OKP)
    if (
      alg %in%
        c(
          "RS256",
          "RS384",
          "RS512",
          "ES256",
          "ES384",
          "ES512",
          "EDDSA"
        )
    ) {
      jwks <- fetch_jwks(
        issuer,
        jwks_cache,
        pins = pins,
        pin_mode = pin_mode,
        provider = prov
      )
      verified <- FALSE
      # Determine candidate keys with safer kid handling
      if (!is.null(kid)) {
        # If header has kid, try only matching keys. If none match, refresh JWKS once and try again.
        kid_keys <- select_candidate_jwks(
          jwks,
          header_alg = alg,
          kid = kid,
          pins = pins
        )
        if (length(kid_keys) == 0L) {
          did_force_refresh <- FALSE
          if (
            isTRUE(jwks_force_refresh_allowed(
              issuer,
              jwks_cache,
              pins = pins,
              pin_mode = pin_mode,
              min_interval = 30,
              issuer_match = provider_issuer_match(prov),
              jwks_host_issuer_match = isTRUE(try(
                prov@jwks_host_issuer_match,
                silent = TRUE
              )),
              jwks_host_allow_only = {
                ao <- try(prov@jwks_host_allow_only, silent = TRUE)
                if (inherits(ao, "try-error")) NA_character_ else ao
              }
            ))
          ) {
            did_force_refresh <- TRUE
            jwks <- fetch_jwks(
              issuer,
              jwks_cache,
              force_refresh = TRUE,
              pins = pins,
              pin_mode = pin_mode,
              provider = prov
            )
            kid_keys <- select_candidate_jwks(
              jwks,
              header_alg = alg,
              kid = kid,
              pins = pins
            )
          }
        }
        if (length(kid_keys) == 0L) {
          if (isTRUE(did_force_refresh)) {
            err_id_token("No JWKS key matches kid")
          } else {
            err_id_token("No JWKS key matches kid (JWKS refresh rate-limited)")
          }
        }
        keys <- kid_keys
      } else {
        # No kid: use usual candidate filtering (use='sig', alg preference)
        keys <- select_candidate_jwks(
          jwks,
          header_alg = alg,
          kid = NULL,
          pins = pins
        )
      }

      keys <- filter_jwks_for_alg(keys, alg)
      if (length(keys) == 0L) {
        err_id_token("No compatible JWKS keys for alg")
      }
      keys <- filter_microsoft_jwks_for_token_issuer(
        keys,
        provider_issuer = issuer,
        token_issuer = parsed_payload$iss %||% NULL,
        token_tid = issuer_expectation$token_tid
      )
      if (length(keys) == 0L && isTRUE(issuer_expectation$enforce_key_issuer)) {
        err_id_token("No Microsoft JWKS key matches token issuer scope")
      }

      # Attempt verification only with the selected keys (no fallback to all when kid is present)
      for (jk in keys) {
        pub <- try(jwk_to_pubkey(jk), silent = TRUE)
        if (inherits(pub, "try-error")) {
          next
        }
        if (isTRUE(verify_jws_signature_no_time(id_token, pub, alg))) {
          verified <- TRUE
          if (identical(alg, "EDDSA")) {
            verified_eddsa_curve <- resolve_verified_eddsa_curve(
              jwk = jk,
              key = pub
            )
          }
          break
        }
      }
      if (!isTRUE(verified)) err_id_token("ID token signature invalid")
    } else if (alg %in% c("HS256", "HS384", "HS512")) {
      # Gate HMAC verification behind an explicit, opt-in option
      allow_hs <- isTRUE(getOption("shinyOAuth.allow_hs", FALSE))

      if (!allow_hs) {
        err_id_token(c(
          "x" = "HS* requires `options(shinyOAuth.allow_hs = TRUE)`",
          "i" = paste0(
            "Enable only when your client_secret is strictly server-side, ",
            "is rotated regularly, and you accept the trade-offs of symmetric tokens"
          )
        ))
      }

      if (!is_valid_string(client_secret)) {
        err_input("HS* validation requires client_secret")
      }

      min_secret_bytes <- min_hmac_key_bytes(alg)
      if (nchar(client_secret, type = "bytes") < min_secret_bytes) {
        err_input(paste0(
          alg,
          " requires client_secret >= ",
          min_secret_bytes,
          " bytes"
        ))
      }

      if (
        !isTRUE(verify_hmac_jws_signature_no_time(
          id_token,
          client_secret,
          alg
        ))
      ) {
        err_id_token("ID token HMAC invalid")
      }
    } else {
      err_id_token(paste0("Unsupported JWT alg: ", header$alg))
    }
  }

  # Claims checks
  # OIDC Core §3.1.3.7 step 2: iss MUST exactly match the Issuer Identifier.
  # For Microsoft tenant-independent metadata, the effective issuer is derived
  # from the token's GUID tid claim.
  if (!is_valid_string(payload$iss)) {
    err_id_token("Issuer mismatch/invalid")
  }
  if (!identical(payload$iss, issuer_expectation$expected_issuer)) {
    err_id_token("Issuer mismatch/invalid")
  }
  aud <- payload$aud
  # OIDC: aud MAY be a string or an array of strings. Accept length >= 1.
  if (
    !(is.character(aud) &&
      length(aud) >= 1 &&
      !anyNA(aud) &&
      all(nzchar(aud)))
  ) {
    err_id_token("Audience invalid")
  }
  if (!(client_id %in% aud)) {
    err_id_token("Audience does not include client_id")
  }
  if (!is_valid_string(payload$sub)) {
    err_id_token("ID token missing sub claim")
  }
  # OIDC Core 12.2: During refresh, sub MUST match the original ID token's sub
  if (is_valid_string(expected_sub) && !identical(payload$sub, expected_sub)) {
    err_id_token("ID token sub claim does not match original (OIDC 12.2)")
  }
  if (is.null(payload$exp)) {
    err_id_token("ID token missing exp claim")
  }
  # Validate temporal claims are single, finite numerics before arithmetic
  is_single_finite_number <- function(x) {
    is.numeric(x) && length(x) == 1 && is.finite(x) && !is.na(x)
  }
  if (!is_single_finite_number(payload$exp)) {
    err_id_token("exp claim must be a single finite number")
  }
  exp_val <- as.numeric(payload$exp)

  # Use integer seconds to minimize flakiness vs. boundary tests
  now <- floor(as.numeric(Sys.time()))
  lwe <- as.numeric(leeway %||% 0)
  if (!is.finite(lwe) || is.na(lwe) || length(lwe) != 1) {
    lwe <- 0
  }
  if (exp_val < (now - lwe)) {
    err_id_token("ID token expired")
  }
  # OIDC Core requires iat to be present on ID Tokens
  if (is.null(payload$iat)) {
    err_id_token("ID token missing iat claim")
  }
  if (!is_single_finite_number(payload$iat)) {
    err_id_token("iat claim must be a single finite number when present")
  }
  iat_val <- as.numeric(payload$iat)
  if (iat_val > (now + lwe)) {
    err_id_token("ID token issued in the future")
  }
  # OIDC Core §3.1.3.7 rule 9: reject tokens with unreasonably long lifetimes.
  # A misconfigured or malicious provider could issue an ID token valid for years.
  max_lifetime <- getOption("shinyOAuth.max_id_token_lifetime", 86400)
  if (
    is.numeric(max_lifetime) &&
      length(max_lifetime) == 1L &&
      is.finite(max_lifetime)
  ) {
    if (max_lifetime <= 0) {
      err_config(c(
        "x" = "shinyOAuth.max_id_token_lifetime must be a positive number",
        "i" = paste0("Got: ", max_lifetime)
      ))
    }
    if ((exp_val - iat_val) > max_lifetime) {
      err_id_token(c(
        "x" = "ID token lifetime exceeds max_id_token_lifetime",
        "i" = paste0(
          "exp=",
          exp_val,
          ", iat=",
          iat_val,
          ", lifetime=",
          exp_val - iat_val,
          "s",
          ", max_id_token_lifetime=",
          max_lifetime,
          "s"
        )
      ))
    }
  }
  if (!is.null(payload$nbf)) {
    if (!is_single_finite_number(payload$nbf)) {
      err_id_token("nbf claim must be a single finite number when present")
    }
    nbf_val <- as.numeric(payload$nbf)
    # Token is not yet valid when the not-before time is beyond allowed clock skew.
    # Use a > comparison for consistency with exp/iat boundary handling.
    if (nbf_val > (now + lwe)) {
      err_id_token("ID token not yet valid (nbf)")
    }
  }
  if (is_valid_string(expected_nonce)) {
    if (is.null(payload$nonce)) {
      err_id_token("ID token missing nonce claim")
    }
    if (!identical(payload$nonce, expected_nonce)) {
      err_id_token("ID token nonce mismatch")
    }
  }
  # Authorized party (azp) handling per OIDC Core §2: if aud has multiple
  # entries, azp MUST be present and equal to the client_id. If azp is present
  # in any case, it MUST equal client_id.
  if (!is.null(payload$azp)) {
    if (!identical(payload$azp, client_id)) {
      err_id_token("azp claim does not match client_id")
    }
  } else if (length(aud) > 1) {
    err_id_token("Multiple audiences but azp claim missing")
  }

  # auth_time validation per OIDC Core §3.1.2.1 / §2:
  # When max_age was requested, auth_time MUST be present. Validate
  # that now - auth_time <= max_age + leeway.
  if (!is.null(max_age)) {
    max_age_val <- suppressWarnings(as.numeric(max_age))
    if (
      !is.numeric(max_age_val) ||
        length(max_age_val) != 1L ||
        !is.finite(max_age_val) ||
        max_age_val < 0
    ) {
      err_id_token("max_age must be a non-negative finite number")
    }
    if (is.null(payload$auth_time)) {
      err_id_token(
        "ID token missing auth_time claim (required when max_age is requested, OIDC Core 3.1.2.1)"
      )
    }
    if (!is_single_finite_number(payload$auth_time)) {
      err_id_token("auth_time claim must be a single finite number")
    }
    auth_time_val <- as.numeric(payload$auth_time)
    if (auth_time_val > (now + lwe)) {
      err_id_token(c(
        "x" = "auth_time is in the future",
        "i" = paste0(
          "auth_time=",
          auth_time_val,
          ", now=",
          now,
          ", leeway=",
          lwe,
          "s"
        )
      ))
    }
    elapsed <- now - auth_time_val
    if (elapsed > (max_age_val + lwe)) {
      err_id_token(c(
        "x" = "Authentication too old (auth_time exceeded max_age)",
        "i" = paste0(
          "auth_time=",
          auth_time_val,
          ", now=",
          now,
          ", elapsed=",
          elapsed,
          "s, max_age=",
          max_age_val,
          "s, leeway=",
          lwe,
          "s"
        )
      ))
    }
  }

  # at_hash (Access Token hash) validation per OIDC Core §3.1.3.8 / §3.2.2.9:
  # When the ID token contains an at_hash claim, verify the access token
  # binding. This is a defense-in-depth measure against token substitution.
  # When id_token_at_hash_required is TRUE, the claim MUST be present.
  at_hash_required <- isTRUE(prov@id_token_at_hash_required)
  if (at_hash_required && is.null(payload$at_hash)) {
    err_id_token(
      "ID token missing required at_hash claim (id_token_at_hash_required = TRUE)"
    )
  }
  if (!is.null(payload$at_hash)) {
    if (!is_valid_string(expected_access_token)) {
      err_id_token(
        "ID token contains at_hash claim but no access token was provided for validation"
      )
    }
    if (identical(alg, "EDDSA") && isTRUE(skip_signature)) {
      err_id_token(c(
        "x" = paste(
          "Cannot validate EdDSA at_hash when signature verification is skipped"
        ),
        "i" = "Exact EdDSA at_hash validation requires a verified key or JWK to resolve the concrete curve"
      ))
    }
    computed <- compute_at_hash(
      expected_access_token,
      alg,
      eddsa_curve = verified_eddsa_curve
    )
    if (!constant_time_compare(computed, payload$at_hash)) {
      err_id_token(
        "at_hash claim does not match the access token (OIDC Core 3.1.3.8)"
      )
    }
  }

  attr(payload, "signature_verified") <- !isTRUE(skip_signature)

  invisible(payload)
}

canonicalize_eddsa_curve <- function(eddsa_curve) {
  if (
    !is.character(eddsa_curve) ||
      length(eddsa_curve) != 1L ||
      is.na(eddsa_curve) ||
      !nzchar(eddsa_curve)
  ) {
    return(NULL)
  }

  curve <- toupper(eddsa_curve)
  if (identical(curve, "ED25519")) {
    return("Ed25519")
  }
  if (identical(curve, "ED448")) {
    return("Ed448")
  }

  NULL
}

resolve_verified_eddsa_curve <- function(jwk = NULL, key = NULL) {
  # Prefer the JWK curve because it is explicit and survives key conversion.
  if (is.list(jwk)) {
    curve <- canonicalize_eddsa_curve(jwk$crv %||% NULL)
    if (!is.null(curve)) {
      return(curve)
    }
  }

  if (!is.null(key)) {
    if (inherits(key, "ed25519")) {
      return("Ed25519")
    }
    if (inherits(key, "ed448")) {
      return("Ed448")
    }
  }

  NULL
}

#' Compute at_hash value per OIDC Core section 3.1.3.8
#'
#' Takes the left-most half of the hash of the access token ASCII octets
#' using the hash algorithm from the JWT alg header, then base64url-encodes it.
#' For `EdDSA`, the generic JWT alg is not sufficient; callers must provide the
#' concrete verified curve so the digest policy is explicit.
#'
#' @param access_token The access token string.
#' @param alg The JWT algorithm (e.g., "RS256", "ES384", "RS512").
#' @param eddsa_curve Optional concrete EdDSA curve (`"Ed25519"` or `"Ed448"`).
#' @return A base64url-encoded string representing the at_hash.
#' @keywords internal
#' @noRd
compute_at_hash <- function(access_token, alg, eddsa_curve = NULL) {
  stopifnot(is_valid_string(access_token), is_valid_string(alg))
  alg <- toupper(alg)

  # Map JWT alg to hash function per RFC 7518:
  # *256 -> SHA-256, *384 -> SHA-384, *512 -> SHA-512
  hash_fn <- if (grepl("256", alg, fixed = TRUE)) {
    openssl::sha256
  } else if (grepl("384", alg, fixed = TRUE)) {
    openssl::sha384
  } else if (grepl("512", alg, fixed = TRUE)) {
    openssl::sha512
  } else if (identical(alg, "EDDSA")) {
    curve <- canonicalize_eddsa_curve(eddsa_curve)
    if (is.null(curve)) {
      err_id_token(c(
        "x" = "Cannot validate EdDSA at_hash without the resolved verified curve",
        "i" = "Expected Ed25519 or Ed448 from the key or JWK that verified the token"
      ))
    }

    if (identical(curve, "Ed25519")) {
      openssl::sha512
    } else {
      err_id_token(c(
        "x" = "Ed448 at_hash validation is not yet supported",
        "i" = "This runtime does not expose the SHAKE256 helper needed for exact Ed448 mapping"
      ))
    }
  } else {
    err_id_token(paste0(
      "Cannot determine hash algorithm for at_hash from alg: ",
      alg
    ))
  }
  full_hash <- hash_fn(charToRaw(access_token))
  # Take the left-most half of the hash octets
  hash_bytes <- as.raw(full_hash)
  left_half <- hash_bytes[seq_len(length(hash_bytes) %/% 2L)]
  base64url_encode(left_half)
}

#' Build and sign OAuth client assertion (RFC 7523)
#'
#' Constructs a JWT with claims suitable for `client_secret_jwt` or
#' `private_key_jwt` token endpoint authentication and returns the compact
#' serialization. The JWT uses the client's configured credentials to sign
#' the assertion. Header will include alg and optional kid (when provided).
#'
#' Claims:
#'  - iss: client_id
#'  - sub: client_id
#'  - aud: token endpoint URL (passed as `aud`)
#'  - iat: current epoch seconds
#'  - exp: iat + ttl (default 120s; override with options(shinyOAuth.client_assertion_ttl))
#'  - jti: random unique identifier
#'
#' @keywords internal
#' @noRd
build_client_assertion <- function(client, aud) {
  S7::check_is_S7(client, class = OAuthClient)
  stopifnot(is_valid_string(aud))

  style <- normalize_token_auth_style(
    client@provider@token_auth_style %||% "header"
  )
  alg_cfg <- client@client_assertion_alg %||% NA_character_
  # Defense-in-depth: ensure scalar before indexing (validator should already
  # enforce this, but runtime callers may bypass validation).
  if (!is.character(alg_cfg) || length(alg_cfg) != 1L) {
    alg_cfg <- NA_character_ # nolint
  }
  alg_chr <- as.character(alg_cfg)
  alg <- canonicalize_jws_alg(alg_chr)
  # Resolve default algorithm with key-aware logic for private_key_jwt.
  # Previous behavior always fell back to RS256 which breaks EC/OKP keys.
  if (!nzchar(alg)) {
    if (identical(style, "client_secret_jwt")) {
      alg <- "HS256"
    } else if (identical(style, "private_key_jwt")) {
      # Pick a sensible default based on the private key type/curve.
      key0 <- normalize_private_key_input(client@client_private_key)
      alg <- choose_default_alg_for_private_key(key0)
    }
  }
  # TTL (seconds) for client assertion; default 2 minutes
  ttl <- suppressWarnings(as.integer(getOption(
    "shinyOAuth.client_assertion_ttl",
    120L
  )))
  if (!is.finite(ttl) || is.na(ttl)) {
    ttl <- 120L
  } else if (ttl < 60L) {
    ttl <- 60L
  } else if (ttl > 300L) {
    rlang::warn(
      c(
        "!" = "shinyOAuth.client_assertion_ttl above 300 seconds is not allowed; clamping to 300 seconds",
        "i" = paste0("Configured value: ", ttl)
      ),
      .frequency = "once",
      .frequency_id = "client-assertion-ttl-max"
    )
    ttl <- 300L
  }
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@client_id,
    sub = client@client_id,
    aud = aud,
    iat = now,
    exp = now + ttl,
    jti = random_urlsafe(32)
  )

  # Header base; jose helpers set alg automatically for HS* (via size) but we
  # include explicit alg to be clear. Include kid if configured for private keys.
  header <- list(
    typ = "JWT",
    alg = alg
  )
  if (identical(style, "private_key_jwt")) {
    kid <- client@client_private_key_kid %||% NA_character_
    if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
      header$kid <- kid
    }
  }

  if (identical(style, "client_secret_jwt")) {
    min_secret_bytes <- min_hmac_key_bytes(alg)
    size <- min_secret_bytes * 8L
    secret <- client@client_secret %||%
      err_config("client_secret missing for client_secret_jwt")
    if (nchar(secret, type = "bytes") < min_secret_bytes) {
      err_config(
        paste0(
          "client_secret_jwt with client_assertion_alg '",
          alg,
          "' requires client_secret >= ",
          min_secret_bytes,
          " bytes"
        )
      )
    }
    # Build a proper jwt_claim from named list via do.call
    clm <- do.call(jose::jwt_claim, claims)
    # jose will set alg based on size, but we also pass header to include typ
    jwt <- jose::jwt_encode_hmac(
      clm,
      secret = secret,
      header = header,
      size = size
    )
    return(jwt)
  }

  if (identical(style, "private_key_jwt")) {
    key <- normalize_private_key_input(client@client_private_key)
    clm <- do.call(jose::jwt_claim, claims)
    # Hard-fail impossible alg/key pairs before signing. jose::jwt_encode_sig()
    # can otherwise emit mismatched JOSE alg headers instead of rejecting them.
    if (!private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
      err_config(
        c(
          "x" = paste0(
            "client_assertion_alg '",
            alg,
            "' is incompatible with the provided private key"
          )
        ),
        context = list(
          phase = "build_client_assertion",
          alg = alg
        )
      )
    }
    jwt <- try(
      jose::jwt_encode_sig(clm, key = key, header = header),
      silent = TRUE
    )
    if (inherits(jwt, "try-error")) {
      err_config(
        c(
          "x" = "Failed to sign client assertion",
          "i" = paste0(
            "Tried alg '",
            alg,
            "' with the configured private key"
          )
        ),
        context = list(
          phase = "build_client_assertion",
          alg = alg
        )
      )
    }
    return(jwt)
  }

  err_config(
    c("x" = "build_client_assertion called for non-JWT auth style"),
    context = list(style = as.character(style))
  )
}

#' Resolve the audience (`aud`) value for a JWT client assertion.
#'
#' Uses an explicit client override when present, otherwise uses the exact URL
#' on the httr2 request (so any URL normalization/modification stays consistent
#' with the audience claim). Falls back to the provider token_url for non-httr2
#' request doubles used in tests.
#'
#' @keywords internal
#' @noRd
resolve_client_assertion_audience <- function(client, req) {
  S7::check_is_S7(client, class = OAuthClient)

  override <- client@client_assertion_audience %||% NA_character_
  # Defense-in-depth: ensure scalar before indexing.
  if (!is.character(override) || length(override) != 1L) {
    override <- NA_character_ # nolint
  }
  override_chr <- as.character(override)
  if (!is.na(override_chr) && nzchar(override_chr)) {
    return(override_chr)
  }

  if (inherits(req, "httr2_request")) {
    url0 <- req$url %||% NA_character_
    url_chr <- as.character(url0[[1]])
    if (!is.na(url_chr) && nzchar(url_chr)) {
      return(url_chr)
    }
  }

  client@provider@token_url
}

#' Resolve the signing algorithm for a signed authorization request.
#'
#' @keywords internal
#' @noRd
resolve_authorization_request_signing_alg <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  alg_cfg <- client@authorization_request_signing_alg %||% NA_character_
  if (!is.character(alg_cfg) || length(alg_cfg) != 1L) {
    alg_cfg <- NA_character_
  }
  alg <- canonicalize_jws_alg(alg_cfg)

  allowed_hmac <- c("HS256", "HS384", "HS512")
  allowed_asym <- c(
    "RS256",
    "ES256",
    "ES384",
    "ES512"
  )

  if (!nzchar(alg)) {
    if (!is.null(client@client_private_key)) {
      key0 <- normalize_private_key_input(client@client_private_key)
      return(choose_default_alg_for_private_key(key0))
    }
    if (!is_valid_string(client@client_secret)) {
      err_config(
        "authorization_request_mode = 'request' requires client_private_key or client_secret"
      )
    }
    if (nchar(client@client_secret, type = "bytes") < 32) {
      err_config(
        paste(
          "authorization_request_mode = 'request' requires client_secret >= 32 bytes",
          "when no client_private_key is configured"
        )
      )
    }
    return("HS256")
  }

  if (identical(toupper(alg), "NONE")) {
    err_config("authorization_request_signing_alg = 'none' is not supported")
  }

  if (alg %in% allowed_hmac) {
    if (!is_valid_string(client@client_secret)) {
      err_config("HS* authorization_request_signing_alg requires client_secret")
    }
    if (nchar(client@client_secret, type = "bytes") < 32) {
      err_config(
        "HS* authorization_request_signing_alg requires client_secret >= 32 bytes"
      )
    }
    return(alg)
  }

  if (alg %in% allowed_asym) {
    if (is.null(client@client_private_key)) {
      err_config(
        "asymmetric authorization_request_signing_alg requires client_private_key"
      )
    }
    return(alg)
  }

  err_config(paste0(
    "Unsupported authorization_request_signing_alg: ",
    as.character(alg)
  ))
}

#' Resolve the audience (`aud`) value for a signed authorization request.
#'
#' @keywords internal
#' @noRd
resolve_authorization_request_audience <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  override <- client@authorization_request_audience %||% NA_character_
  if (!is.character(override) || length(override) != 1L) {
    override <- NA_character_
  }
  override_chr <- as.character(override)
  if (!is.na(override_chr) && nzchar(override_chr)) {
    return(override_chr)
  }

  provider_issuer <- client@provider@issuer %||% NA_character_
  if (is_valid_string(provider_issuer)) {
    return(provider_issuer)
  }

  auth_url <- client@provider@auth_url %||% NA_character_
  if (is_valid_string(auth_url)) {
    return(auth_url)
  }

  err_config(
    "Could not resolve an audience for the signed authorization request"
  )
}

#' Canonicalize a JWS alg name for JOSE headers.
#'
#' @keywords internal
#' @noRd
canonicalize_jws_alg <- function(alg) {
  if (!is.character(alg) || length(alg) != 1L) {
    return("")
  }

  alg_chr <- trimws(as.character(alg)[[1]])
  if (is.na(alg_chr) || !nzchar(alg_chr)) {
    return("")
  }

  alg_upper <- toupper(alg_chr)
  if (identical(alg_upper, "EDDSA")) {
    return("EdDSA")
  }

  alg_upper
}

#' Return the minimum HMAC key length in bytes for a JWS alg.
#'
#' @keywords internal
#' @noRd
min_hmac_key_bytes <- function(alg) {
  alg <- canonicalize_jws_alg(alg)

  switch(
    alg,
    HS256 = 32L,
    HS384 = 48L,
    HS512 = 64L,
    err_config(paste0("Unsupported HMAC alg for key length check: ", alg))
  )
}

#' Check whether a private key can sign a JWT with a given alg.
#'
#' @keywords internal
#' @noRd
private_key_can_sign_jws_alg <- function(key, alg, typ = "JWT") {
  alg <- canonicalize_jws_alg(alg)

  if (inherits(key, "rsa")) {
    return(identical(alg, "RS256"))
  }

  if (inherits(key, "ecdsa")) {
    jwk <- try(
      jsonlite::fromJSON(jose::write_jwk(key), simplifyVector = TRUE),
      silent = TRUE
    )
    if (!inherits(jwk, "try-error") && is.list(jwk)) {
      crv <- jwk$crv %||% NA_character_
      if (identical(crv, "P-256")) {
        return(identical(alg, "ES256"))
      }
      if (identical(crv, "P-384")) {
        return(identical(alg, "ES384"))
      }
      if (identical(crv, "P-521")) {
        return(identical(alg, "ES512"))
      }
    }

    return(alg %in% c("ES256", "ES384", "ES512"))
  }

  if (inherits(key, "ed25519") || inherits(key, "ed448")) {
    return(FALSE)
  }

  clm <- jose::jwt_claim(jti = "compatibility-check", iat = 1L)
  hdr <- list(typ = typ, alg = alg)
  sig_try <- try(
    jose::jwt_encode_sig(clm, key = key, header = hdr),
    silent = TRUE
  )

  !inherits(sig_try, "try-error")
}

#' Encode a compact HMAC JWS while preserving a custom JOSE header.
#'
#' @keywords internal
#' @noRd
encode_hmac_jwt_with_header <- function(
  claims,
  secret,
  header,
  size,
  alg = NULL
) {
  if (!is.list(claims) || !length(claims)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty claims list")
  }
  if (!is_valid_string(secret)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty secret")
  }
  if (!is.list(header) || !length(header)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty header list")
  }

  alg <- canonicalize_jws_alg(alg)
  if (!nzchar(alg)) {
    alg <- switch(
      as.character(size),
      `256` = "HS256",
      `384` = "HS384",
      `512` = "HS512",
      err_config(paste0(
        "Unsupported HMAC signing size for encode_hmac_jwt_with_header: ",
        as.character(size)
      ))
    )
  }

  min_secret_bytes <- min_hmac_key_bytes(alg)
  if (nchar(secret, type = "bytes") < min_secret_bytes) {
    err_config(paste0(
      alg,
      " requires client_secret >= ",
      min_secret_bytes,
      " bytes"
    ))
  }

  header_json <- jsonlite::toJSON(
    header,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- jsonlite::toJSON(
    claims,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )

  encoded_header <- base64url_encode(charToRaw(enc2utf8(header_json)))
  encoded_payload <- base64url_encode(charToRaw(enc2utf8(payload_json)))
  signing_input <- paste0(encoded_header, ".", encoded_payload)
  key_raw <- charToRaw(enc2utf8(secret))

  signature_raw <- switch(
    as.character(size),
    `256` = openssl::sha256(charToRaw(signing_input), key = key_raw),
    `384` = openssl::sha384(charToRaw(signing_input), key = key_raw),
    `512` = openssl::sha512(charToRaw(signing_input), key = key_raw),
    err_config(paste0(
      "Unsupported HMAC signing size for encode_hmac_jwt_with_header: ",
      as.character(size)
    ))
  )

  paste0(signing_input, ".", base64url_encode(signature_raw))
}

#' Build and sign a JWT-secured authorization request (RFC 9101).
#'
#' @keywords internal
#' @noRd
build_authorization_request_object <- function(client, params) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(params) || !length(params)) {
    err_config(
      "build_authorization_request_object requires a non-empty params list"
    )
  }

  param_names <- tolower(trimws(names(params) %||% character(0)))
  if (any(param_names %in% c("request", "request_uri"))) {
    err_config(
      "Authorization request parameters must not already include request or request_uri"
    )
  }

  alg <- resolve_authorization_request_signing_alg(client)
  aud <- resolve_authorization_request_audience(client)
  now <- floor(as.numeric(Sys.time()))
  ttl <- 120L

  claims_param <- params$claims %||% NULL
  if (
    is.character(claims_param) &&
      length(claims_param) == 1L &&
      nzchar(claims_param)
  ) {
    parsed_claims <- tryCatch(
      jsonlite::fromJSON(claims_param, simplifyVector = FALSE),
      error = function(...) NULL
    )
    if (is.list(parsed_claims)) {
      params$claims <- parsed_claims
    }
  }

  params[intersect(
    names(params) %||% character(0),
    c("iss", "aud", "iat", "exp", "jti")
  )] <- NULL

  claims <- compact_list(c(
    params,
    list(
      iss = client@client_id,
      aud = aud,
      iat = now,
      exp = now + ttl,
      jti = random_urlsafe(32)
    )
  ))

  header <- list(
    typ = "oauth-authz-req+jwt",
    alg = alg
  )

  if (!(alg %in% c("HS256", "HS384", "HS512"))) {
    kid <- client@client_private_key_kid %||% NA_character_
    if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
      header$kid <- kid
    }
  }

  clm <- do.call(jose::jwt_claim, claims)

  if (alg %in% c("HS256", "HS384", "HS512")) {
    size <- min_hmac_key_bytes(alg) * 8L

    return(encode_hmac_jwt_with_header(
      claims = claims,
      secret = client@client_secret,
      header = header,
      size = size,
      alg = alg
    ))
  }

  key <- normalize_private_key_input(client@client_private_key)
  if (!private_key_can_sign_jws_alg(key, alg, typ = "oauth-authz-req+jwt")) {
    err_config(
      c(
        "x" = paste0(
          "authorization_request_signing_alg '",
          alg,
          "' is incompatible with the provided private key"
        )
      ),
      context = list(alg = alg)
    )
  }
  jwt <- try(
    jose::jwt_encode_sig(clm, key = key, header = header),
    silent = TRUE
  )
  if (inherits(jwt, "try-error")) {
    err_config(
      c(
        "x" = "Failed to sign authorization request object",
        "i" = paste0("Tried alg '", alg, "' with the configured private key")
      ),
      context = list(alg = alg)
    )
  }

  jwt
}

#' Normalize a client private key input to an openssl::key
#'
#' Accepts either an openssl::key-like object or a PEM string. Password-protected
#' keys are not supported in this helper; supply an openssl::key unlocked in R
#' if needed.
#' @keywords internal
#' @noRd
normalize_private_key_input <- function(key, arg_name = "client_private_key") {
  if (inherits(key, "key") || inherits(key, "rsa") || inherits(key, "ecdsa")) {
    return(key)
  }
  if (is.character(key) && length(key) >= 1L) {
    pem <- paste(key, collapse = "\n")
    k <- try(openssl::read_key(pem), silent = TRUE)
    if (inherits(k, "try-error")) {
      err_config(paste0("Failed to parse ", arg_name, " PEM"))
    }
    return(k)
  }
  err_config(paste0(arg_name, " must be an openssl::key or PEM string"))
}

#' Choose a default JWT alg compatible with a given private key
#'
#' For RSA keys, prefer RS256. For EC keys, try ES256/384/512 to match P-256/384/521.
#' Other key types are not currently supported for outbound JWT signing and
#' fall back to a configuration error.
#' @keywords internal
#' @noRd
choose_default_alg_for_private_key <- function(key) {
  if (inherits(key, "rsa")) {
    return("RS256")
  }

  if (inherits(key, "ecdsa")) {
    for (alg in c("ES256", "ES384", "ES512")) {
      if (private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
        return(alg)
      }
    }
  }

  # Unknown key classes still go through the same compatibility guard so we do
  # not infer defaults from jose::jwt_encode_sig() accepting impossible pairs.
  for (alg in c("RS256", "ES256", "ES384", "ES512")) {
    if (private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
      return(canonicalize_jws_alg(alg))
    }
  }
  err_config(
    c(
      "x" = "Could not determine a compatible default outbound JWT signing algorithm for the provided private key",
      "i" = paste(
        "shinyOAuth currently supports RSA and ECDSA private keys for",
        "outbound client assertions, request objects, and DPoP proofs"
      ),
      "i" = "EdDSA remains supported for inbound ID token verification"
    )
  )
}
