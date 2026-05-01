# This file contains the inbound JWT helpers that apply ID token validation
# rules on top of the generic JWT parsing and signature helpers.
# Use them when a returned ID token must be matched to the expected issuer,
# audience, nonce, access token, or provider-specific issuer rules such as
# Microsoft tenant-specific validation.

# 1 Inbound ID token helpers ----------------------------------------------

## 1.1 Main ID token validation -------------------------------------------

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
  # "JWT" per RFC 7519. Many providers omit typ; that is still allowed.
  # RFC 7515 s4.1.11: also reject critical header parameters we do not support.
  enforce_inbound_jwt_header_policy(header_fields, err_id_token)

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
  # Used only inside validate_id_token() to keep numeric claim checks concise.
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

## 1.2 EdDSA and at_hash helpers ------------------------------------------

# Normalize an EdDSA curve label into the spelling used by this file.
# Used by EdDSA-specific at_hash handling. Input: curve name. Output:
# normalized curve or NULL.
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

# Resolve the verified EdDSA curve from the JWK or openssl key that verified
# the token.
# Used by EdDSA at_hash validation. Input: optional JWK and key. Output:
# normalized curve or NULL.
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
