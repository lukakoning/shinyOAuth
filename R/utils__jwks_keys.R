# This file contains the helpers that select, inspect, decode, and validate
# JWK and JWKS key objects.
# Use them after a JWKS is fetched, when signature verification needs
# compatible candidate keys, usable public keys, and structural checks on the
# returned key material.

# 1 JWKS verification helpers ---------------------------------------------

## 1.1 Select candidate keys ----------------------------------------------

#' Internal: Select candidate JWKs for signature verification
#'
#' Filters keys that declare use != "sig" while retaining keys that omit `use`.
#' Optionally restricts to a specific `kid` and orders candidates to prefer
#' keys whose JWK `alg` matches the JWT header algorithm when provided.
#'
#' @param jwks_or_keys A JWKS list (with $keys) or a normalized list of JWKs
#' @param header_alg Optional JWT header alg (character)
#' @param kid Optional key id to restrict candidates to
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'   to restrict candidate keys to. Only keys with matching thumbprints are
#'   returned.
#'
#' @return A list of JWKs, filtered and ordered by preference
#'
#' @keywords internal
#' @noRd
select_candidate_jwks <- function(
  jwks_or_keys,
  header_alg = NULL,
  kid = NULL,
  pins = NULL
) {
  # Normalize input to a list of key objects
  keys <- jwks_or_keys
  if (is.list(jwks_or_keys) && !is.null(jwks_or_keys$keys)) {
    keys <- jwks_or_keys$keys
  }
  if (is.data.frame(keys)) {
    keys <- unname(lapply(seq_len(nrow(keys)), function(i) {
      as.list(keys[i, , drop = FALSE])
    }))
  } else if (is.list(keys)) {
    nm <- names(keys)
    if (
      !is.null(nm) && any(nm %in% c("kty", "kid", "n", "e", "crv", "x", "y"))
    ) {
      keys <- list(keys)
    }
  } else {
    err_parse("JWKS keys malformed")
  }

  if (!is.list(keys)) {
    keys <- list()
  }

  # Keep keys where use is missing or explicitly 'sig'
  keep_use <- vapply(
    keys,
    function(k) {
      u <- try(k$use, silent = TRUE)
      if (inherits(u, "try-error") || is.null(u)) {
        return(TRUE)
      }
      is.character(u) && length(u) == 1L && identical(tolower(u), "sig")
    },
    logical(1)
  )
  keys <- keys[keep_use]

  # Honor key_ops: keep keys where key_ops is missing or includes "verify"
  # (RFC 7517 Section 4.3: key_ops restricts permitted operations)
  keep_ops <- vapply(
    keys,
    function(k) {
      valid_key_ops <- c(
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "wrapkey",
        "unwrapkey",
        "derivekey",
        "derivebits"
      )
      ops <- try(k$key_ops, silent = TRUE)
      if (inherits(ops, "try-error") || is.null(ops)) {
        return(TRUE)
      }
      if (!is.character(ops) || length(ops) == 0L || anyNA(ops)) {
        return(FALSE)
      }
      ops_norm <- tolower(ops)
      if (
        !all(nzchar(ops)) ||
          anyDuplicated(ops_norm) > 0L ||
          !all(ops_norm %in% valid_key_ops)
      ) {
        return(FALSE)
      }
      # For signature verification, the key must support "verify"
      "verify" %in% ops_norm
    },
    logical(1)
  )
  keys <- keys[keep_ops]

  # If a kid is provided, restrict to matching keys
  if (!is.null(kid)) {
    keys <- Filter(
      function(k) {
        kk <- k$kid %||% NA_character_
        is.character(kk) && length(kk) == 1L && !is.na(kk) && identical(kk, kid)
      },
      keys
    )
  }

  # Order by preference: JWK alg matching header_alg comes first
  if (
    length(keys) > 1L &&
      is.character(header_alg) &&
      length(header_alg) == 1L &&
      nzchar(header_alg)
  ) {
    ha <- toupper(header_alg)
    ord_score <- vapply(
      keys,
      function(k) {
        ka <- try(k$alg, silent = TRUE)
        if (inherits(ka, "try-error") || is.null(ka)) {
          return(1L)
        }
        if (!is.character(ka) || length(ka) != 1L || !nzchar(ka)) {
          return(1L)
        }
        if (identical(toupper(ka), ha)) 0L else 1L
      },
      integer(1)
    )
    idx <- order(ord_score)
    keys <- keys[idx]
  }

  # Filter by pins: only return keys whose thumbprint is in the pin list.
  # This ensures signature verification uses only pinned keys, not merely
  # that the JWKS passes a presence check.
  if (!is.null(pins) && length(pins) > 0 && length(keys) > 0) {
    pins <- unique(as.character(pins))
    keys <- Filter(
      function(k) {
        tp <- try(compute_jwk_thumbprint(k), silent = TRUE)
        if (inherits(tp, "try-error")) {
          return(FALSE)
        }
        tp %in% pins
      },
      keys
    )
  }

  keys
}

# Filter candidate JWKs to those compatible with one JWT algorithm.
# Used after candidate selection and before signature verification. Input: key
# list plus JWT alg. Output: filtered key list.
# Filter candidate JWKs to those that are compatible with a JWT alg.
# This mirrors the stricter ID token behavior: key type/curve must match the
# JWT alg, and an advertised JWK alg becomes a hard constraint when present.
filter_jwks_for_alg <- function(keys, alg) {
  if (!is.list(keys) || length(keys) == 0L) {
    return(list())
  }

  alg <- toupper(alg %||% "")

  jwk_compatible <- function(k, alg0) {
    kty <- toupper(k$kty %||% "")
    crv <- toupper(k$crv %||% "")
    switch(
      alg0,
      RS256 = kty == "RSA",
      RS384 = kty == "RSA",
      RS512 = kty == "RSA",
      ES256 = (kty == "EC" && crv == "P-256"),
      ES384 = (kty == "EC" && crv == "P-384"),
      ES512 = (kty == "EC" && crv == "P-521"),
      EDDSA = (kty == "OKP" && crv %in% c("ED25519", "ED448")),
      FALSE
    )
  }

  keys <- Filter(function(k) jwk_compatible(k, alg), keys)

  Filter(
    function(k) {
      ka <- k$alg %||% NULL
      is.null(ka) || toupper(ka) == alg
    },
    keys
  )
}

## 1.2 Convert and validate key material ----------------------------------

#' Internal: Convert JWK (RSA, EC, or OKP) to an openssl public key
#'
#' @keywords internal
#' @noRd
jwk_to_pubkey <- function(jwk) {
  kty <- jwk$kty %||% err_parse("JWK missing kty")
  if (!kty %in% c("RSA", "EC", "OKP")) {
    err_parse(paste0("Unsupported JWK kty: ", kty))
  }
  # jose::read_jwk takes a JSON string or file path
  jwk_json <- jsonlite::toJSON(jwk, auto_unbox = TRUE, null = "null")
  key <- try(jose::read_jwk(jwk_json), silent = TRUE)
  if (inherits(key, "try-error")) {
    err_parse("Failed to parse JWK")
  }
  key
}

#' Internal: Compute RFC 7638 JWK thumbprint (SHA-256, base64url, no padding)
#'
#' Supports RSA, EC, and OKP public keys. The canonical JSON serialization uses
#' the minimal member set in lexicographic key order:
#' - RSA: {"e":"...","kty":"RSA","n":"..."}
#' - EC:  {"crv":"...","kty":"EC","x":"...","y":"..."}
#' - OKP: {"crv":"...","kty":"OKP","x":"..."}
#'
#' @keywords internal
#' @noRd
compute_jwk_thumbprint <- function(jwk) {
  if (!is.list(jwk)) {
    err_parse("JWK must be a list")
  }
  kty <- jwk$kty %||% err_parse("JWK missing kty")
  if (kty == "RSA") {
    e <- jwk$e %||% err_parse("RSA JWK missing e")
    n <- jwk$n %||% err_parse("RSA JWK missing n")
    if (!is.character(e) || !is.character(n)) {
      err_parse("RSA JWK e/n must be character")
    }
    canon <- list(e = e, kty = "RSA", n = n)
    # Order keys explicitly as required by RFC 7638 (lexicographic)
    canon <- canon[c("e", "kty", "n")]
  } else if (kty == "EC") {
    crv <- jwk$crv %||% err_parse("EC JWK missing crv")
    x <- jwk$x %||% err_parse("EC JWK missing x")
    y <- jwk$y %||% err_parse("EC JWK missing y")
    if (!is.character(crv) || !is.character(x) || !is.character(y)) {
      err_parse("EC JWK crv/x/y must be character")
    }
    canon <- list(crv = crv, kty = "EC", x = x, y = y)
    canon <- canon[c("crv", "kty", "x", "y")]
  } else if (kty == "OKP") {
    crv <- jwk$crv %||% err_parse("OKP JWK missing crv")
    x <- jwk$x %||% err_parse("OKP JWK missing x")
    if (!is.character(crv) || !is.character(x)) {
      err_parse("OKP JWK crv/x must be character")
    }
    canon <- list(crv = crv, kty = "OKP", x = x)
    canon <- canon[c("crv", "kty", "x")]
  } else {
    err_parse("Unsupported JWK kty for thumbprint")
  }
  json <- jsonlite::toJSON(canon, auto_unbox = TRUE, null = "null", digits = NA)
  # Ensure minified JSON (no whitespace); jsonlite pretty=FALSE by default
  json_raw <- charToRaw(as.character(json))
  digest <- openssl::sha256(json_raw)
  base64url_encode(digest)
}

# 2 JWK decoding helpers ---------------------------------------------------

## 2.1 Decode and size-check key fields -----------------------------------

# Strictly decode a base64urlUInt field from a JWK.
# Used by RSA, EC, and OKP key validation. Input: encoded field value and field
# name. Output: raw decoded bytes.
strict_decode_jwk_base64url_uint <- function(value, field_name) {
  if (
    !is.character(value) ||
      length(value) != 1L ||
      is.na(value) ||
      !nzchar(value)
  ) {
    err_parse(paste0(field_name, " must be a non-empty base64urlUInt"))
  }

  if (!grepl("^[A-Za-z0-9_-]+$", value)) {
    err_parse(paste0(field_name, " must be a strict base64urlUInt"))
  }

  decoded <- tryCatch(base64url_decode_raw(value), error = function(...) NULL)
  if (is.null(decoded) || !is.raw(decoded) || length(decoded) == 0L) {
    err_parse(paste0(field_name, " must be a valid base64urlUInt"))
  }

  decoded
}

# Compute the effective RSA modulus size in bits.
# Used during JWKS validation to reject weak RSA keys. Input: modulus raw
# bytes. Output: integer bit length.
jwk_rsa_modulus_bits <- function(modulus_raw) {
  non_zero_idx <- which(modulus_raw != as.raw(0))
  if (length(non_zero_idx) == 0L) {
    return(0L)
  }

  trimmed <- modulus_raw[non_zero_idx[1]:length(modulus_raw)]
  first_octet <- as.integer(trimmed[[1]])
  ((length(trimmed) - 1L) * 8L) + floor(log(first_octet, base = 2)) + 1L
}

# Return the expected EC coordinate size for one supported curve.
# Used by EC JWK validation. Input: curve name. Output: byte length or NULL.
jwk_ec_coordinate_size <- function(curve) {
  switch(
    as.character(curve %||% ""),
    "P-256" = 32L,
    "P-384" = 48L,
    "P-521" = 66L,
    NULL
  )
}

# Strictly decode and size-check one EC coordinate.
# Used by EC JWK validation. Input: encoded coordinate, field name, and curve.
# Output: raw decoded bytes.
strict_decode_jwk_ec_coordinate <- function(value, field_name, curve) {
  decoded <- strict_decode_jwk_base64url_uint(value, field_name)
  expected_len <- jwk_ec_coordinate_size(curve)

  if (!is.null(expected_len) && length(decoded) != expected_len) {
    err_parse(paste0(
      field_name,
      " must decode to ",
      expected_len,
      " bytes for curve ",
      curve
    ))
  }

  decoded
}

## 1.3 Validate fetched JWKS objects --------------------------------------

#' Internal: Validate JWKS structure and optionally enforce pinning
#'
#' @param jwks Parsed JWKS (list)
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'   to pin against.
#' @param pin_mode Either "any" (at least one key matches a pin) or "all"
#'   (every RSA/EC/OKP key must match a pin).
#'
#' @keywords internal
#' @noRd
validate_jwks <- function(jwks, pins = NULL, pin_mode = c("any", "all")) {
  pin_mode <- match.arg(pin_mode)
  if (!is.list(jwks)) {
    err_parse("Invalid JWKS structure")
  }
  ks <- jwks$keys
  if (is.null(ks)) {
    err_parse("JWKS missing keys array")
  }
  if (is.data.frame(ks)) {
    ks <- unname(lapply(seq_len(nrow(ks)), function(i) {
      as.list(ks[i, , drop = FALSE])
    }))
  } else if (is.list(ks)) {
    nm <- names(ks)
    if (
      !is.null(nm) && any(nm %in% c("kty", "n", "e", "crv", "x", "y", "kid"))
    ) {
      ks <- list(ks)
    }
  } else {
    err_parse("JWKS keys malformed")
  }
  if (!is.list(ks)) {
    err_parse("JWKS keys must be a list")
  }
  if (length(ks) > 100) {
    err_parse("JWKS contains excessive keys")
  }

  # Validate each key minimally and ensure no private params leaked
  supported_seen <- 0L
  private_params <- c("d", "p", "q", "dp", "dq", "qi", "oth")
  thumbprints <- character()
  for (i in seq_along(ks)) {
    k <- ks[[i]]
    if (!is.list(k)) {
      err_parse("JWK entry must be an object")
    }
    kty <- k$kty %||% err_parse("JWK missing kty")
    kid <- k$kid %||% NA_character_
    if (!is.na(kid)) {
      if (!is.character(kid) || length(kid) != 1 || nchar(kid) > 128) {
        err_parse("JWK kid invalid")
      }
    }
    # No private key parameters in a JWKS
    if (any(names(k) %in% private_params)) {
      err_parse("JWKS contains private key material")
    }
    if (kty %in% c("RSA", "EC", "OKP")) {
      supported_seen <- supported_seen + 1L
      # Minimal member presence
      if (kty == "RSA") {
        if (!is.character(k$n) || !is.character(k$e)) {
          err_parse("RSA JWK missing n/e")
        }
        modulus_raw <- strict_decode_jwk_base64url_uint(k$n, "RSA JWK n")
        strict_decode_jwk_base64url_uint(k$e, "RSA JWK e")
        if (jwk_rsa_modulus_bits(modulus_raw) < 2048L) {
          err_parse("RSA JWK modulus must be at least 2048 bits")
        }
      } else if (kty == "EC") {
        if (!is.character(k$crv) || !is.character(k$x) || !is.character(k$y)) {
          err_parse("EC JWK missing crv/x/y")
        }
        strict_decode_jwk_ec_coordinate(k$x, "EC JWK x", k$crv)
        strict_decode_jwk_ec_coordinate(k$y, "EC JWK y", k$crv)
      } else if (kty == "OKP") {
        if (!is.character(k$crv) || !is.character(k$x)) {
          err_parse("OKP JWK missing crv/x")
        }
        strict_decode_jwk_base64url_uint(k$x, "OKP JWK x")
      }
      # Compute thumbprint for pinning
      tp <- try(compute_jwk_thumbprint(k), silent = TRUE)
      if (!inherits(tp, "try-error")) {
        thumbprints <- c(thumbprints, tp)
      }
    }
  }
  if (supported_seen == 0L) {
    err_parse("JWKS contains no supported public keys (RSA/EC/OKP)")
  }

  # Enforce pinning if configured
  if (!is.null(pins) && length(pins) > 0) {
    pins <- unique(as.character(pins))
    if (pin_mode == "any") {
      if (!any(thumbprints %in% pins)) {
        err_parse("JWKS pinning failed: no key matches a configured pin")
      }
    } else if (pin_mode == "all") {
      # All supported keys must be pinned
      missed <- setdiff(thumbprints, pins)
      if (length(missed) > 0) {
        err_parse("JWKS pinning failed: unpinned key(s) present")
      }
    }
  }
  invisible(TRUE)
}
