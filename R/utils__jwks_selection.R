# This file contains helpers that choose which JWKs are candidates for JWT
# signature verification.
# Use them after JWKS download when only some keys are compatible with the
# current JWT algorithm, key id, or configured pins.

# 1 JWKS key selection -----------------------------------------------------

## 1.1 Candidate filtering -------------------------------------------------

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
