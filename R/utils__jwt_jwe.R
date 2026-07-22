# This file contains the low-level compact JWE helpers used for outbound
# request-object encryption and inbound decryption of nested JWTs such as
# encrypted JARM responses
# A JWE is the encrypted JWT form used when request objects need
# confidentiality in addition to signature protection
# Used for compact JWE encoding/decoding, recipient-key normalization, and
# AES-CBC-HMAC content-encryption helpers

# 1 Compact JWE helpers -------------------------------------------------------

## 1.1 Algorithm normalization ------------------------------------------------

#' Canonicalize a JWE alg name for JOSE headers
#'
#' Used by the compact JWE helpers in this file.
#'
#' @param alg Algorithm name to normalize.
#' @return Canonicalized JOSE algorithm string, or `""` when unavailable.
#' @keywords internal
#' @noRd
canonicalize_jwe_alg <- function(alg) {
  if (!is.character(alg) || length(alg) != 1L) {
    return("")
  }

  alg_chr <- trimws(as.character(alg)[[1]])
  if (is.na(alg_chr) || !nzchar(alg_chr)) {
    return("")
  }

  toupper(alg_chr)
}

#' Canonicalize a JWE enc name for JOSE headers
#'
#' Used by the compact JWE helpers in this file.
#'
#' @param enc Content-encryption algorithm name to normalize.
#' @return Canonicalized JOSE content-encryption algorithm string, or `""`
#'   when unavailable.
#' @keywords internal
#' @noRd
canonicalize_jwe_enc <- function(enc) {
  if (!is.character(enc) || length(enc) != 1L) {
    return("")
  }

  enc_chr <- trimws(as.character(enc)[[1]])
  if (is.na(enc_chr) || !nzchar(enc_chr)) {
    return("")
  }

  toupper(enc_chr)
}

#' Resolve AES-CBC-HMAC parameters for a JWE enc value
#'
#' Used by compact JWE encryption/decryption helpers for the supported
#' AES-CBC-HMAC content-encryption family.
#'
#' @param enc JOSE content-encryption algorithm name.
#' @return Named list describing CEK, HMAC, AES, and tag sizes.
#' @keywords internal
#' @noRd
jwe_cbc_hmac_spec <- function(enc) {
  enc <- canonicalize_jwe_enc(enc)

  switch(
    enc,
    "A128CBC-HS256" = list(
      enc = enc,
      cek_bytes = 32L,
      mac_key_bytes = 16L,
      enc_key_bytes = 16L,
      iv_bytes = 16L,
      tag_bytes = 16L,
      hmac_alg = "HS256"
    ),
    "A192CBC-HS384" = list(
      enc = enc,
      cek_bytes = 48L,
      mac_key_bytes = 24L,
      enc_key_bytes = 24L,
      iv_bytes = 16L,
      tag_bytes = 24L,
      hmac_alg = "HS384"
    ),
    "A256CBC-HS512" = list(
      enc = enc,
      cek_bytes = 64L,
      mac_key_bytes = 32L,
      enc_key_bytes = 32L,
      iv_bytes = 16L,
      tag_bytes = 32L,
      hmac_alg = "HS512"
    ),
    err_config(paste0("Unsupported compact JWE enc: ", enc))
  )
}

## 1.2 Compact JWE parsing ----------------------------------------------------

#' Split a compact JWE into decoded parts
#'
#' Used by the compact JWE decryption helpers and unit tests.
#'
#' @param jwe Compact JWE string.
#' @return List containing the encoded segments, decoded raw segments, and the
#'   parsed protected header.
#' @keywords internal
#' @noRd
jwe_compact_parts <- function(jwe) {
  if (!is.character(jwe) || length(jwe) != 1L || is.na(jwe)) {
    err_parse(
      "Invalid JWE format: expected a single compact serialization string"
    )
  }

  dot_pos <- gregexpr(".", jwe, fixed = TRUE)[[1]]
  if (length(dot_pos) != 4L || identical(dot_pos[[1]], -1L)) {
    err_parse("Invalid JWE format: expected 5 dot-separated parts")
  }

  protected <- substr(jwe, 1L, dot_pos[1] - 1L)
  encrypted_key <- substr(jwe, dot_pos[1] + 1L, dot_pos[2] - 1L)
  iv <- substr(jwe, dot_pos[2] + 1L, dot_pos[3] - 1L)
  ciphertext <- substr(jwe, dot_pos[3] + 1L, dot_pos[4] - 1L)
  tag <- substr(jwe, dot_pos[4] + 1L, nchar(jwe))

  protected_raw <- strict_decode_jwt_segment(protected, "protected header")
  protected_text <- strict_decode_jwt_json_text(
    protected_raw,
    "protected header"
  )
  reject_duplicate_json_object_members(protected_text, "JWE protected header")
  assert_json_text_is_object(protected_text, "JWE protected header")
  protected_header <- tryCatch(
    jsonlite::fromJSON(protected_text, simplifyVector = FALSE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWE protected header JSON",
        "i" = conditionMessage(e)
      ))
    }
  )

  list(
    protected = protected,
    encrypted_key = encrypted_key,
    iv = iv,
    ciphertext = ciphertext,
    tag = tag,
    protected_raw = protected_raw,
    encrypted_key_raw = strict_decode_jwt_segment(
      encrypted_key,
      "encrypted key",
      allow_empty = TRUE
    ),
    iv_raw = strict_decode_jwt_segment(iv, "initialization vector"),
    ciphertext_raw = strict_decode_jwt_segment(ciphertext, "ciphertext"),
    tag_raw = strict_decode_jwt_segment(tag, "authentication tag"),
    protected_header = protected_header
  )
}

## 1.3 Key normalization ------------------------------------------------------

#' Normalize a compact JWE recipient public-key input
#'
#' Accepts an OpenSSL key object, a PEM string, a parsed JWK object, or a JWK
#' JSON string. Used by outbound compact JWE encryption helpers.
#'
#' @param key Recipient public-key input to normalize.
#' @param arg_name Argument name used in error messages.
#' @return Normalized public-key object.
#' @keywords internal
#' @noRd
normalize_jwe_recipient_public_key <- function(
  key,
  arg_name = "request_object_encryption_jwk"
) {
  if (
    inherits(key, "key") ||
      inherits(key, "pubkey") ||
      inherits(key, "rsa") ||
      inherits(key, "ecdsa")
  ) {
    return(key)
  }

  if (is.list(key)) {
    return(jwk_to_pubkey(key))
  }

  if (is.character(key) && length(key) >= 1L) {
    text <- paste(key, collapse = "\n")
    if (grepl("^\\s*\\{", text)) {
      parsed_jwk <- try(
        jsonlite::fromJSON(text, simplifyVector = FALSE),
        silent = TRUE
      )
      if (!inherits(parsed_jwk, "try-error") && is.list(parsed_jwk)) {
        return(jwk_to_pubkey(parsed_jwk))
      }
    }

    parsed_key <- try(openssl::read_key(text), silent = TRUE)
    if (!inherits(parsed_key, "try-error")) {
      return(parsed_key)
    }

    err_config(paste0("Failed to parse ", arg_name))
  }

  err_config(paste0(
    arg_name,
    " must be a JWK object, JWK JSON string, openssl::key, or PEM string"
  ))
}

#' Normalize a JWKS or JWK collection into a list of key objects
#'
#' Used by Request Object encryption key selection helpers.
#'
#' @param jwks_or_keys A JWKS list or candidate JWK list.
#' @return List of JWK objects.
#' @keywords internal
#' @noRd
normalize_request_object_encryption_jwks <- function(jwks_or_keys) {
  keys <- jwks_or_keys
  if (is.list(jwks_or_keys) && !is.null(jwks_or_keys[["keys"]])) {
    keys <- jwks_or_keys[["keys"]]
  }
  if (is.data.frame(keys)) {
    keys <- unname(lapply(seq_len(nrow(keys)), function(index) {
      as.list(keys[index, , drop = FALSE])
    }))
  } else if (is.list(keys)) {
    key_names <- names(keys)
    if (
      !is.null(key_names) &&
        any(key_names %in% c("kty", "kid", "n", "e", "crv", "x", "y"))
    ) {
      keys <- list(keys)
    }
  } else {
    err_parse("JWKS keys malformed")
  }

  if (!is.list(keys)) {
    return(list())
  }

  keys
}

#' Check whether a JWK is structurally compatible with one JWE alg
#'
#' Used by Request Object encryption key selection helpers.
#'
#' @param jwk Parsed JWK object.
#' @param alg JOSE key-management algorithm.
#' @return `TRUE` when the JWK is compatible with the requested alg.
#' @keywords internal
#' @noRd
jwk_is_compatible_with_jwe_alg <- function(jwk, alg) {
  kty <- jwk[["kty"]] %||% ""

  switch(
    canonicalize_jwe_alg(alg),
    "RSA-OAEP" = identical(kty, "RSA"),
    FALSE
  )
}

#' Select candidate JWKs for Request Object encryption
#'
#' Filters a JWKS down to keys that can be used for outbound Request Object
#' encryption. Used before a recipient public key is resolved.
#'
#' @param jwks_or_keys A JWKS list or candidate JWK list.
#' @param alg JOSE key-management algorithm.
#' @param kid Optional key id used to select one provider encryption key.
#' @return Filtered list of candidate JWK objects.
#' @keywords internal
#' @noRd
select_candidate_jwks_for_encryption <- function(
  jwks_or_keys,
  alg,
  kid = NULL
) {
  keys <- normalize_request_object_encryption_jwks(jwks_or_keys)

  keep_use <- vapply(
    keys,
    function(key) {
      use <- try(key[["use"]], silent = TRUE)
      if (inherits(use, "try-error") || is.null(use)) {
        return(TRUE)
      }
      is.character(use) && length(use) == 1L && identical(use, "enc")
    },
    logical(1)
  )
  keys <- keys[keep_use]

  keep_ops <- vapply(
    keys,
    function(key) {
      valid_key_ops <- c(
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "wrapKey",
        "unwrapKey",
        "deriveKey",
        "deriveBits"
      )
      key_ops <- try(key[["key_ops"]], silent = TRUE)
      if (inherits(key_ops, "try-error") || is.null(key_ops)) {
        return(TRUE)
      }
      if (!is.character(key_ops) || length(key_ops) == 0L || anyNA(key_ops)) {
        return(FALSE)
      }
      if (
        !all(nzchar(key_ops)) ||
          anyDuplicated(key_ops) > 0L ||
          !all(key_ops %in% valid_key_ops)
      ) {
        return(FALSE)
      }
      any(key_ops %in% c("encrypt", "wrapKey"))
    },
    logical(1)
  )
  keys <- keys[keep_ops]

  if (is_valid_string(kid)) {
    keys <- Filter(
      function(key) {
        key_kid <- key[["kid"]] %||% NA_character_
        is.character(key_kid) &&
          length(key_kid) == 1L &&
          !is.na(key_kid) &&
          identical(key_kid, kid)
      },
      keys
    )
  }

  keys <- Filter(
    function(key) {
      jwk_is_compatible_with_jwe_alg(key, alg)
    },
    keys
  )

  Filter(
    function(key) {
      key_alg <- key[["alg"]] %||% ""
      !nzchar(key_alg) || identical(key_alg, canonicalize_jwe_alg(alg))
    },
    keys
  )
}

#' Rank one Request Object encryption JWK candidate
#'
#' Used to prefer explicit encryption keys when more than one candidate remains
#' after filtering.
#'
#' @param jwk Parsed JWK object.
#' @param alg JOSE key-management algorithm.
#' @return Integer preference score.
#' @keywords internal
#' @noRd
rank_request_object_encryption_jwk <- function(jwk, alg) {
  score <- 0L

  use <- jwk[["use"]] %||% ""
  if (identical(use, "enc")) {
    score <- score + 4L
  }

  key_ops <- jwk[["key_ops"]] %||% character(0)
  if (length(key_ops) > 0 && any(key_ops %in% c("encrypt", "wrapKey"))) {
    score <- score + 2L
  }

  key_alg <- jwk[["alg"]] %||% ""
  if (nzchar(key_alg) && identical(key_alg, canonicalize_jwe_alg(alg))) {
    score <- score + 4L
  }

  score
}

#' Resolve Request Object encryption configuration for one client
#'
#' Used by authorization-request builders before a signed Request Object is
#' optionally wrapped in JWE.
#'
#' @param client OAuth client carrying Request Object encryption settings.
#' @return `NULL` when encryption is disabled, otherwise a named list.
#' @keywords internal
#' @noRd
resolve_authorization_request_encryption_config <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  alg <- canonicalize_jwe_alg(
    client@request_object_encryption_alg %||% NA_character_
  )
  enc <- canonicalize_jwe_enc(
    client@request_object_encryption_enc %||% NA_character_
  )
  kid <- client@request_object_encryption_kid %||% NA_character_

  if (!nzchar(alg) && !nzchar(enc)) {
    return(NULL)
  }
  if (!nzchar(alg) || !nzchar(enc)) {
    err_config(
      paste(
        "request_object_encryption_alg and",
        "request_object_encryption_enc must both be provided"
      )
    )
  }

  list(
    alg = alg,
    enc = enc,
    kid = if (is_valid_string(kid)) kid else NULL
  )
}

#' Resolve the public key used for Request Object encryption
#'
#' Used by outbound Request Object builders after signing has completed and a
#' nested JWE wrapper needs one recipient key.
#'
#' @param client OAuth client carrying Request Object encryption settings.
#' @param alg JOSE key-management algorithm.
#' @param kid Optional key id used to select one provider encryption key.
#' @return Named list with the normalized public key and resolved `kid`.
#' @keywords internal
#' @noRd
resolve_authorization_request_encryption_public_key <- function(
  client,
  alg,
  kid = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  explicit_key <- client@provider@request_object_encryption_jwk %||% NULL
  if (!is.null(explicit_key)) {
    explicit_jwk <- if (is.list(explicit_key)) explicit_key else NULL
    explicit_kid <- explicit_jwk[["kid"]] %||% NULL
    explicit_alg <- canonicalize_jwe_alg(
      explicit_jwk[["alg"]] %||% ""
    )

    if (
      is_valid_string(kid) &&
        is_valid_string(explicit_kid) &&
        !identical(explicit_kid, kid)
    ) {
      err_config(
        paste(
          "request_object_encryption_kid does not match the provider's",
          "explicit request_object_encryption_jwk kid"
        )
      )
    }
    if (
      nzchar(explicit_alg) &&
        !identical(explicit_alg, canonicalize_jwe_alg(alg))
    ) {
      err_config(
        paste0(
          "provider request_object_encryption_jwk advertises JWE alg '",
          explicit_alg,
          "' but the client requested '",
          canonicalize_jwe_alg(alg),
          "'"
        )
      )
    }

    return(list(
      public_key = normalize_jwe_recipient_public_key(explicit_key),
      kid = kid %||% explicit_kid
    ))
  }

  issuer <- client@provider@issuer %||% NA_character_
  if (!is_valid_string(issuer)) {
    err_config(
      paste(
        "Request Object encryption requires provider issuer or provider",
        "request_object_encryption_jwk"
      )
    )
  }

  jwks <- fetch_jwks(
    issuer = issuer,
    jwks_cache = client@provider@jwks_cache,
    pins = client@provider@jwks_pins,
    pin_mode = client@provider@jwks_pin_mode,
    provider = client@provider
  )
  candidates <- select_candidate_jwks_for_encryption(
    jwks_or_keys = jwks,
    alg = alg,
    kid = kid
  )

  if (length(candidates) == 0L) {
    err_config(
      paste(
        "No provider Request Object encryption key matched the requested",
        "alg/kid combination"
      )
    )
  }

  if (length(candidates) > 1L) {
    candidate_scores <- vapply(
      candidates,
      rank_request_object_encryption_jwk,
      integer(1),
      alg = alg
    )
    best_index <- which(candidate_scores == max(candidate_scores))
    candidates <- candidates[best_index]

    if (length(candidates) > 1L) {
      err_config(
        paste(
          "Multiple provider Request Object encryption keys matched; set",
          "request_object_encryption_kid or provider",
          "request_object_encryption_jwk"
        )
      )
    }
  }

  selected_jwk <- candidates[[1]]

  list(
    public_key = jwk_to_pubkey(selected_jwk),
    kid = selected_jwk[["kid"]] %||% kid
  )
}

## 1.4 AES-CBC-HMAC helpers ---------------------------------------------------

#' Encode one non-negative integer as 64-bit big-endian raw bytes
#'
#' Used by compact JWE AES-CBC-HMAC tag computation to encode the AAD length in
#' bits, per RFC 7516 Appendix B.
#'
#' @param value Non-negative integer-like numeric value.
#' @return Eight raw bytes in big-endian order.
#' @keywords internal
#' @noRd
uint64_to_big_endian_raw <- function(value) {
  if (
    !is.numeric(value) ||
      length(value) != 1L ||
      !is.finite(value) ||
      value < 0 ||
      value != floor(value)
  ) {
    err_config("uint64_to_big_endian_raw requires one non-negative integer")
  }

  remainder <- value
  out <- raw(8)
  for (idx in 8:1) {
    out[[idx]] <- as.raw(remainder %% 256)
    remainder <- floor(remainder / 256)
  }

  out
}

#' Split a JWE AES-CBC-HMAC CEK into MAC and encryption keys
#'
#' Used by compact JWE AES-CBC-HMAC encryption and decryption helpers.
#'
#' @param cek_raw Raw content-encryption key.
#' @param enc JOSE content-encryption algorithm name.
#' @return Named list with `mac_key` and `enc_key` raw vectors.
#' @keywords internal
#' @noRd
split_jwe_cbc_hmac_cek <- function(cek_raw, enc) {
  spec <- jwe_cbc_hmac_spec(enc)
  if (!is.raw(cek_raw) || length(cek_raw) != spec[["cek_bytes"]]) {
    err_config(paste0(
      spec[["enc"]],
      " requires a CEK of ",
      spec[["cek_bytes"]],
      " bytes"
    ))
  }

  list(
    mac_key = cek_raw[seq_len(spec[["mac_key_bytes"]])],
    enc_key = cek_raw[
      (spec[["mac_key_bytes"]] + 1L):(spec[["mac_key_bytes"]] +
        spec[["enc_key_bytes"]])
    ]
  )
}

#' Compute the compact JWE AES-CBC-HMAC authentication tag
#'
#' Used by compact JWE AES-CBC-HMAC encryption and decryption helpers.
#'
#' @param enc JOSE content-encryption algorithm name.
#' @param mac_key Raw MAC key.
#' @param protected_header_b64 Base64url-encoded protected header.
#' @param iv_raw Raw initialization vector.
#' @param ciphertext_raw Raw ciphertext.
#' @return Raw authentication tag.
#' @keywords internal
#' @noRd
compute_compact_jwe_auth_tag <- function(
  enc,
  mac_key,
  protected_header_b64,
  iv_raw,
  ciphertext_raw
) {
  spec <- jwe_cbc_hmac_spec(enc)

  if (!is.raw(mac_key) || length(mac_key) != spec[["mac_key_bytes"]]) {
    err_config(paste0(
      spec[["enc"]],
      " requires a MAC key of ",
      spec[["mac_key_bytes"]],
      " bytes"
    ))
  }

  aad_raw <- charToRaw(as.character(protected_header_b64))
  al_raw <- uint64_to_big_endian_raw(length(aad_raw) * 8)
  mac_input <- c(aad_raw, iv_raw, ciphertext_raw, al_raw)

  full_tag <- switch(
    spec[["hmac_alg"]],
    HS256 = openssl::sha256(mac_input, key = mac_key),
    HS384 = openssl::sha384(mac_input, key = mac_key),
    HS512 = openssl::sha512(mac_input, key = mac_key),
    err_config(paste0(
      "Unsupported compact JWE HMAC algorithm: ",
      spec[["hmac_alg"]]
    ))
  )

  full_tag[seq_len(spec[["tag_bytes"]])]
}

## 1.5 Compact JWE encryption and decryption ----------------------------------

#' Encrypt a compact JWE using RSA-OAEP and AES-CBC-HMAC
#'
#' Used by outbound Request Object encryption when signed request objects are
#' nested inside a compact JWE.
#'
#' @param plaintext Plaintext value as raw bytes or a scalar character string.
#' @param public_key Recipient public key input.
#' @param alg JOSE key-management algorithm name.
#' @param enc JOSE content-encryption algorithm name.
#' @param kid Optional JOSE `kid` header value.
#' @param typ Optional JOSE `typ` header value.
#' @param cty Optional JOSE `cty` header value.
#' @return Compact JWE string.
#' @keywords internal
#' @noRd
jwe_compact_encrypt <- function(
  plaintext,
  public_key,
  alg,
  enc,
  kid = NULL,
  typ = NULL,
  cty = NULL
) {
  alg <- canonicalize_jwe_alg(alg)
  enc <- canonicalize_jwe_enc(enc)

  if (!identical(alg, "RSA-OAEP")) {
    err_config(paste0("Unsupported compact JWE alg: ", alg))
  }

  spec <- jwe_cbc_hmac_spec(enc)
  recipient_key <- normalize_jwe_recipient_public_key(public_key)
  plaintext_raw <- if (is.raw(plaintext)) {
    plaintext
  } else if (
    is.character(plaintext) &&
      length(plaintext) == 1L &&
      !is.na(plaintext)
  ) {
    charToRaw(enc2utf8(plaintext))
  } else {
    err_config("jwe_compact_encrypt requires raw or scalar character plaintext")
  }

  header <- list(alg = alg, enc = enc)
  if (is_valid_string(kid)) {
    header[["kid"]] <- kid
  }
  if (is_valid_string(typ)) {
    header[["typ"]] <- typ
  }
  if (is_valid_string(cty)) {
    header[["cty"]] <- cty
  }

  header_json <- jsonlite::toJSON(
    header,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  protected_header_b64 <- base64url_encode(charToRaw(enc2utf8(header_json)))

  cek_raw <- openssl::rand_bytes(spec[["cek_bytes"]])
  key_parts <- split_jwe_cbc_hmac_cek(cek_raw, enc)
  encrypted_key_raw <- try(
    openssl::rsa_encrypt(
      cek_raw,
      pubkey = recipient_key,
      oaep = TRUE
    ),
    silent = TRUE
  )
  if (inherits(encrypted_key_raw, "try-error")) {
    err_config(
      "Failed to encrypt compact JWE CEK with the recipient public key"
    )
  }
  iv_raw <- openssl::rand_bytes(spec[["iv_bytes"]])
  ciphertext_raw <- openssl::aes_cbc_encrypt(
    plaintext_raw,
    key = key_parts[["enc_key"]],
    iv = iv_raw
  )
  tag_raw <- compute_compact_jwe_auth_tag(
    enc = enc,
    mac_key = key_parts[["mac_key"]],
    protected_header_b64 = protected_header_b64,
    iv_raw = iv_raw,
    ciphertext_raw = ciphertext_raw
  )

  paste(
    protected_header_b64,
    base64url_encode(encrypted_key_raw),
    base64url_encode(iv_raw),
    base64url_encode(ciphertext_raw),
    base64url_encode(tag_raw),
    sep = "."
  )
}

#' Decrypt a compact JWE using RSA-OAEP and AES-CBC-HMAC
#'
#' Used by inbound encrypted JARM validation and tests that need to inspect
#' nested JWTs after compact JWE encryption.
#'
#' @param jwe Compact JWE string.
#' @param private_key Recipient private key input.
#' @return Named list with the parsed header and decrypted plaintext.
#' @keywords internal
#' @noRd
jwe_compact_decrypt <- function(jwe, private_key) {
  parts <- jwe_compact_parts(jwe)
  header <- parts[["protected_header"]]
  alg <- canonicalize_jwe_alg(
    jwt_header_field_exact(header, "alg") %||% ""
  )
  enc <- canonicalize_jwe_enc(
    jwt_header_field_exact(header, "enc") %||% ""
  )

  if (!identical(alg, "RSA-OAEP")) {
    err_parse(paste0("Unsupported compact JWE alg: ", alg))
  }

  spec <- jwe_cbc_hmac_spec(enc)
  key <- normalize_private_key_input(
    private_key,
    arg_name = "request_object_encryption_private_key"
  )
  cek_failed <- FALSE
  cek_raw <- try(
    openssl::rsa_decrypt(
      parts[["encrypted_key_raw"]],
      key = key,
      oaep = TRUE
    ),
    silent = TRUE
  )
  if (inherits(cek_raw, "try-error")) {
    cek_failed <- TRUE
    cek_raw <- openssl::rand_bytes(spec[["cek_bytes"]])
  } else if (!is.raw(cek_raw) || length(cek_raw) != spec[["cek_bytes"]]) {
    cek_failed <- TRUE
    cek_raw <- openssl::rand_bytes(spec[["cek_bytes"]])
  }

  key_parts <- split_jwe_cbc_hmac_cek(cek_raw, enc)
  expected_tag <- compute_compact_jwe_auth_tag(
    enc = enc,
    mac_key = key_parts[["mac_key"]],
    protected_header_b64 = parts[["protected"]],
    iv_raw = parts[["iv_raw"]],
    ciphertext_raw = parts[["ciphertext_raw"]]
  )
  if (
    isTRUE(cek_failed) ||
      !constant_time_compare(parts[["tag_raw"]], expected_tag)
  ) {
    err_parse(
      "Compact JWE decryption failed",
      context = list(compact_jwe_failure = "authenticated_decryption")
    )
  }

  plaintext_raw <- try(
    openssl::aes_cbc_decrypt(
      parts[["ciphertext_raw"]],
      key = key_parts[["enc_key"]],
      iv = parts[["iv_raw"]]
    ),
    silent = TRUE
  )
  if (inherits(plaintext_raw, "try-error")) {
    err_parse(
      "Compact JWE decryption failed",
      context = list(compact_jwe_failure = "authenticated_decryption")
    )
  }

  plaintext <- tryCatch(
    {
      if (any(plaintext_raw == as.raw(0))) {
        return(NULL)
      }
      txt <- rawToChar(plaintext_raw)
      if (!isTRUE(validUTF8(txt))) {
        return(NULL)
      }
      txt
    },
    error = function(...) NULL
  )

  list(
    header = header,
    plaintext_raw = plaintext_raw,
    plaintext = plaintext
  )
}
