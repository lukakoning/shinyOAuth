# This file contains the encryption helpers for the sealed OAuth state
# payload
# The state value is the temporary login data sent out during redirect and
# checked again on callback
# Used for encrypting that state into a compact token and decrypting it safely
# during callback handling

# 1 State encryption helpers ---------------------------------------------------

## 1.1 Encrypt and decrypt sealed state ----------------------------------------

# Functions in this subsection encrypt state payloads before login redirects and
# decrypt them again during callback handling.

#' Internal: normalize or derive a 32-byte state encryption key
#'
#' Accepts either a sufficiently long character passphrase or a raw key.
#' Character inputs are UTF-8 normalized and derived with SHA-256; raw inputs
#' of exactly 32 bytes are used as-is, and longer raw inputs are hashed to
#' avoid silent truncation. Used by the state encrypt/decrypt helpers below.
#'
#' @param key Character passphrase or raw key material.
#' @param min_chars Minimum allowed passphrase length for character keys.
#' @return Raw 32-byte encryption key.
#' @keywords internal
#' @noRd
normalize_key32 <- function(key, min_chars = 32L) {
  if (is.null(key)) {
    err_config("state key is NULL", context = list(phase = "key_derivation"))
  }
  if (is.character(key)) {
    if (!is_valid_string(key)) {
      err_config(
        "state key must be a non-empty single string",
        context = list(phase = "key_derivation")
      )
    }

    # Ensure passphrase strength before derivation
    if (nchar(key, type = "bytes") < as.integer(min_chars)) {
      err_config(
        sprintf(
          "state key must be at least %d characters; got %d",
          as.integer(min_chars),
          nchar(key, type = "bytes")
        ),
        context = list(
          phase = "key_derivation",
          min_chars = as.integer(min_chars)
        )
      )
    }

    # Derive 32-byte key; normalize to UTF-8 to avoid locale-dependent bytes
    key <- openssl::sha256(charToRaw(enc2utf8(key)))
  } else if (is.raw(key)) {
    # Raw key path: enforce >= 32 bytes; use exact 32 as-is; hash if longer
    # Rationale: truncation discards entropy and may surprise operators who
    # paste 64-byte secrets. Hashing preserves full-entropy contribution and
    # yields a deterministic 32-byte key.
    if (length(key) < 32L) {
      err_config(
        sprintf(
          "raw state key must be at least 32 bytes; got %d",
          length(key)
        ),
        context = list(phase = "key_derivation")
      )
    }
    if (length(key) == 32L) {
      # Use provided 32 random bytes directly (highest entropy, no transform)
      key <- key
    } else {
      # For raw inputs > 32 bytes, derive a 32-byte key via SHA-256 to avoid
      # silent entropy loss from truncation and ensure deterministic derivation.
      key <- openssl::sha256(key)
    }
  } else {
    err_config(
      "state key must be character or raw",
      context = list(phase = "key_derivation")
    )
  }
  key
}

#' Internal: read a positive numeric value from option or environment
#'
#' Used by `state_decrypt_gcm()` for defensive size limits where package
#' options should take precedence over environment-variable fallbacks.
#'
#' @param opt_name Option name to read first.
#' @param env_name Fallback environment variable name.
#' @param default Positive numeric default.
#' @return Positive numeric limit value.
#' @keywords internal
#' @noRd
get_option_env_positive_number <- function(opt_name, env_name, default) {
  val <- getOption(opt_name, NULL)
  if (is.null(val)) {
    env <- Sys.getenv(env_name, unset = NA_character_)
    if (!is.na(env) && nzchar(env)) {
      suppressWarnings(val <- as.numeric(env))
    }
  }
  if (
    !is.numeric(val) ||
      length(val) != 1L ||
      is.na(val) ||
      !is.finite(val) ||
      val <= 0
  ) {
    return(as.numeric(default))
  }
  as.numeric(val)
}

#' Internal: apply an optional delay before state decryption failure
#'
#' Used by `state_decrypt_fail()`. Defaults to no delay so malformed state
#' does not intentionally block the Shiny event loop. Explicit positive delays
#' add timing noise but sleep synchronously, including during async prevalidation.
#'
#' @return No return value; may sleep briefly before returning invisibly.
#' @keywords internal
#' @noRd
state_decrypt_delay_before_fail <- function() {
  bounds <- getOption("shinyOAuth.state_fail_delay_ms", 0)
  ms <- 0
  if (is.numeric(bounds) && length(bounds) >= 1) {
    b1 <- suppressWarnings(as.numeric(bounds[1]))
    if (!is.finite(b1) || is.na(b1) || b1 < 0) {
      b1 <- 0
    }
    if (length(bounds) >= 2) {
      b2 <- suppressWarnings(as.numeric(bounds[2]))
      if (!is.finite(b2) || is.na(b2) || b2 < 0) {
        b2 <- b1
      }
      lo <- min(b1, b2)
      hi <- max(b1, b2)
      ms <- stats::runif(1, min = lo, max = hi)
    } else {
      ms <- b1
    }
  }
  if (is.finite(ms) && !is.na(ms) && ms > 0) {
    Sys.sleep(ms / 1000)
  }
  invisible(NULL)
}

#' Internal: raise a normalized invalid-state error during state decryption
#'
#' Used by `state_decrypt_gcm()` so all invalid-state failures pass through the
#' same optional delay and `err_invalid_state()` path.
#'
#' @param msg Invalid-state message.
#' @param context Structured error context.
#' @return No return value; always raises `err_invalid_state()`.
#' @keywords internal
#' @noRd
state_decrypt_fail <- function(msg, context = list()) {
  state_decrypt_delay_before_fail()
  err_invalid_state(msg, context = context)
}

#' Check whether the installed openssl release supports authenticated GCM
#'
#' @param version Installed openssl package version.
#' @return Whether openssl is at least version 2.6.0.
#' @keywords internal
#' @noRd
state_openssl_gcm_available <- function(version = utils::packageVersion("openssl")) {
  package_version(version) >= "2.6.0"
}

#' Recommend upgrading openssl once per R session when CBC-HMAC is selected
#'
#' @return No meaningful return value; emits an advisory warning.
#' @keywords internal
#' @noRd
state_warn_old_openssl <- function() {
  warn_pkg(
    "Upgrade openssl to version 2.6.0 or later",
    c(
      "i" = "shinyOAuth is using authenticated AES-CBC-HMAC compatibility mode because openssl < 2.6.0 is installed.",
      "i" = 'Run install.packages("openssl") and restart R to use authenticated AES-GCM.'
    ),
    class = "shinyOAuth_openssl_upgrade_warning",
    .frequency = "once",
    .frequency_id = "shinyOAuth-openssl-upgrade"
  )
}

#' Derive separate CBC-HMAC keys for version 3 state envelopes
#'
#' @param key Normalized 32-byte state key.
#' @return Named list with raw MAC and encryption keys.
#' @keywords internal
#' @noRd
state_cbc_hmac_keys <- function(key) {
  cek <- as.raw(openssl::sha512(
    charToRaw("shinyOAuth:state:v3:A256CBC-HS512"), key = key
  ))
  split_jwe_cbc_hmac_cek(cek, "A256CBC-HS512")
}

#' Authenticate a version 3 state envelope using RFC 7518 section 5.2
#'
#' @param ct Raw ciphertext.
#' @param iv Raw initialization vector.
#' @param mac_key Raw 32-byte MAC key.
#' @return Raw 32-byte authentication tag.
#' @keywords internal
#' @noRd
state_cbc_hmac_tag <- function(ct, iv, mac_key) {
  compute_compact_jwe_auth_tag(
    "A256CBC-HS512",
    mac_key,
    base64url_encode(charToRaw('{"v":3,"enc":"A256CBC-HS512"}')),
    iv,
    ct
  )
}

#' Internal: encrypt a state payload into an authenticated envelope
#'
#' Uses AES-GCM on openssl >= 2.6.0 and AES-256-CBC-HMAC-SHA512 on older
#' releases. Returns a base64url-wrapped token containing version, IV, tag,
#' and ciphertext. Used when login state is created before redirect.
#'
#' @param payload State payload to encrypt.
#' @param key Character passphrase or raw key material.
#' @param version Optional envelope version: 2 for GCM or 3 for CBC-HMAC.
#'   By default, selects GCM on openssl >= 2.6.0 and CBC-HMAC on older releases.
#' @param min_key_chars Minimum passphrase length for character keys.
#' @return Compact encrypted state token string.
#' @keywords internal
#' @noRd
state_encrypt_gcm <- function(payload, key, version = NULL, min_key_chars = 32L) {
  if (is.null(payload)) {
    err_input(c("x" = "payload is NULL"), context = list(phase = "encrypt"))
  }
  key <- normalize_key32(key, min_chars = min_key_chars)
  gcm_available <- state_openssl_gcm_available()
  version <- if (is.null(version)) {
    if (gcm_available) 2L else 3L
  } else {
    normalize_state_envelope_version(version)
  }
  if (is.na(version) || !version %in% c(2L, 3L)) {
    err_input("New state envelopes must use version 2 or 3")
  }
  if (version == 2L && !gcm_available) {
    err_config("AES-GCM state encryption requires openssl >= 2.6.0")
  }

  json <- jsonlite::toJSON(
    payload,
    auto_unbox = TRUE,
    digits = NA,
    null = "null"
  )
  if (!is_valid_string(json)) {
    err_input(
      c("x" = "payload serialized to empty JSON string"),
      context = list(phase = "encrypt")
    )
  }

  if (version == 2L) {
    iv <- openssl::rand_bytes(12L)
    enc <- openssl::aes_gcm_encrypt(charToRaw(json), key = key, iv = iv)
    if (!is.raw(enc)) {
      err_config(
        "Unexpected ciphertext from aes_gcm_encrypt()",
        context = list(phase = "encrypt")
      )
    }
    tag <- attr(enc, "tag", exact = TRUE)
    if (!is.raw(tag) || length(tag) != 16L) {
      err_config(
        "AES-GCM encryption requires a 16-byte authentication tag",
        context = list(phase = "encrypt")
      )
    }
  } else {
    if (!gcm_available) state_warn_old_openssl()
    keys <- state_cbc_hmac_keys(key)
    iv <- openssl::rand_bytes(16L)
    enc <- openssl::aes_cbc_encrypt(charToRaw(json), key = keys[["enc_key"]], iv = iv)
    if (!is.raw(enc) || !length(enc) || length(enc) %% 16L != 0L) {
      err_config(
        "Unexpected ciphertext from aes_cbc_encrypt()",
        context = list(phase = "encrypt")
      )
    }
    tag <- state_cbc_hmac_tag(enc, iv, keys[["mac_key"]])
  }

  token_obj <- list(
    v = as.integer(version),
    iv = base64url_encode(iv),
    tg = base64url_encode(tag),
    ct = base64url_encode(enc)
  )
  base64url_encode(charToRaw(jsonlite::toJSON(token_obj, auto_unbox = TRUE)))
}

#' Normalize a state-envelope version
#'
#' @param value Candidate version value.
#' @return A non-negative integer or `NA_integer_` when invalid.
#' @keywords internal
#' @noRd
normalize_state_envelope_version <- function(value) {
  if (
    !is.numeric(value) ||
      length(value) != 1L ||
      is.na(value) ||
      !is.finite(value) ||
      value < 0 ||
      value > .Machine[["integer.max"]] ||
      value != trunc(value)
  ) {
    return(NA_integer_)
  }
  as.integer(value)
}

#' Internal: decrypt and validate an authenticated state envelope
#'
#' Decodes the outer base64url wrapper, validates the version and envelope
#' members, verifies the authentication tag, and returns the parsed JSON
#' payload. The helper enforces size caps and emits audit events for parse
#' failures without disclosing plaintext or key material. Used when callback
#' handling resumes after the provider redirects back.
#'
#' @param token Compact encrypted state token.
#' @param key Character passphrase or raw key material.
#' @param expected_version Optional expected envelope version. By default,
#'   versions 2 (AES-GCM) and 3 (AES-CBC-HMAC) are accepted. Version 2 requires
#'   an openssl API that verifies GCM tags. Version 1 is always rejected.
#' @param size_limits Optional internal envelope budgets; external state uses
#'   the configured state limits by default.
#' @param min_key_chars Minimum passphrase length for character keys.
#' @return Parsed decrypted state payload list.
#' @keywords internal
#' @noRd
state_decrypt_gcm <- function(
  token,
  key,
  expected_version = NULL,
  min_key_chars = 32L,
  size_limits = NULL
) {
  # Hard caps
  max_token_chars <- get_option_env_positive_number(
    "shinyOAuth.state_max_token_chars",
    "shinyOAuth_STATE_MAX_TOKEN_CHARS",
    8192
  )
  max_wrapper_bytes <- get_option_env_positive_number(
    "shinyOAuth.state_max_wrapper_bytes",
    "shinyOAuth_STATE_MAX_WRAPPER_BYTES",
    8192
  )
  max_ct_b64_chars <- get_option_env_positive_number(
    "shinyOAuth.state_max_ct_b64_chars",
    "shinyOAuth_STATE_MAX_CT_B64_CHARS",
    8192
  )
  max_ct_bytes <- get_option_env_positive_number(
    "shinyOAuth.state_max_ct_bytes",
    "shinyOAuth_STATE_MAX_CT_BYTES",
    8192
  )
  if (!is.null(size_limits)) {
    stopifnot(
      is.list(size_limits),
      length(size_limits) == 4L,
      all(vapply(
        size_limits,
        function(x) {
          is.numeric(x) &&
            length(x) == 1L &&
            is.finite(x) &&
            x > 0
        },
        logical(1)
      ))
    )
    max_token_chars <- size_limits[["token"]]
    max_wrapper_bytes <- size_limits[["wrapper"]]
    max_ct_b64_chars <- size_limits[["ct_b64"]]
    max_ct_bytes <- size_limits[["ct"]]
  }

  # Internal helper: emit an audit event for a parse or decrypt failure.
  # Used only by `state_decrypt_gcm()` so failure reasons are logged without
  # leaking plaintext or key material.
  # @param reason_code Stable failure reason.
  # @param details Additional redacted context fields.
  # @return No return value; emits a best-effort audit event and returns
  #   invisibly.
  audit_fail <- function(reason_code, details = list()) {
    ctx <- c(
      list(
        phase = "decrypt",
        reason = as.character(reason_code),
        token_digest = try(string_digest(token), silent = TRUE)
      ),
      details
    )
    # Best-effort: never interfere with control flow
    try(audit_event("state_parse_failure", context = ctx), silent = TRUE)
    invisible(NULL)
  }

  state_fail <- state_decrypt_fail

  if (!is_valid_string(token)) {
    audit_fail("token_not_string")
    state_fail(
      "token must be a non-empty single string",
      context = list(phase = "decrypt")
    )
  }
  # Preemptively cap the base64url string length to avoid excessive decode work
  token_len <- nchar(token, type = "bytes")
  if (token_len > max_token_chars) {
    audit_fail(
      "token_b64_too_large",
      details = list(length = token_len, limit = max_token_chars)
    )
    state_fail(
      "state token too large",
      context = list(phase = "decrypt", where = "token_b64")
    )
  }
  key <- normalize_key32(key, min_chars = min_key_chars)

  decoded <- try(base64url_decode_raw(token), silent = TRUE)
  if (inherits(decoded, "try-error")) {
    audit_fail("token_b64_invalid")
    state_fail(
      "state token is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  # Cap decoded wrapper size before JSON parsing
  if (length(decoded) > max_wrapper_bytes) {
    audit_fail(
      "token_wrapper_too_large",
      details = list(length = length(decoded), limit = max_wrapper_bytes)
    )
    state_fail(
      "state token wrapper too large",
      context = list(phase = "decrypt", where = "wrapper_raw")
    )
  }
  # JSON text cannot contain embedded NUL bytes. Without this guard,
  # rawToChar() may truncate at NUL and accidentally accept appended garbage.
  if (any(decoded == as.raw(0))) {
    audit_fail("token_payload_embedded_nul")
    state_fail(
      "state token payload is not valid JSON",
      context = list(phase = "decrypt")
    )
  }
  payload_json <- try(rawToChar(decoded), silent = TRUE)
  if (
    inherits(payload_json, "try-error") ||
      !isTRUE(validUTF8(payload_json))
  ) {
    audit_fail("token_payload_utf8_invalid")
    state_fail(
      "state token payload is not valid UTF-8",
      context = list(phase = "decrypt")
    )
  }
  Encoding(payload_json) <- "UTF-8"
  obj <- try(
    {
      reject_duplicate_json_object_members(payload_json, "State envelope JSON")
      jsonlite::parse_json(payload_json, simplifyVector = FALSE)
    },
    silent = TRUE
  )
  # Ensure predictable structure: must be a named list (not data.frame)
  if (
    inherits(obj, "try-error") ||
      !is.list(obj) ||
      is.data.frame(obj) ||
      is.null(names(obj))
  ) {
    audit_fail("token_payload_json_invalid")
    state_fail(
      "state token payload is not valid JSON",
      context = list(phase = "decrypt")
    )
  }
  found_version <- normalize_state_envelope_version(obj[["v"]])
  expected_version <- if (is.null(expected_version)) {
    c(2L, 3L)
  } else {
    normalize_state_envelope_version(expected_version)
  }
  if (
    is.na(found_version) ||
      anyNA(expected_version) ||
      !found_version %in% c(2L, 3L) ||
      !found_version %in% expected_version
  ) {
    audit_fail(
      "token_version_mismatch",
      details = list(
        found_version = found_version,
        expected_version = expected_version
      )
    )
    state_fail(
      "state token version mismatch",
      context = list(phase = "decrypt")
    )
  }

  if (!is_valid_string(obj[["iv"]])) {
    audit_fail("iv_missing")
    state_fail("state token missing IV", context = list(phase = "decrypt"))
  }
  iv <- try(base64url_decode_raw(obj[["iv"]]), silent = TRUE)
  if (inherits(iv, "try-error")) {
    audit_fail("iv_b64_invalid")
    state_fail(
      "state token IV is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  iv_bytes <- if (found_version == 2L) 12L else 16L
  tag_bytes <- if (found_version == 2L) 16L else 32L
  if (length(iv) != iv_bytes) {
    audit_fail("iv_len_invalid", details = list(iv_len = length(iv)))
    state_fail(
      sprintf("invalid state IV length: %d", length(iv)),
      context = list(phase = "decrypt")
    )
  }
  if (!is_valid_string(obj[["tg"]])) {
    audit_fail("tag_missing")
    state_fail("state token missing tag", context = list(phase = "decrypt"))
  }
  tg <- try(base64url_decode_raw(obj[["tg"]]), silent = TRUE)
  if (inherits(tg, "try-error")) {
    audit_fail("tag_b64_invalid")
    state_fail(
      "state token tag is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  if (length(tg) != tag_bytes) {
    audit_fail("tag_len_invalid", details = list(tag_len = length(tg)))
    state_fail(
      sprintf("invalid state tag length: %d", length(tg)),
      context = list(phase = "decrypt")
    )
  }
  if (!is_valid_string(obj[["ct"]])) {
    audit_fail("ciphertext_missing")
    state_fail(
      "state token missing ciphertext",
      context = list(phase = "decrypt")
    )
  }
  # Cap ciphertext base64 length before attempting to decode
  ct_b64_len <- try(
    nchar(obj[["ct"]], type = "bytes"),
    silent = TRUE
  )
  if (
    !inherits(ct_b64_len, "try-error") &&
      is.numeric(ct_b64_len) &&
      ct_b64_len > max_ct_b64_chars
  ) {
    audit_fail(
      "ciphertext_b64_too_large",
      details = list(length = ct_b64_len, limit = max_ct_b64_chars)
    )
    state_fail(
      "state token ciphertext too large",
      context = list(phase = "decrypt", where = "ct_b64")
    )
  }
  ct <- try(base64url_decode_raw(obj[["ct"]]), silent = TRUE)
  if (inherits(ct, "try-error")) {
    audit_fail("ciphertext_b64_invalid")
    state_fail(
      "state token ciphertext is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  if (length(ct) < 1L) {
    audit_fail("ciphertext_empty")
    state_fail("empty ciphertext", context = list(phase = "decrypt"))
  }
  # Cap decoded ciphertext size before authentication and decryption.
  if (length(ct) > max_ct_bytes) {
    audit_fail(
      "ciphertext_too_large",
      details = list(length = length(ct), limit = max_ct_bytes)
    )
    state_fail(
      "state token ciphertext too large",
      context = list(phase = "decrypt", where = "ct_raw")
    )
  }

  auth_fail <- function() {
    audit_fail("state_auth_failed")
    state_fail(
      c(
        "x" = "State authentication failed",
        "!" = "This often indicates the state key/secret does not match the one used to encrypt the state (e.g., OAuthClient created inside a Shiny session so the key changes on redirect/new session, different Shiny worker, or rotated secret)."
      ),
      context = list(phase = "decrypt")
    )
  }
  if (found_version == 3L) {
    keys <- state_cbc_hmac_keys(key)
    expected_tag <- state_cbc_hmac_tag(ct, iv, keys[["mac_key"]])
    # Verify before CBC decryption so unauthenticated input cannot reach
    # padding checks or the native decryption error path.
    if (!constant_time_compare(tg, expected_tag) || length(ct) %% 16L != 0L) {
      auth_fail()
    }
    res <- try(
      openssl::aes_cbc_decrypt(data = ct, key = keys[["enc_key"]], iv = iv),
      silent = TRUE
    )
  } else {
    if (
      !state_openssl_gcm_available() ||
        !"tag" %in% names(formals(openssl::aes_gcm_decrypt))
    ) {
      audit_fail("gcm_tag_api_unavailable")
      state_fail(
        "Version 2 state requires openssl >= 2.6.0 for authenticated GCM decryption; upgrade openssl or restart authorization.",
        context = list(phase = "decrypt")
      )
    }
    res <- try(
      openssl::aes_gcm_decrypt(data = ct, tag = tg, key = key, iv = iv),
      silent = TRUE
    )
  }
  if (inherits(res, "try-error")) {
    auth_fail()
  }
  # Decrypted wrapper payload is JSON text; reject embedded NULs to avoid
  # truncation-acceptance edge cases.
  if (any(res == as.raw(0))) {
    audit_fail("decrypted_payload_embedded_nul")
    state_fail(
      c(
        "x" = "state token decrypted payload is not valid JSON",
        "!" = "This can happen if the state key/secret is wrong (e.g., OAuthClient created inside a Shiny session so the key changes on redirect/new session, different Shiny worker, or rotated secret); the decrypted bytes won't decode as JSON."
      ),
      context = list(phase = "decrypt")
    )
  }
  parsed <- try(
    {
      payload_json <- rawToChar(res)
      if (!isTRUE(validUTF8(payload_json))) {
        err_parse("Decrypted state JSON contains invalid UTF-8")
      }
      Encoding(payload_json) <- "UTF-8"
      reject_duplicate_json_object_members(payload_json, "Decrypted state JSON")
      jsonlite::parse_json(payload_json, simplifyVector = FALSE)
    },
    silent = TRUE
  )
  if (
    inherits(parsed, "try-error") || !is.list(parsed) || is.data.frame(parsed)
  ) {
    audit_fail("decrypted_json_invalid")
    state_fail(
      c(
        "x" = "state token decrypted payload is not valid JSON",
        "!" = "This can happen if the state key/secret is wrong (e.g., OAuthClient created inside a Shiny session so the key changes on redirect/new session, different Shiny worker, or rotated secret); the decrypted bytes won't decode as JSON."
      ),
      context = list(phase = "decrypt")
    )
  }
  # Normalize and validate decrypted payload shape
  # - Must be a named list so downstream validation can rely on names
  if (is.null(names(parsed))) {
    audit_fail("decrypted_json_unnamed_list")
    state_fail(
      "state token decrypted payload must be an object with named fields",
      context = list(phase = "decrypt")
    )
  }
  # Scopes are expected downstream as a character vector; preserve empty as character(0)
  if (!is.null(parsed[["scopes"]])) {
    sc <- parsed[["scopes"]]
    # If parsed with simplifyVector = FALSE, JSON arrays become lists; convert list-of-length-one strings to character vector
    if (is.list(sc)) {
      ok <- vapply(
        sc,
        function(el) is.character(el) && length(el) == 1L && !is.na(el),
        logical(1)
      )
      if (length(sc) == 0L) {
        parsed[["scopes"]] <- character()
      } else if (all(ok)) {
        parsed[["scopes"]] <- vapply(
          sc,
          function(el) as.character(el),
          character(1)
        )
      } else if (is.character(sc)) {
        # no-op
      } else {
        # Leave as-is; downstream validation will reject incompatible types
        parsed[["scopes"]] <- sc
      }
    } else if (is.null(sc)) {
      parsed[["scopes"]] <- character()
    } else if (is.character(sc)) {
      # already character vector
    } else {
      # Any other type left as-is for downstream validators to handle
    }
  }
  parsed
}

# 2 State cache keys -----------------------------------------------------------

#' Derive a cache key for an OAuth state value
#'
#' cachem only allows lowercase letters and digits in keys. We preserve the
#' original high-entropy state (mixed-case base64url) in the encrypted payload
#' and store/retrieve associated data under a deterministic lowercase-hex
#' SHA-256 of that state.
#'
#' @param state OAuth state string.
#' @return Lowercase hex cache key.
#' @keywords internal
#' @noRd
state_cache_key <- function(state) {
  if (!is.character(state) || length(state) != 1L || !nzchar(state)) {
    # Audit malformed state identifiers used for cache lookups
    try(
      audit_event(
        "state_parse_failure",
        context = list(
          phase = "cache_key",
          reason = "state_not_string",
          state_digest = try(string_digest(state), silent = TRUE)
        )
      ),
      silent = TRUE
    )
    err_invalid_state(
      "state_cache_key: state must be a non-empty single string",
      context = list(phase = "cache_key")
    )
  }
  raw_to_hex_lower(openssl::sha256(charToRaw(state)))
}
