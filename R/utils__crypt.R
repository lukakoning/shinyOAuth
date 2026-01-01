# Authenticated encrypt/decrypt of the state payload ---------------------------

# Normalize/derive a 32-byte key with basic checks
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

state_encrypt_gcm <- function(payload, key, version = 1L, min_key_chars = 32L) {
  if (is.null(payload)) {
    err_input(c("x" = "payload is NULL"), context = list(phase = "encrypt"))
  }
  key <- normalize_key32(key, min_chars = min_key_chars)

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

  iv <- openssl::rand_bytes(12L) # 96-bit IV for GCM

  enc <- openssl::aes_gcm_encrypt(charToRaw(json), key = key, iv = iv)

  # Handle both return shapes (list with $data/$tag or raw(ct||tag))
  if (is.list(enc) && !is.null(enc$data) && !is.null(enc$tag)) {
    ct <- enc$data
    tag <- enc$tag
  } else if (is.raw(enc) && !is.null(attr(enc, "tag", exact = TRUE))) {
    # Some versions return ciphertext as raw with tag attribute
    ct <- enc
    tag <- attr(enc, "tag", exact = TRUE)
    if (!is.raw(tag) || length(tag) != 16L) {
      err_config(
        c("x" = "Unexpected GCM tag attribute length"),
        context = list(phase = "encrypt")
      )
    }
  } else if (is.raw(enc)) {
    n <- length(enc)
    if (n < 16L) {
      err_invalid_state(
        c("x" = "ciphertext too short"),
        context = list(phase = "encrypt")
      )
    }
    if (n == 16L) {
      # zero-length ciphertext, tag only
      tag <- enc
      ct <- raw(0)
    } else {
      tag <- enc[(n - 15L):n]
      ct <- enc[1:(n - 16L)]
    }
  } else {
    err_config(
      c("x" = "Unexpected return type from aes_gcm_encrypt()"),
      context = list(phase = "encrypt")
    )
  }

  token_obj <- list(
    v = as.integer(version),
    iv = b64url_encode(iv),
    tg = b64url_encode(tag),
    ct = b64url_encode(ct)
  )
  b64url_encode(charToRaw(jsonlite::toJSON(token_obj, auto_unbox = TRUE)))
}

state_decrypt_gcm <- function(
  token,
  key,
  expected_version = 1L,
  min_key_chars = 32L
) {
  # Configurable defensive limits (options or env var fallback)
  # Defaults chosen to comfortably exceed real-world usage yet block DoS-size inputs.
  get_limit <- function(opt_name, env_name, default) {
    # Priority: option > env var > default
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

  # Hard caps
  max_token_chars <- get_limit(
    "shinyOAuth.state_max_token_chars",
    "shinyOAuth_STATE_MAX_TOKEN_CHARS",
    8192
  )
  max_wrapper_bytes <- get_limit(
    "shinyOAuth.state_max_wrapper_bytes",
    "shinyOAuth_STATE_MAX_WRAPPER_BYTES",
    8192
  )
  max_ct_b64_chars <- get_limit(
    "shinyOAuth.state_max_ct_b64_chars",
    "shinyOAuth_STATE_MAX_CT_B64_CHARS",
    8192
  )
  max_ct_bytes <- get_limit(
    "shinyOAuth.state_max_ct_bytes",
    "shinyOAuth_STATE_MAX_CT_BYTES",
    8192
  )

  # Local helper: emit a non-sensitive audit event for parse failures
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

  # Local helper: introduce tiny randomized delay before failing
  # Goal: reduce timing side-channels between different failure modes
  # Tuning: options(shinyOAuth.state_fail_delay_ms = c(min_ms, max_ms))
  #  - default jitter ~10-30ms; set to 0 or NULL to disable if needed (e.g., tests)
  delay_before_fail <- function() {
    bounds <- getOption("shinyOAuth.state_fail_delay_ms", c(10, 30))
    # Sanitize option input; accept numeric scalar or length-2 vector (ms)
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
      # Convert ms -> seconds
      Sys.sleep(ms / 1000)
    }
    invisible(NULL)
  }

  # Wrapper to normalize all state failures from this function
  state_fail <- function(msg, context = list()) {
    delay_before_fail()
    err_invalid_state(msg, context = context)
  }

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

  decoded <- try(b64url_decode(token), silent = TRUE)
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
  payload_json <- try(rawToChar(decoded), silent = TRUE)
  if (inherits(payload_json, "try-error")) {
    audit_fail("token_payload_utf8_invalid")
    state_fail(
      "state token payload is not valid UTF-8",
      context = list(phase = "decrypt")
    )
  }
  obj <- try(
    jsonlite::fromJSON(payload_json, simplifyVector = FALSE),
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
  if (!identical(as.integer(obj$v), as.integer(expected_version))) {
    audit_fail(
      "token_version_mismatch",
      details = list(
        found_version = as.integer(obj$v),
        expected_version = as.integer(expected_version)
      )
    )
    state_fail(
      "state token version mismatch",
      context = list(phase = "decrypt")
    )
  }

  if (!is_valid_string(obj$iv)) {
    audit_fail("iv_missing")
    state_fail("state token missing IV", context = list(phase = "decrypt"))
  }
  iv <- try(b64url_decode(obj$iv), silent = TRUE)
  if (inherits(iv, "try-error")) {
    audit_fail("iv_b64_invalid")
    state_fail(
      "state token IV is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  if (length(iv) != 12L) {
    audit_fail("iv_len_invalid", details = list(iv_len = length(iv)))
    state_fail(
      sprintf("invalid GCM IV length: %d", length(iv)),
      context = list(phase = "decrypt")
    )
  }
  if (!is_valid_string(obj$tg)) {
    audit_fail("tag_missing")
    state_fail("state token missing tag", context = list(phase = "decrypt"))
  }
  tg <- try(b64url_decode(obj$tg), silent = TRUE)
  if (inherits(tg, "try-error")) {
    audit_fail("tag_b64_invalid")
    state_fail(
      "state token tag is not valid base64",
      context = list(phase = "decrypt")
    )
  }
  if (length(tg) != 16L) {
    audit_fail("tag_len_invalid", details = list(tag_len = length(tg)))
    state_fail(
      sprintf("invalid GCM tag length: %d", length(tg)),
      context = list(phase = "decrypt")
    )
  }
  if (!is_valid_string(obj$ct)) {
    audit_fail("ciphertext_missing")
    state_fail(
      "state token missing ciphertext",
      context = list(phase = "decrypt")
    )
  }
  # Cap ciphertext base64 length before attempting to decode
  ct_b64_len <- try(nchar(obj$ct, type = "bytes"), silent = TRUE)
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
  ct <- try(b64url_decode(obj$ct), silent = TRUE)
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
  # Cap decoded ciphertext size to avoid expensive GCM on large inputs
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

  # 3-arg API expects data = ct||tag
  res <- try(
    openssl::aes_gcm_decrypt(data = c(ct, tg), key = key, iv = iv),
    silent = TRUE
  )
  if (inherits(res, "try-error")) {
    audit_fail("gcm_auth_failed")
    state_fail(
      c(
        "x" = "GCM authentication failed",
        "!" = "This often indicates the state key/secret does not match the one used to encrypt the state (e.g., OAuthClient created inside a Shiny session so the key changes on redirect/new session, different Shiny worker, or rotated secret)."
      ),
      context = list(phase = "decrypt")
    )
  }
  parsed <- try(
    jsonlite::fromJSON(rawToChar(res), simplifyVector = FALSE),
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
  if (!is.null(parsed$scopes)) {
    sc <- parsed$scopes
    # If parsed with simplifyVector = FALSE, JSON arrays become lists; convert list-of-length-one strings to character vector
    if (is.list(sc)) {
      ok <- vapply(
        sc,
        function(el) is.character(el) && length(el) == 1L && !is.na(el),
        logical(1)
      )
      if (length(sc) == 0L) {
        parsed$scopes <- character()
      } else if (all(ok)) {
        parsed$scopes <- vapply(sc, function(el) as.character(el), character(1))
      } else if (is.character(sc)) {
        # no-op
      } else {
        # Leave as-is; downstream validation will reject incompatible types
        parsed$scopes <- sc
      }
    } else if (is.null(sc)) {
      parsed$scopes <- character()
    } else if (is.character(sc)) {
      # already character vector
    } else {
      # Any other type left as-is for downstream validators to handle
    }
  }
  parsed
}


# Helpers for cache-safe keys -------------------------------------------------

#' Derive a cache key for an OAuth state value
#'
#' cachem only allows lowercase letters and digits in keys. We preserve the
#' original high-entropy state (mixed-case base64url) in the encrypted payload
#' and store/retrieve associated data under a deterministic lowercase-hex
#' SHA-256 of that state.
#'
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

#' Convert raw vector to lowercase hex string (cachem-safe)
#'
#' @keywords internal
#' @noRd
raw_to_hex_lower <- function(r) {
  if (!is.raw(r)) {
    err_input(
      "raw_to_hex_lower requires a raw vector",
      context = list(phase = "cache_key")
    )
  }
  paste0(as.character(r), collapse = "")
}

# Timing-safe equality --------------------------------------------------------

#' Constant-time comparison for secrets
#'
#' Compare two strings in a way that does not leak information via timing
#' differences from early exits or character-by-character mismatch. Inputs are
#' coerced to character(1) with NA/NULL treated as a mismatch.
#'
#' To reduce length-dependent timing differences, both inputs are first hashed
#' with SHA-256 to produce fixed 32-byte digests. The function then performs a
#' constant-time XOR-accumulate comparison over those digests.
#'
#' This helper is intended for comparing short secret values like browser
#' tokens, nonces, or state-bound identifiers. It operates on raw byte values
#' and does not perform normalization; callers should ensure the same encoding
#' is used on both sides (we expect native UTF-8/ASCII for our use cases).
#'
#' @keywords internal
#' @noRd
constant_time_compare <- function(a, b) {
  # Normalize to single character scalars; everything else mismatches.
  is_valid <- function(x) is.character(x) && length(x) == 1L && !is.na(x)
  if (!is_valid(a) || !is_valid(b)) {
    # Treat invalid inputs as non-equal but still run blinded loop to avoid
    # observable timing differences between invalid and valid shapes.
    a <- as.character(NA)
    b <- as.character("")
  }

  # Hash both sides to fixed length (32 bytes) to blind original length.
  # Using openssl keeps consistency with the rest of the package.
  ar <- openssl::sha256(charToRaw(as.character(a)))
  br <- openssl::sha256(charToRaw(as.character(b)))

  # Constant-time compare over fixed 32-byte digests.
  acc <- as.integer(0L)
  for (i in seq_len(length(ar))) {
    ai <- as.integer(ar[[i]])
    bi <- as.integer(br[[i]])
    acc <- bitwOr(acc, bitwXor(ai, bi))
  }
  # Equal iff accumulator is zero
  isTRUE(identical(acc, 0L))
}
