# Helpers to compute non-reversible digests for sensitive strings (tokens, ids)
# By default uses HMAC-SHA256 with a per-process key to prevent correlation
# if audit logs leak. Set shinyOAuth.audit_digest_key = FALSE to disable keying.
string_digest <- function(x, key = get_audit_digest_key()) {
  # Normalize to a length-1 character scalar for consistent hashing
  if (is.null(x) || length(x) == 0) {
    return(NA_character_)
  }
  # Use only the first element if vector provided
  x1 <- x[[1L]]
  # Coerce to character before nzchar to avoid type errors (e.g., numeric ids)
  x_chr <- tryCatch(as.character(x1), error = function(...) NA_character_)
  if (!is_valid_string(x_chr)) {
    return(NA_character_)
  }
  raw_x <- charToRaw(x_chr)
  dig <- if (!is.null(key) && length(key) > 0) {
    # Keyed HMAC-SHA256: prevents correlation if logs leak
    tryCatch(
      openssl::sha256(raw_x, key = key),
      error = function(...) NULL
    )
  } else {
    # Unkeyed SHA-256: deterministic across processes (legacy behavior)
    tryCatch(openssl::sha256(raw_x), error = function(...) NULL)
  }

  if (is.null(dig)) {
    return(NA_character_)
  }
  paste0(sprintf("%02x", as.integer(dig)), collapse = "")
}

# Per-process key for audit digests. Auto-generated on first access.
# Set `options(shinyOAuth.audit_digest_key = FALSE)` to disable keying.
# Set to a fixed raw/character value to correlate digests across processes.
audit_digest_key_env <- new.env(parent = emptyenv())

get_audit_digest_key <- function() {
  opt <- getOption("shinyOAuth.audit_digest_key")

  # Explicitly disable keying
  if (identical(opt, FALSE)) {
    return(NULL)
  }

  # Check for explicit user-supplied key
  if (!is.null(opt)) {
    # User supplied a key; coerce to raw if character
    if (is.character(opt)) {
      return(charToRaw(paste(opt, collapse = "")))
    }
    if (is.raw(opt)) {
      return(opt)
    }
    # Invalid type: fall through to auto-generate with warning
    rlang::warn(
      c(
        "Invalid `shinyOAuth.audit_digest_key` type; must be character or raw.",
        i = "Falling back to auto-generated per-process key."
      ),
      .frequency = "once",
      .frequency_id = "shinyOAuth.audit_digest_key_invalid"
    )
  }

  # Auto-generate per-process key on first call
  if (is.null(audit_digest_key_env$key)) {
    audit_digest_key_env$key <- openssl::rand_bytes(32L)
  }
  audit_digest_key_env$key
}
