# This file contains the helpers that hash sensitive values before they are
# written to audit logs or telemetry
# Used for keeping identifiers stable enough for correlation without logging
# them in plain text

# 1 Audit digests --------------------------------------------------------------

## 1.1 Digest helpers ----------------------------------------------------------

#' Compute a digest for a sensitive string
#'
#' Hashes one value for audit or telemetry use. By default this uses HMAC-SHA256
#' with a per-process key so digests stay stable within one process without
#' becoming globally correlatable if logs leak. Used by audit and telemetry
#' helpers.
#'
#' @param x Value to digest. Only the first element is used.
#' @param key Optional raw or character key returned by
#'   `get_audit_digest_key()`. Set the corresponding option to `FALSE` to
#'   disable keying.
#' @return A lowercase hex digest string, or `NA_character_` when `x` cannot be
#'   reduced to a valid scalar string.
#' @keywords internal
#' @noRd
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

#' Resolve the audit digest key
#'
#' Returns the configured digest key, coercing character values to raw bytes and
#' lazily generating a per-process key when no explicit option has been set.
#' Used by `string_digest()`.
#'
#' @return A raw vector containing the digest key, or `NULL` when keyed digests
#'   are disabled.
#' @keywords internal
#' @noRd
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
    warn_pkg(
      "Invalid `shinyOAuth.audit_digest_key` option",
      c(
        "!" = "`shinyOAuth.audit_digest_key` must be a character scalar or raw vector.",
        "i" = "Falling back to an auto-generated per-process key."
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
