#' Internal: drop NULL/NA values from a list (for query building)
#' @keywords internal
#' @noRd
compact_list <- function(x) {
  if (!is.list(x)) {
    return(x)
  }
  x[
    !vapply(
      x,
      function(v) is.null(v) || (length(v) == 1 && is.na(v)),
      logical(1)
    )
  ]
}

#' Internal: check if input is a non-empty string
#'
#' @keywords internal
#' @noRd
is_valid_string <- function(x, min_char = 1) {
  is.character(x) &&
    length(x) == 1 &&
    !is.na(x) &&
    nzchar(x) &&
    nchar(x) >= min_char
}

#' Internal: validate untrusted scalar query param sizes
#'
#' This helper is used for values that originate from URL query strings.
#' It is intentionally strict about scalar-ness to avoid vector amplification.
#'
#' @keywords internal
#' @noRd
validate_untrusted_query_param <- function(
  name,
  value,
  max_bytes,
  allow_empty = FALSE
) {
  if (is.null(value)) {
    return(invisible(NULL))
  }

  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' must be a single string", name),
      context = list(param = name)
    )
  }

  if (!isTRUE(allow_empty) && !nzchar(value)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' must be non-empty", name),
      context = list(param = name)
    )
  }

  max_bytes <- as.numeric(max_bytes)
  if (!is.finite(max_bytes) || is.na(max_bytes) || max_bytes <= 0) {
    err_invalid_state(
      "Internal error: invalid max_bytes in query param validator",
      context = list(param = name)
    )
  }

  actual_bytes <- nchar(value, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' had invalid length", name),
      context = list(param = name)
    )
  }

  if (actual_bytes > max_bytes) {
    err_invalid_state(
      sprintf(
        "Callback query parameter '%s' exceeded maximum length (%s bytes)",
        name,
        format(max_bytes, scientific = FALSE, trim = TRUE)
      ),
      context = list(
        param = name,
        max_bytes = max_bytes,
        actual_bytes = actual_bytes
      )
    )
  }

  invisible(NULL)
}

#' Internal: validate untrusted callback query string sizes
#'
#' This helper guards against extremely large callback query strings causing
#' substantial allocation during parsing.
#'
#' @keywords internal
#' @noRd
validate_untrusted_query_string <- function(query_string, max_bytes) {
  if (is.null(query_string)) {
    return(invisible(NULL))
  }

  if (
    !is.character(query_string) ||
      length(query_string) != 1L ||
      is.na(query_string)
  ) {
    err_invalid_state(
      "Callback query string must be a single string",
      context = list(component = "query_string")
    )
  }

  max_bytes <- as.numeric(max_bytes)
  if (!is.finite(max_bytes) || is.na(max_bytes) || max_bytes <= 0) {
    err_invalid_state(
      "Internal error: invalid max_bytes in query string validator",
      context = list(component = "query_string")
    )
  }

  actual_bytes <- nchar(query_string, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_invalid_state(
      "Callback query string had invalid length",
      context = list(component = "query_string")
    )
  }

  if (actual_bytes > max_bytes) {
    err_invalid_state(
      sprintf(
        "Callback query string exceeded maximum length (%s bytes)",
        format(max_bytes, scientific = FALSE, trim = TRUE)
      ),
      context = list(
        component = "query_string",
        max_bytes = max_bytes,
        actual_bytes = actual_bytes
      )
    )
  }

  invisible(NULL)
}

#' Internal: read a positive numeric scalar option
#'
#' Returns `default` when the option is unset or invalid.
#'
#' @keywords internal
#' @noRd
get_option_positive_number <- function(name, default) {
  val <- getOption(name, NULL)
  if (is.null(val)) {
    return(as.numeric(default))
  }

  val <- suppressWarnings(as.numeric(val))
  if (!is.numeric(val) || length(val) != 1L || is.na(val) || !is.finite(val)) {
    return(as.numeric(default))
  }
  if (val <= 0) {
    return(as.numeric(default))
  }
  val
}

# Internal: safely coerce to scalar character or NA
.scalar_chr <- function(x) {
  if (is.null(x) || length(x) == 0) {
    return(NA_character_)
  }
  as.character(x[[1]])
}

#' Internal: coerce expires_in to numeric more tolerantly
#'
#' Some providers return `expires_in` as a quoted string (e.g., in
#' form-encoded responses) and may include leading zeros ("0003600") or a
#' trailing decimal ("3600.0"). This helper converts:
#' - digit-only strings to numeric directly; and
#' - other numeric-like strings to numeric when they parse to a finite
#'   non-negative number.
#' Other inputs are returned unchanged so upstream validation can handle them.
#'
#' @keywords internal
#' @noRd
coerce_expires_in <- function(x) {
  # Already numeric or NULL -> return as is
  if (is.null(x) || is.numeric(x)) {
    return(x)
  }
  # Only coerce length-1, non-NA character strings
  if (is.character(x) && length(x) == 1L && !is.na(x)) {
    sx <- trimws(x)
    # Fast-path for digit-only strings (allows leading zeros)
    if (grepl("^[0-9]+$", sx)) {
      return(as.numeric(sx))
    }
    # Fallback: try parsing other numeric-like strings (e.g., "3600.0")
    num <- suppressWarnings(as.numeric(sx))
    if (length(num) == 1L && !is.na(num) && is.finite(num) && num >= 0) {
      return(num)
    }
  }
  x
}

#' Internal: normalize client state cache max_age to a positive scalar
#'
#' Falls back to 5 minutes (300s) when the cache backend does not expose a
#' finite `max_age` via `$info()`.
#'
#' When falling back, emits a once-per-session warning to help operators
#' understand that browser cookie lifetimes will use the default rather than
#' the cache's TTL.
#'
#' @keywords internal
#' @noRd
client_state_store_max_age <- function(client, default = 300) {
  max_age_raw <- tryCatch(
    client@state_store$info(),
    error = function(...) NULL
  )

  max_age <- suppressWarnings(
    tryCatch(
      as.numeric(max_age_raw$max_age),
      error = function(...) NA_real_
    )
  )

  if (length(max_age) != 1L || !is.finite(max_age) || max_age <= 0) {
    fallback <- suppressWarnings(as.numeric(default))
    if (length(fallback) != 1L || !is.finite(fallback) || fallback <= 0) {
      # Final guard: default to 300s to align with built-in cache_mem default
      fallback <- 300
    }

    # Emit a concise once-per-session warning with guidance
    st_class <- try(class(client@state_store)[1], silent = TRUE)
    st_class <- if (!inherits(st_class, "try-error") && length(st_class) == 1) {
      st_class
    } else {
      NULL
    }
    rlang::warn(
      c(
        format_header("State store TTL not detected"),
        "!" = paste0(
          "client@state_store$info()$max_age was not a finite positive number; ",
          "falling back to default cookie lifetime of ",
          fallback,
          "s"
        ),
        "i" = paste0(
          "To align the browser cookie with your cache TTL, ensure your state_store ",
          "exposes {.code info()$max_age} or configure {.code cachem::cache_mem(max_age = ...)}"
        ),
        if (!is.null(st_class)) {
          paste0("i State store class: ", st_class)
        } else {
          NULL
        }
      ),
      .frequency = "once",
      .frequency_id = "state_store_max_age_fallback"
    )

    return(fallback)
  }

  max_age
}

#' Internal: resolve expires_at when expires_in is absent from the token response
#'
#' RFC 6749 §5.1 says `expires_in` is RECOMMENDED. When it is absent we check
#' `options(shinyOAuth.default_expires_in)` for a configurable fallback (seconds).
#' If neither is available, falls back to `Inf`, meaning proactive refresh will
#' never trigger. A once-per-phase warning is emitted either way so operators
#' know the value was not server-provided.
#'
#' @return Numeric scalar: computed `expires_at` (epoch seconds or `Inf`).
#' @keywords internal
#' @noRd
resolve_missing_expires_in <- function(phase = NULL) {
  phase_msg <- if (is_valid_string(phase)) {
    paste0(" (phase: ", phase, ")")
  } else {
    ""
  }

  # Check configurable fallback
  default_ei <- getOption("shinyOAuth.default_expires_in", NULL)
  if (!is.null(default_ei)) {
    default_ei <- suppressWarnings(as.numeric(default_ei))
    if (
      length(default_ei) == 1L &&
        is.finite(default_ei) &&
        default_ei > 0
    ) {
      rlang::warn(
        c(
          format_header("Token response missing expires_in"),
          "!" = paste0(
            "The token response did not include an expires_in value",
            phase_msg
          ),
          "i" = paste0(
            "Using options(shinyOAuth.default_expires_in = ",
            default_ei,
            ") as fallback"
          ),
          "i" = "See RFC 6749 \u00a75.1: expires_in is RECOMMENDED"
        ),
        class = "shinyOAuth_missing_expires_in",
        .frequency = "once",
        .frequency_id = paste0(
          "expires_in_missing",
          if (is_valid_string(phase)) paste0("-", phase) else ""
        )
      )
      return(as.numeric(Sys.time()) + default_ei)
    }
  }

  rlang::warn(
    c(
      format_header("Token response missing expires_in"),
      "!" = paste0(
        "The token response did not include an expires_in value",
        phase_msg,
        "; assuming infinite token lifetime"
      ),
      "i" = "Proactive token refresh will not trigger without a known expiry",
      "i" = "Set options(shinyOAuth.default_expires_in = <seconds>) to supply a fallback",
      "i" = "See RFC 6749 \u00a75.1: expires_in is RECOMMENDED"
    ),
    class = "shinyOAuth_missing_expires_in",
    .frequency = "once",
    .frequency_id = paste0(
      "expires_in_missing",
      if (is_valid_string(phase)) paste0("-", phase) else ""
    )
  )

  Inf
}

#' Internal: warn when expires_in is non-positive
#'
#' `expires_in <= 0` is technically valid (meaning "expires now"), but is often
#' surprising and can indicate a provider/configuration issue.
#'
#' @keywords internal
#' @noRd
warn_about_nonpositive_expires_in <- function(expires_in, phase = NULL) {
  if (is.null(expires_in)) {
    return(invisible(FALSE))
  }

  if (
    !is.numeric(expires_in) ||
      length(expires_in) != 1L ||
      !is.finite(expires_in)
  ) {
    return(invisible(FALSE))
  }

  if (expires_in > 0) {
    return(invisible(FALSE))
  }

  phase_msg <- if (is_valid_string(phase)) {
    paste0(" (phase: ", phase, ")")
  } else {
    ""
  }

  rlang::warn(
    c(
      format_header("Token expires immediately"),
      "!" = paste0(
        "Token response returned expires_in = ",
        expires_in,
        ", so the token is immediately expired",
        phase_msg
      ),
      "i" = "This is unusual and may indicate provider misconfiguration"
    ),
    .frequency = "once",
    .frequency_id = paste0(
      "expires_in_nonpositive",
      if (is_valid_string(phase)) paste0("-", phase) else ""
    )
  )

  invisible(TRUE)
}

#' Internal: normalize state payload freshness window (issued_at) to seconds
#'
#' This is intentionally independent of the state store TTL. The state store TTL
#' controls server-side single-use state caching and browser cookie max-age;
#' this value controls how old the decrypted state payload's `issued_at` is
#' allowed to be.
#'
#' @keywords internal
#' @noRd
client_state_payload_max_age <- function(client, default = 300) {
  max_age <- suppressWarnings(as.numeric(client@state_payload_max_age))

  if (length(max_age) != 1L || !is.finite(max_age) || max_age <= 0) {
    fallback <- suppressWarnings(as.numeric(default))
    if (length(fallback) != 1L || !is.finite(fallback) || fallback <= 0) {
      fallback <- 300
    }
    return(fallback)
  }

  max_age
}

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
# Set options(shinyOAuth.audit_digest_key = FALSE) to disable keying.
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
