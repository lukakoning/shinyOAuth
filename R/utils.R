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
string_digest <- function(x) {
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
  dig <- try(openssl::sha256(charToRaw(x_chr)), silent = TRUE)
  if (inherits(dig, "try-error")) {
    return(NA_character_)
  }
  paste0(sprintf("%02x", as.integer(dig)), collapse = "")
}
