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
#' RFC 6749 \u00a75.1 says `expires_in` is RECOMMENDED. When it is absent we check
#' `options(shinyOAuth.default_expires_in)` for a configurable fallback (seconds).
#' If the option is absent or invalid, shinyOAuth falls back to 3600 seconds.
#' A once-per-phase warning is emitted either way so operators know the value
#' was not server-provided.
#'
#' @return Numeric scalar: computed `expires_at` (epoch seconds).
#' @keywords internal
#' @noRd
resolve_missing_expires_in <- function(phase = NULL) {
  phase_msg <- if (is_valid_string(phase)) {
    paste0(" (phase: ", phase, ")")
  } else {
    ""
  }

  package_default_ei <- 3600
  option_ei <- getOption("shinyOAuth.default_expires_in", NULL)
  option_ei_num <- suppressWarnings(as.numeric(option_ei))

  if (
    !is.null(option_ei) &&
      length(option_ei_num) == 1L &&
      is.finite(option_ei_num) &&
      option_ei_num > 0
  ) {
    fallback_ei <- option_ei_num
    fallback_msg <- paste0(
      "Using `options(shinyOAuth.default_expires_in = ",
      fallback_ei,
      ")` as fallback"
    )
  } else {
    fallback_ei <- package_default_ei
    fallback_msg <- paste0(
      "Using shinyOAuth's default fallback of ",
      package_default_ei,
      " seconds"
    )

    if (!is.null(option_ei)) {
      fallback_msg <- paste0(
        "Ignoring invalid `options(shinyOAuth.default_expires_in)`; ",
        fallback_msg
      )
    }
  }

  rlang::warn(
    c(
      format_header("Token response missing expires_in"),
      "!" = paste0(
        "The token response did not include an expires_in value",
        phase_msg
      ),
      "i" = fallback_msg,
      "i" = "Set `options(shinyOAuth.default_expires_in = <seconds>)` to override this fallback",
      "i" = "See RFC 6749 \u00a75.1: expires_in is RECOMMENDED"
    ),
    class = "shinyOAuth_missing_expires_in",
    .frequency = "once",
    .frequency_id = paste0(
      "expires_in_missing",
      if (is_valid_string(phase)) paste0("-", phase) else ""
    )
  )

  as.numeric(Sys.time()) + fallback_ei
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
