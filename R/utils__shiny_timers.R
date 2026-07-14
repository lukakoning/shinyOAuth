# 1 Timer scheduling ------------------------------------------------------------

#' Convert seconds to a safe Shiny timer delay
#'
#' Converts a finite duration in seconds to milliseconds and caps long waits at
#' the largest R integer. Callers therefore re-evaluate long-lived boundaries in
#' bounded chunks instead of passing an overflowing integer to Shiny.
#'
#' @param seconds Finite duration in seconds.
#' @param buffer_seconds Finite buffer added before conversion.
#' @param minimum_ms Minimum returned delay in milliseconds.
#' @return A finite numeric delay in milliseconds.
#' @keywords internal
#' @noRd
shiny_timer_delay_ms <- function(
  seconds,
  buffer_seconds = 0,
  minimum_ms = 100
) {
  stopifnot(
    is.numeric(seconds),
    length(seconds) == 1L,
    is.finite(seconds),
    is.numeric(buffer_seconds),
    length(buffer_seconds) == 1L,
    is.finite(buffer_seconds),
    is.numeric(minimum_ms),
    length(minimum_ms) == 1L,
    is.finite(minimum_ms),
    minimum_ms >= 0
  )

  milliseconds <- (seconds + buffer_seconds) * 1000
  max(minimum_ms, min(milliseconds, as.double(.Machine$integer.max)))
}


# 2 Proactive refresh pacing ---------------------------------------------------

#' Compute the delay after refreshing a short-lived token
#'
#' @param token Refreshed OAuth token.
#' @param now Current Unix timestamp in seconds.
#' @param lead_seconds Configured proactive refresh lead time.
#' @return Delay in seconds before another refresh may begin.
#' @keywords internal
#' @noRd
proactive_refresh_success_delay <- function(token, now, lead_seconds) {
  expires_at <- tryCatch(token@expires_at, error = function(...) NA_real_)
  lifetime <- expires_at - now
  if (!is.finite(lifetime) || lifetime <= 0 || lifetime > lead_seconds) {
    return(0)
  }

  max(1, lifetime / 2)
}

#' Compute a bounded proactive-refresh failure backoff
#'
#' @param failure_count Number of consecutive failures.
#' @param retry_after Server-requested delay in seconds, when available.
#' @param jitter Proportional jitter from zero through one.
#' @return Delay in seconds before another refresh may begin.
#' @keywords internal
#' @noRd
proactive_refresh_failure_delay <- function(
  failure_count,
  retry_after = NA_real_,
  jitter = stats::runif(1)
) {
  exponent <- min(max(as.integer(failure_count) - 1L, 0L), 8L)
  delay <- min(2^exponent, 300)
  if (is.finite(retry_after) && retry_after >= 0) {
    delay <- max(delay, retry_after)
  }

  min(delay * (1 + 0.25 * jitter), 3600)
}

#' Extract Retry-After from an HTTP error condition
#'
#' @param condition Error condition raised by an HTTP request.
#' @return Retry delay in seconds, or `NA_real_` when unavailable.
#' @keywords internal
#' @noRd
refresh_condition_retry_after <- function(condition) {
  response <- tryCatch(condition[["response"]], error = function(...) NULL)
  if (is.null(response)) {
    response <- attr(condition, "response", exact = TRUE)
  }
  if (is.null(response)) {
    return(NA_real_)
  }

  parse_retry_after_header(response)
}
