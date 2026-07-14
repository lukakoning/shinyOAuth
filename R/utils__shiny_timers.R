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
