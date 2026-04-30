# This file contains small cryptographic utility helpers that other auth and
# state helpers build on.
# Use them for safe raw-to-hex conversion and constant-time comparisons in
# places where token or signature material should not leak through timing.

# 1 Cryptographic primitives -----------------------------------------------

## 1.1 Raw and comparison helpers -----------------------------------------

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

#' Internal: compare two values using a timing-blinded path
#'
#' Character inputs are converted to raw bytes; invalid inputs are treated as a
#' mismatch but still pass through the same SHA-256 and accumulator path so the
#' caller does not branch on type- or length-based timing differences.
#'
#' @keywords internal
#' @noRd
constant_time_compare <- function(a, b) {
  # Normalize one input into raw bytes before the blinded comparison path.
  # Used only by constant_time_compare(). Input: character or raw value.
  # Output: raw vector or NULL.
  normalize_input <- function(x) {
    if (is.raw(x) && !is.null(x)) {
      return(x)
    }

    if (is.character(x) && length(x) == 1L && !is.na(x)) {
      return(charToRaw(as.character(x)))
    }

    NULL
  }

  a_raw <- normalize_input(a)
  b_raw <- normalize_input(b)
  if (is.null(a_raw) || is.null(b_raw)) {
    # Treat invalid inputs as a mismatch but keep the blinded comparison path.
    a_raw <- raw()
    b_raw <- as.raw(0L)
  }

  ar <- openssl::sha256(a_raw)
  br <- openssl::sha256(b_raw)

  acc <- as.integer(0L)
  for (i in seq_len(length(ar))) {
    ai <- as.integer(ar[[i]])
    bi <- as.integer(br[[i]])
    acc <- bitwOr(acc, bitwXor(ai, bi))
  }

  isTRUE(identical(acc, 0L))
}
