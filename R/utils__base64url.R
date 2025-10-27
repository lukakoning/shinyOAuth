#' Internal base64url helpers (canonical)
#'
#' These helpers provide a single source of truth for base64url encoding/decoding
#' across the package. They are intentionally small wrappers around openssl's
#' base64 functions with URL-safe translation and padding handling.
#'
#' Provided helpers:
#' - b64url_encode(raw|character) -> base64url string (no padding)
#' - b64url_decode(string) -> raw vector
#' - base64url_encode(raw) -> base64url string (alias for b64url_encode)
#' - base64url_decode(string) -> character (UTF-8 text)
#' - base64url_decode_raw(string) -> raw vector
#'
#' @keywords internal
#' @noRd
b64url_encode <- function(x) {
  # Disable line breaks to avoid embedded newlines in long encodings
  s <- openssl::base64_encode(x, linebreak = FALSE)
  # Defensive: strip any CR/LF that might slip through from upstream inputs
  s <- gsub("[\r\n]", "", s, perl = TRUE)
  s <- sub("=+$", "", s)
  chartr("+/", "-_", s)
}

#' @keywords internal
#' @noRd
b64url_decode <- function(s) {
  s <- chartr("-_", "+/", s)
  pad <- (4 - (nchar(s) %% 4)) %% 4
  if (pad > 0L) {
    s <- paste0(s, strrep("=", pad))
  }
  openssl::base64_decode(s)
}

#' @keywords internal
#' @noRd
base64url_encode <- function(raw_bytes) {
  b64url_encode(raw_bytes)
}

#' @keywords internal
#' @noRd
base64url_decode <- function(x) {
  rawToChar(b64url_decode(x))
}

#' @keywords internal
#' @noRd
base64url_decode_raw <- function(x) {
  b64url_decode(x)
}
