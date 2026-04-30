#' Internal base64url helpers
#'
#' Canonical helpers used across JWT, JWKS, state encryption, DPoP, and mTLS:
#' - base64url_encode(raw|character) -> base64url string (no padding)
#' - base64url_decode_raw(string) -> raw vector
#' - base64url_decode(string) -> UTF-8 text with embedded-NUL rejection
#'
#' @keywords internal
#' @noRd
base64url_encode <- function(raw_bytes) {
  # Disable line breaks to avoid embedded newlines in long encodings
  s <- openssl::base64_encode(raw_bytes, linebreak = FALSE)
  # Defensive: strip any CR/LF that might slip through from upstream inputs
  s <- gsub("[\r\n]", "", s, perl = TRUE)
  s <- sub("=+$", "", s)
  chartr("+/", "-_", s)
}

#' @keywords internal
#' @noRd
base64url_decode_raw <- function(x) {
  x <- chartr("-_", "+/", x)
  pad <- (4 - (nchar(x) %% 4)) %% 4
  if (pad > 0L) {
    x <- paste0(x, strrep("=", pad))
  }
  openssl::base64_decode(x)
}

#' @keywords internal
#' @noRd
base64url_decode <- function(x) {
  raw_bytes <- base64url_decode_raw(x)
  # Guard against embedded NUL bytes which would cause rawToChar() to silently
  # truncate the output. Mirrors the NUL hardening in utils__crypt.R.
  if (any(raw_bytes == as.raw(0))) {
    err_parse("base64url payload contains embedded NUL byte")
  }
  rawToChar(raw_bytes)
}
