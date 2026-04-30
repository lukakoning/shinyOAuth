# This file contains the low-level base64url helpers used by JWT, JWKS, DPoP,
# and sealed state code.
# Use them when binary data needs the URL-safe base64 encoding required by many
# OAuth and OpenID Connect specs.

# 1 Base64url helpers ------------------------------------------------------

## 1.1 Encode and decode ---------------------------------------------------

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

# Decode a base64url string into raw bytes.
# Used by JWT, JWKS, and cryptographic helpers. Input: base64url string.
# Output: raw vector.
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

# Decode a base64url string into text while rejecting embedded NUL bytes.
# Used when base64url content should become UTF-8-like text. Input: base64url
# string. Output: character string.
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
