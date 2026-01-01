#' Generate a cryptographically secure URL-safe random string
#'
#' @description
#' Internal helper to produce a random string suitable for OAuth state and
#' OIDC nonce values. Uses `openssl::rand_bytes()` for cryptographic entropy
#' then encodes with base64url and strips any padding. The result is truncated
#' to the requested length.
#'
#' @param n Length of output string (default 32). Recommended >= 16.
#'
#' @return A length-1 character string composed of URL-safe Base64 characters
#'   (A-Z, a-z, 0-9, '-', '_').
#'
#' @keywords internal
#' @noRd
random_urlsafe <- function(n = 32) {
  if (!is.numeric(n) || length(n) != 1 || is.na(n) || !is.finite(n) || n <= 0) {
    err_input("n must be a positive numeric scalar")
  }
  # Generate >= n bytes then base64url encode and trim to n characters
  # 3 raw bytes -> 4 base64 chars, so need ceiling(n * 3 / 4) bytes
  needed_bytes <- ceiling(n * 3 / 4)
  raw <- openssl::rand_bytes(needed_bytes)
  # Canonical base64url encoding without padding or line breaks
  b64 <- base64url_encode(raw)
  # Defensive: ensure no CR/LF artifacts before truncation
  b64 <- gsub("[\r\n]", "", b64, perl = TRUE)
  substr(b64, 1, n)
}

#' Generate a cryptographically random OIDC nonce
#'
#' @keywords internal
#' @noRd
gen_oidc_nonce <- function(length = 32) {
  random_urlsafe(length)
}

#' Validate OAuth/OIDC nonce
#'
#' A nonce should be a high-entropy, URL-safe string. We accept the RFC 3986
#' "unreserved" characters: \[A-Z\] / \[a-z\] / \[0-9\] / "-" / "." / "_" / "~".
#' To approximate >=128 bits of entropy for base64url-like strings, we require
#' a minimum length of 22 characters. Max is capped at 255.
#'
#' @keywords internal
#' @noRd
validate_oidc_nonce <- function(nonce, min_chars = 22, max_chars = 255) {
  if (length(nonce) != 1) {
    err_pkce("nonce must be a length-1 string")
  }
  if (!is.character(nonce)) {
    err_pkce("nonce must be character")
  }
  if (!is_valid_string(nonce)) {
    err_pkce("nonce missing or empty")
  }

  n <- nchar(nonce, type = "bytes")
  if (n < min_chars || n > max_chars) {
    err_pkce(sprintf(
      "nonce length must be between %d and %d characters",
      min_chars,
      max_chars
    ))
  }

  # Unreserved characters per RFC 3986
  if (!grepl('^[A-Za-z0-9._~-]+$', nonce)) {
    err_pkce("nonce contains invalid characters (allowed: A-Z a-z 0-9 - . _ ~)")
  }

  invisible(TRUE)
}

#' Generate a RFC 7636 PKCE code_verifier
#'
#' @keywords internal
#' @noRd
gen_code_verifier <- function(n = 64) {
  # RFC 7636 requires 43-128 chars from unreserved set
  if (!is.numeric(n) || length(n) != 1 || is.na(n) || n < 43 || n > 128) {
    err_pkce("n must be between 43 and 128")
  }
  # Use cryptographically secure randomness: generate URL-safe base64 string
  # comprised of [A-Za-z0-9-_] which is a subset of the allowed unreserved
  # characters [A-Za-z0-9-._~] per RFC 7636.
  v <- random_urlsafe(n)
  validate_code_verifier(v)
  v
}

#' Validate PKCE code verifier per RFC 7636
#'
#' A code_verifier is a high-entropy cryptographic random string using the
#' characters \[A-Z\] / \[a-z\] / \[0-9\] / "-" / "." / "_" / "~" with a minimum
#' length of 43 characters and a maximum length of 128 characters.
#'
#' @keywords internal
#' @noRd
validate_code_verifier <- function(verifier) {
  if (length(verifier) != 1) {
    err_pkce("code_verifier must be length-1 string")
  }
  if (!is.character(verifier)) {
    err_pkce("code_verifier must be character")
  }
  if (!is_valid_string(verifier)) {
    err_pkce("code_verifier missing or empty")
  }
  n <- nchar(verifier, type = "bytes")
  if (n < 43 || n > 128) {
    err_pkce("code_verifier length must be between 43 and 128 characters")
  }
  if (!grepl('^[A-Za-z0-9._~-]+$', verifier)) {
    err_pkce("code_verifier contains invalid characters")
  }
  invisible(TRUE)
}

#' Validate browser token (shinyOAuth_sid)
#'
#' JS sets a 64-byte random token encoded as lowercase hex
#' (128 chars, \[0-9a-f\]). Enforce lowercase only to match JS
#' and avoid accepting mixed/uppercase variants.
#'
#' @param token String to validate (e.g., input$shinyOAuth_sid)
#' @param expected_bytes Expected number of random bytes before hex-encoding.
#'   Defaults to 64 to match the JS `randomHex(64)` call.
#'
#' @keywords internal
#' @noRd
validate_browser_token <- function(token, expected_bytes = 64L) {
  if (length(token) != 1) {
    err_pkce("browser token must be a length-1 string")
  }
  if (!is.character(token)) {
    err_pkce("browser token must be character")
  }
  if (!is_valid_string(token)) {
    err_pkce("browser token missing or empty")
  }

  if (isTRUE(allow_skip_browser_token()) && identical(token, "__SKIPPED__")) {
    # When testing
    return(invisible(TRUE))
  }

  expected_len <- as.integer(2L * expected_bytes)
  n <- nchar(token, type = "bytes")
  if (n != expected_len) {
    err_pkce(sprintf(
      "browser token must be %d hex characters (got %d)",
      expected_len,
      n
    ))
  }

  # Enforce lowercase hex only to match browser generation
  pat <- sprintf("^[a-f0-9]{%d}$", expected_len)
  if (!grepl(pat, token)) {
    err_pkce(
      "browser token must contain only lowercase hex characters (0-9, a-f)"
    )
  }

  invisible(TRUE)
}

#' Validate OAuth2 "state" value
#'
#' The `state` parameter should be an opaque, high-entropy, URL-safe string.
#' We accept RFC 3986 "unreserved" characters:
#'   \[A-Z\] / \[a-z\] / \[0-9\] / "-" / "." / "_" / "~".
#' To approximate >=128 bits of entropy for base64url-like strings (~6 bits/char),
#' the default minimum length is 22 characters. Upper bound is conservative.
#'
#' @param state String to validate.
#' @param min_chars Minimum allowed length. Default 22 (~128 bits for base64url-like).
#' @param max_chars Maximum allowed length. Default 255.
#' @param strict_base64url If TRUE, restrict to base64url charset only
#'   (`[A-Za-z0-9_-]`) rather than the full RFC 3986 unreserved set.
#'
#' @keywords internal
#' @noRd
validate_state <- function(
  state,
  min_chars = 22L,
  max_chars = 255L,
  strict_base64url = FALSE
) {
  if (length(state) != 1) {
    err_pkce("state must be a length-1 string")
  }
  if (!is.character(state)) {
    err_pkce("state must be character")
  }
  if (!is_valid_string(state)) {
    err_pkce("state missing or empty")
  }

  n <- nchar(state, type = "bytes")
  if (n < min_chars || n > max_chars) {
    err_pkce(sprintf(
      "state length must be between %d and %d characters",
      min_chars,
      max_chars
    ))
  }

  # Allowed characters
  pat <- if (isTRUE(strict_base64url)) {
    # base64url charset only
    "^[A-Za-z0-9_-]+$"
  } else {
    # RFC 3986 "unreserved"
    "^[A-Za-z0-9._~-]+$"
  }
  if (!grepl(pat, state)) {
    msg <- if (isTRUE(strict_base64url)) {
      "state contains invalid characters (allowed: A-Z a-z 0-9 - _)"
    } else {
      "state contains invalid characters (allowed: A-Z a-z 0-9 - . _ ~)"
    }
    err_pkce(msg)
  }

  invisible(TRUE)
}
