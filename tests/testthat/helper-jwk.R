# jose 1.2.1 can include an ASN.1 sign-padding byte in exported RSA integers.
# Test issuers must publish minimal Base64urlUInt values (RFC 7518 Section 2).
write_test_jwk <- function(key) {
  jwk <- jsonlite::fromJSON(jose::write_jwk(key), simplifyVector = FALSE)
  if (identical(jwk$kty, "RSA")) {
    for (field in c("n", "e")) {
      bytes <- shinyOAuth:::base64url_decode_raw(jwk[[field]])
      while (length(bytes) > 1L && bytes[[1]] == as.raw(0)) {
        bytes <- bytes[-1L]
      }
      jwk[[field]] <- shinyOAuth:::base64url_encode(bytes)
    }
  }
  jsonlite::toJSON(jwk, auto_unbox = TRUE)
}
