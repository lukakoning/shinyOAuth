# Bearer and DPoP credentials use the b64token syntax from RFC 6750 section 2.1.
# Check bytes and the entire value: in particular, never trim or repair secrets.
is_valid_access_token <- function(value) {
  is_valid_string(value) &&
    grepl("^[A-Za-z0-9._~+/-]+=*$", value, useBytes = TRUE)
}
