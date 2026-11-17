# The upgrade notice is asserted in test-state-crypto-selection.R. Consume it
# before unrelated tests exercise authenticated state on older openssl.
if (!shinyOAuth:::state_openssl_gcm_available()) {
  suppressWarnings(shinyOAuth:::state_warn_old_openssl())
}
