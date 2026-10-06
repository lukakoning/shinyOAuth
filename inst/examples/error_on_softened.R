# Note: error_on_softened() is deprecated because it only checks a narrow subset
# of shinyOAuth's security-relaxing options

# Throw an error if one of the options listed in ?error_on_softened is enabled.
# Below call does not error if run with default options:
error_on_softened()

# Below call would error (is therefore not run):
if (interactive()) {
  (function() {
    old <- options(shinyOAuth.skip_id_sig = TRUE)
    on.exit(options(old), add = TRUE)
    error_on_softened()
  })()
}
