# error_on_softened() is deprecated and checks only the options in its help page.
# Use startup checks for the exact settings your deployment permits.

# Default options pass this check:
error_on_softened()

# This call would raise an error:
if (interactive()) {
  (function() {
    old <- options(shinyOAuth.skip_id_sig = TRUE)
    on.exit(options(old), add = TRUE)
    error_on_softened()
  })()
}
