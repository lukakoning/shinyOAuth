# Throw an error if any developer-only softening options are enabled
error_on_softened()

# Below call would error (code is not run because of that)
\dontrun{
options(shinyOAuth.skip_id_sig = TRUE)
error_on_softened()
}