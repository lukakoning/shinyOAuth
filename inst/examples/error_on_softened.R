# Throw an error if any developer-only softening options are enabled
# Below call does not error if run with default options:
error_on_softened()

# Below call would error (is therefore not run):
\dontrun{
options(shinyOAuth.skip_id_sig = TRUE)
error_on_softened()
}
