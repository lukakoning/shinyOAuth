# Throw an error if any softening options that relax default safety
# protections are enabled
# Below call does not error if run with default options:
error_on_softened()

# Below call would error (is therefore not run):
\dontrun{
options(shinyOAuth.skip_id_sig = TRUE)
error_on_softened()
}
