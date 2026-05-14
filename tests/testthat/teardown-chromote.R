if (requireNamespace("chromote", quietly = TRUE)) {
  try(
    {
      if (chromote::has_default_chromote_object()) {
        chromote::default_chromote_object()$close()
        chromote::set_default_chromote_object(NULL)
      }
    },
    silent = TRUE
  )
}

unlink(
  list.files(
    tempdir(),
    pattern = "^com\\.google\\.Chrome",
    full.names = TRUE,
    all.files = TRUE
  ),
  recursive = TRUE,
  force = TRUE
)
