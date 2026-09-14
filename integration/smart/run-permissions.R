run_permissions <- function() {
  root <- normalizePath(".", winslash = "/")
  source("integration/smart/helper-inferno.R", local = TRUE)
  source("integration/smart/helper-inferno-browser.R", local = TRUE)
  source("integration/connections/helper-browser.R", local = TRUE)
  source("integration/smart/helper-permissions.R", local = TRUE)
  output <- file.path(root, "integration/smart/.artifacts", paste0("permissions-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(status = "failed", server = "Microsoft FHIR Server 5.0.58",
    server_modified = FALSE, authorization_server = "synthetic SMART fixture",
    unmodified_external_smart_interoperability = "not_established", scenarios = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  app_port <- httpuv::randomPort()
  app_tls <- inferno_tls(root, app_port)
  stack <- permissions_start(root, output, app_tls$origin)
  evidence$provenance <- stack$provenance
  for (index in 1:2) evidence$scenarios[[index]] <-
    permissions_case(root, output, stack, app_tls, app_port, index == 2L, index)
  stopifnot(length(evidence$scenarios) == 2L,
    all(vapply(evidence$scenarios, function(row) isTRUE(row$passed), logical(1))))
  evidence$status <- "passed"
  cat("Protected FHIR: two browser scenarios passed against Microsoft FHIR Server.\n")
}
run_permissions()
