run_inferno_extensions <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (length(args) != 1L || !args %in% c("identity", "account"))
    stop("Usage: Rscript integration/smart/run-inferno-extensions.R identity|account")
  root <- normalizePath(".", winslash = "/")
  for (file in c("helper-inferno-evidence.R", "helper-inferno.R", "helper-inferno-browser.R",
    "helper-inferno-exchanges.R", "helper-inferno-extensions.R", "helper-inferno-account.R"))
    source(file.path("integration/smart", file), local = TRUE)
  source("integration/connections/helper-browser.R", local = TRUE)
  output <- file.path(root, "integration/smart/.artifacts", paste0("inferno-", args, "-",
    format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(status = "failed", gate = args, simulator_modified = TRUE,
    unmodified_external_interoperability = "not_established", scenarios = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  evidence$provenance <- inferno_build(root, output)
  stack <- inferno_start(root, output)
  withr::local_envvar(CURL_CA_BUNDLE = stack$ca)
  if (args == "account") {
    second <- inferno_start(root, output, "b")
    for (index in 1:2) evidence$scenarios[[index]] <-
      inferno_account_case(root, output, list(a = stack, b = second), index == 2L, index)
    stopifnot(length(evidence$scenarios) == 2L,
      all(vapply(evidence$scenarios, function(row) isTRUE(row$passed), logical(1))))
    evidence$status <- "passed"
    cat("Inferno account: two scenarios, 20 upstream test passes.\n")
    return(invisible(evidence))
  }
  cases <- expand.grid(user_type = c("Patient", "RelatedPerson"), launch = c("standalone", "ehr"),
    async = c(FALSE, TRUE), stringsAsFactors = FALSE)
  for (index in seq_len(nrow(cases))) {
    row <- cases[index, ]
    message("Inferno identity: ", row$user_type, " / ", row$launch, " / async=", row$async)
    evidence$scenarios[[index]] <- inferno_identity_case(root, output, stack, row, index)
  }
  stopifnot(length(evidence$scenarios) == 8L,
    all(vapply(evidence$scenarios, function(row) isTRUE(row$verification$passed), logical(1))))
  evidence$status <- "passed"
  cat("Inferno identity: eight scenarios, 40 upstream test passes.\n")
}
run_inferno_extensions()
