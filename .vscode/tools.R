# This file defines a set of tools which are made available via MCP to
# allow agents (specifically, GitHub Copilot) to run common R package
# development tasks

# devtools helper to capture output and errors ---------------------------------

.devtools_capture <- function(expr) {
  res <- NULL
  err <- NULL
  out <- utils::capture.output(
    res <- tryCatch(
      force(expr),
      error = function(e) {
        err <<- e
        NULL
      }
    )
  )
  list(
    ok = is.null(err),
    output = paste(out, collapse = "\n"),
    error = if (!is.null(err)) conditionMessage(err) else NULL
  )
}


# devtools::check() ------------------------------------------------------------

run_check <- function(
  path = ".",
  cran = FALSE,
  remote = FALSE,
  manual = FALSE
) {
  stopifnot(requireNamespace("devtools", quietly = TRUE))
  .devtools_capture(devtools::check(
    path = path,
    cran = cran,
    remote = remote,
    manual = manual
  ))
}

tool_check <- ellmer::tool(
  run_check,
  name = "check_package",
  description = "Run devtools::check() (R CMD check) on the package.",
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    cran = ellmer::type_boolean("Run as if on CRAN (default FALSE)."),
    remote = ellmer::type_boolean("Run remote checks (default FALSE)."),
    manual = ellmer::type_boolean("Build manual (default FALSE).")
  ),
  annotations = ellmer::tool_annotations(
    title = "Package Check",
    read_only_hint = TRUE,
    open_world_hint = FALSE
  )
)


# devtools::document() ---------------------------------------------------------

run_document <- function(
  path = ".",
  roclets = NULL,
  quiet = TRUE
) {
  stopifnot(requireNamespace("devtools", quietly = TRUE))
  .devtools_capture(devtools::document(
    pkg = path,
    roclets = roclets,
    quiet = quiet
  ))
}

tool_document <- ellmer::tool(
  run_document,
  name = "document_package",
  description = "Run devtools::document() to rebuild Rd, NAMESPACE, etc.",
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    roclets = ellmer::type_array(
      "Optional vector of roclet names, e.g. c('rd','namespace')",
      items = ellmer::type_string("A roclet name")
    ),
    quiet = ellmer::type_boolean("Suppress output (default TRUE).")
  ),
  annotations = ellmer::tool_annotations(
    title = "Roxygen Document",
    read_only_hint = TRUE,
    open_world_hint = FALSE
  )
)


# devtools::install() ----------------------------------------------------------

run_install <- function(
  path = ".",
  upgrade = "never",
  build = FALSE,
  quick = FALSE,
  dependencies = FALSE
) {
  stopifnot(requireNamespace("devtools", quietly = TRUE))
  .devtools_capture(devtools::install(
    pkg = path,
    upgrade = upgrade,
    build = build,
    quick = quick,
    dependencies = dependencies
  ))
}

tool_install <- ellmer::tool(
  run_install,
  name = "install_package",
  description = "Install the package with devtools::install().",
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    upgrade = ellmer::type_string(
      "Dependency upgrade policy, e.g. 'never' (default), 'ask', 'always'."
    ),
    build = ellmer::type_boolean("Build before install (default FALSE)."),
    quick = ellmer::type_boolean(
      "Skip byte-compilation and docs (default FALSE)."
    ),
    dependencies = ellmer::type_boolean("Install deps (default FALSE).")
  ),
  annotations = ellmer::tool_annotations(
    title = "Install Package",
    read_only_hint = FALSE,
    idempotent_hint = TRUE,
    open_world_hint = FALSE
  )
)


# devtools::build() ------------------------------------------------------------

run_build <- function(
  path = ".",
  binary = FALSE,
  vignettes = FALSE,
  manual = FALSE
) {
  stopifnot(requireNamespace("devtools", quietly = TRUE))
  .devtools_capture(devtools::build(
    path = path,
    binary = binary,
    vignettes = vignettes,
    manual = manual
  ))
}

tool_build <- ellmer::tool(
  run_build,
  name = "build_package",
  description = "Build a source tarball (or binary) with devtools::build().",
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    binary = ellmer::type_boolean("Build binary (default FALSE)."),
    vignettes = ellmer::type_boolean("Build vignettes (default FALSE)."),
    manual = ellmer::type_boolean("Build manual (default FALSE).")
  ),
  annotations = ellmer::tool_annotations(
    title = "Build Package",
    read_only_hint = FALSE,
    idempotent_hint = TRUE,
    open_world_hint = FALSE
  )
)


# lintr::lint_package() --------------------------------------------------------

run_lint <- function(
  path = ".",
  linters_preset = "defaults", # "defaults" or "strict"
  exclusions = NULL # character vector
) {
  stopifnot(requireNamespace("lintr", quietly = TRUE))

  # choose a preset that's JSON-serializable to pass through tools
  linters <- switch(
    linters_preset,
    strict = lintr::linters_with_defaults(
      line_length_linter = lintr::line_length_linter(100),
      object_length_linter = lintr::object_length_linter(30),
      cyclocomp_linter = lintr::cyclocomp_linter(15)
    ),
    lintr::linters_with_defaults() # defaults
  )

  res <- NULL
  err <- NULL
  out <- utils::capture.output(
    res <- tryCatch(
      lintr::lint_package(
        path = path,
        linters = linters,
        exclusions = exclusions
      ),
      error = function(e) {
        err <<- e
        NULL
      }
    )
  )

  if (!is.null(err)) {
    return(list(
      ok = FALSE,
      output = paste(out, collapse = "\n"),
      error = conditionMessage(err)
    ))
  }

  if (length(res) == 0) {
    return(list(ok = TRUE, output = "No lints found.", error = NULL))
  }
  df <- data.frame(
    file = vapply(res, function(x) x$filename, ""),
    line = vapply(res, function(x) x$line_number, integer(1)),
    col = vapply(res, function(x) x$column_number, integer(1)),
    type = vapply(res, function(x) x$type, ""),
    msg = vapply(res, function(x) x$message, ""),
    stringsAsFactors = FALSE
  )
  txt <- paste(
    utils::capture.output(print(utils::head(df, 50))),
    collapse = "\n"
  )
  list(
    ok = TRUE,
    output = paste0("Lints (showing up to 50):\n", txt, "\nTotal: ", nrow(df)),
    error = NULL
  )
}

tool_lint <- ellmer::tool(
  run_lint,
  name = "lint_package",
  description = "Lint the package with lintr::lint_package(). Returns a summary table.",
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    linters_preset = ellmer::type_string(
      "Linters preset: 'defaults' (default) or 'strict'."
    ),
    exclusions = ellmer::type_array(
      "Character vector of file/dir paths to exclude.",
      items = ellmer::type_string("Path to exclude")
    )
  ),
  annotations = ellmer::tool_annotations(
    title = "Lint Package",
    read_only_hint = TRUE,
    open_world_hint = FALSE
  )
)


# devtools::test() / testthat --------------------------------------------------

run_testthat <- function(
  mode = c("all", "file", "dir"),
  path = ".",
  file = NULL,
  filter = NULL,
  reporter = "summary",
  stop_on_failure = FALSE,
  load_helpers = TRUE
) {
  stopifnot(requireNamespace("testthat", quietly = TRUE))
  mode <- match.arg(mode)

  .devtools_capture({
    if (mode == "all") {
      # Runs tests in a package, sourcing code (loads pkg automatically)
      testthat::test_local(
        path = path,
        reporter = reporter,
        filter = filter,
        stop_on_failure = stop_on_failure,
        load_helpers = load_helpers
      )
    } else if (mode == "dir") {
      # Ensure package is loaded, then run a subdir of tests
      stopifnot(requireNamespace("devtools", quietly = TRUE))
      devtools::load_all(path = path, helpers = load_helpers, quiet = TRUE)

      tests_path <- if (identical(path, ".")) {
        file.path(path, "tests", "testthat")
      } else {
        path
      }

      testthat::test_dir(
        path = tests_path,
        filter = filter,
        reporter = reporter,
        stop_on_failure = stop_on_failure,
        load_helpers = load_helpers
      )
    } else {
      # mode == "file": load pkg, then run a single test file
      if (is.null(file)) {
        stop("When mode = 'file', provide a test file path in `file`.")
      }
      stopifnot(requireNamespace("devtools", quietly = TRUE))
      devtools::load_all(path = path, helpers = load_helpers, quiet = TRUE)

      testthat::test_file(
        path = file,
        reporter = reporter,
        stop_on_failure = stop_on_failure
      )
    }
  })
}

tool_run_testthat <- ellmer::tool(
  run_testthat,
  name = "run_testthat",
  description = "Run testthat tests (all/file/dir). Uses test_local for 'all' and load_all before 'dir'/'file' so the package is loaded.",
  arguments = list(
    mode = ellmer::type_string("One of 'all', 'file', 'dir'."),
    path = ellmer::type_string(
      "Package root (default '.') for 'all'. For 'dir', either '.' or a tests dir like 'tests/testthat'."
    ),
    file = ellmer::type_string("Single test file path (for 'file')."),
    filter = ellmer::type_string("Regex to select tests (for 'all'/'dir')."),
    reporter = ellmer::type_string("Reporter, e.g. 'summary', 'progress'."),
    stop_on_failure = ellmer::type_boolean(
      "Stop on first failure (default FALSE)."
    ),
    load_helpers = ellmer::type_boolean("Load helpers.R (default TRUE).")
  ),
  annotations = ellmer::tool_annotations(
    title = "Run testthat",
    read_only_hint = TRUE,
    open_world_hint = FALSE
  )
)


# covr::poackage_coverage() ----------------------------------------------------

compute_code_coverage <- function(
  path = ".",
  report_format = c("json", "cobertura", "sonarqube"),
  output_file = NULL,           # if provided, write the machine-readable report here
  type = c("tests"),            # e.g. c("tests"), c("tests","examples")
  build_html = FALSE,           # optionally also build covr::report() HTML
  html_file = NULL              # defaults to file.path(path, "coverage.html") if build_html = TRUE
) {
  stopifnot(requireNamespace("covr", quietly = TRUE))

  report_format <- match.arg(report_format)

  # Only needed for JSON output
  if (identical(report_format, "json")) {
    stopifnot(requireNamespace("jsonlite", quietly = TRUE))
  }

  res <- NULL
  err <- NULL
  out <- utils::capture.output(
    res <- tryCatch({
      # Compute coverage
      cov <- covr::package_coverage(path = path, type = type)
      pct <- tryCatch(
        covr::percent_coverage(cov),
        error = function(e) NA_real_
      )

      header <- if (is.finite(pct)) {
        sprintf("Coverage: %.1f%%", pct)
      } else {
        "Coverage: (percent unavailable)"
      }

      # Build machine-readable payload
      payload <- switch(
        report_format,
        cobertura = covr::to_cobertura(cov),
        sonarqube = covr::to_sonarqube(cov),
        json = jsonlite::toJSON(covr::coverage_to_list(cov), auto_unbox = TRUE)
      )

      # Optionally write machine-readable report to disk
      if (!is.null(output_file)) {
        con <- file(output_file, open = "w", encoding = "UTF-8")
        on.exit(close(con), add = TRUE)
        writeLines(as.character(payload), con)
      }

      # Optionally create an HTML report (nice for manual inspection)
      if (isTRUE(build_html)) {
        if (is.null(html_file)) {
          html_file <- file.path(normalizePath(path), "coverage.html")
        }
        covr::report(cov, file = html_file, browse = FALSE)
        header <- paste0(header, "\nHTML report: ", html_file)
      }

      list(
        ok = TRUE,
        output = paste(header, "", as.character(payload), sep = "\n"),
        error = NULL
      )
    }, error = function(e) {
      err <<- e
      NULL
    })
  )

  if (!is.null(err)) {
    return(list(
      ok = FALSE,
      output = paste(out, collapse = "\n"),
      error = conditionMessage(err)
    ))
  }

  res
}

tool_compute_code_coverage <- ellmer::tool(
  compute_code_coverage,
  name = "compute_code_coverage",
  description = paste(
    "Compute package test coverage (covr) and emit a machine-readable report.",
    "Defaults to JSON printed to console; can also write SonarQube or Cobertura XML.",
    "Optionally builds an HTML report via covr::report()."
  ),
  arguments = list(
    path = ellmer::type_string("Path to package (default '.')."),
    report_format = ellmer::type_string(
      "One of 'json' (default), 'sonarqube', or 'cobertura'."
    ),
    output_file = ellmer::type_string(
      "Optional path to write the machine-readable report; if omitted, it is printed."
    ),
    type = ellmer::type_array(
      "Coverage types to include, e.g. c('tests') or c('tests','examples').",
      items = ellmer::type_string("Coverage type")
    ),
    build_html = ellmer::type_boolean(
      "Also build an HTML report with covr::report() (default FALSE)."
    ),
    html_file = ellmer::type_string(
      "Where to write the HTML report if build_html=TRUE (default 'coverage.html' in package root)."
    )
  ),
  annotations = ellmer::tool_annotations(
    title = "Code Coverage",
    read_only_hint = TRUE,
    open_world_hint = FALSE
  )
)


# Export -----------------------------------------------------------------------

# Export a list for registering all tools at once
tools_devtools <- list(
  check_package = tool_check,
  document_package = tool_document,
  install_package = tool_install,
  build_package = tool_build,,
  lint_package = tool_lint,
  run_testthat = tool_run_testthat,
  compute_code_coverage = tool_compute_code_coverage
)
