# Run from the repository root. --existing uses the documented manual project;
# otherwise the runner owns a unique, disposable Compose project and volume.
run_smart_sandbox <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!all(args %in% c("--existing", "--require-compatible-discovery"))) {
    stop(
      "Usage: Rscript integration/smart/run-tests.R [--existing] [--require-compatible-discovery]"
    )
  }
  if (
    !requireNamespace("shinyOAuth", quietly = TRUE) ||
      !"smart_discover" %in% getNamespaceExports("shinyOAuth")
  ) {
    stop(
      "Install this checkout of shinyOAuth before running the SMART discovery suite"
    )
  }
  compose_file <- normalizePath(
    "integration/smart/docker-compose.yml",
    winslash = "/"
  )
  source("integration/smart/helper-sandbox.R", local = TRUE)
  existing <- "--existing" %in% args
  project <- if (existing) {
    "shinyoauth-smart-dev"
  } else {
    paste0(
      "shinyoauth-smart-test-",
      Sys.getpid(),
      "-",
      paste(sample(c(letters, 0:9), 8, TRUE), collapse = "")
    )
  }
  docker <- function(args, check = TRUE) {
    result <- processx::run(
      "docker",
      args,
      error_on_status = FALSE,
      timeout = 600000
    )
    if (check && result$status != 0L) {
      stop(paste(
        c("Docker command failed:", result$stderr, result$stdout),
        collapse = "\n"
      ))
    }
    result
  }
  compose <- function(args, check = TRUE) {
    docker(c("compose", "-f", compose_file, "-p", project, args), check = check)
  }
  docker_version <- trimws(
    docker(c("info", "--format", "{{.ServerVersion}}"))$stdout
  )
  compose(c("config", "--quiet"))
  if (!existing) {
    # This project name is generated here. Cleanup never targets another stack.
    on.exit(
      {
        cleanup <- compose(
          c("down", "--volumes", "--timeout", "10"),
          check = FALSE
        )
        if (cleanup$status != 0L) {
          warning("Sandbox cleanup failed: ", cleanup$stderr)
        }
      },
      add = TRUE
    )
    message(
      "Starting SMART sandbox project ",
      project,
      " (first pull may take several minutes)"
    )
    compose(c("up", "-d"))
  }

  urls <- smart_sandbox_urls()
  ready_urls <- c(
    paste0(urls$raw_fhir, "/metadata"),
    paste0(urls$fhir, "/.well-known/smart-configuration"),
    urls$picker
  )
  deadline <- Sys.time() + 300
  message("Waiting for FHIR R4, SMART discovery and the patient picker")
  repeat {
    ready <- vapply(
      ready_urls,
      function(url) {
        tryCatch(
          httr2::resp_status(smart_sandbox_get(url)) == 200L,
          error = function(e) FALSE
        )
      },
      logical(1)
    )
    if (all(ready)) {
      break
    }
    if (Sys.time() >= deadline) {
      stop(
        "Sandbox readiness timed out for: ",
        paste(ready_urls[!ready], collapse = ", ")
      )
    }
    Sys.sleep(2)
  }

  # Record only image identity and public server metadata, never token responses
  # or patient resources. Check the running images against the pinned config.
  services <- jsonlite::fromJSON(
    compose(c("config", "--format", "json"))$stdout
  )$services
  images <- lapply(names(services), function(service) {
    image <- services[[service]]$image
    container <- trimws(compose(c("ps", "-q", service))$stdout)
    if (!nzchar(container)) {
      stop("Missing sandbox service: ", service)
    }
    actual <- trimws(
      docker(c("inspect", "--format", "{{.Image}}", container))$stdout
    )
    expected <- trimws(
      docker(c("image", "inspect", "--format", "{{.Id}}", image))$stdout
    )
    if (!identical(actual, expected)) {
      stop("Running image differs from the pin: ", service)
    }
    list(service = service, reference = image, image_id = actual)
  })
  discovery <- smart_sandbox_json(paste0(
    urls$fhir,
    "/.well-known/smart-configuration"
  ))
  discovery_probe <- tryCatch(
    shinyOAuth::smart_discover(urls$fhir, allow_http_loopback = TRUE),
    error = identity
  )
  discovery_accepted <- !inherits(discovery_probe, "error")
  fhir <- smart_sandbox_json(paste0(urls$raw_fhir, "/metadata"))
  launcher_version <- jsonlite::fromJSON(
    compose(c("exec", "-T", "launcher", "cat", "package.json"))$stdout
  )$version
  artifact_dir <- file.path("integration/smart/.artifacts", project)
  dir.create(artifact_dir, recursive = TRUE, showWarnings = FALSE)
  evidence <- list(
    checkpoint = "sandbox-smoke-and-smart-discovery",
    smart_discovery_tested = TRUE,
    sandbox_discovery_accepted = discovery_accepted,
    discovery_error_class = if (!discovery_accepted) {
      class(discovery_probe)[[1L]]
    } else {
      NULL
    },
    discovery_release_gate = "not_met",
    application_flow_tested = FALSE,
    checked_at_utc = format(Sys.time(), tz = "UTC", usetz = TRUE),
    r_version = R.version.string,
    shinyOAuth_version = as.character(utils::packageVersion("shinyOAuth")),
    docker_version = docker_version,
    launcher_version = launcher_version,
    transport = "HTTP on loopback; production TLS is a separate gate",
    project = project,
    images = images,
    smart_metadata = discovery,
    fhir_version = fhir$fhirVersion,
    fhir_software = fhir$software,
    status = "started"
  )
  report <- file.path(artifact_dir, "evidence.json")
  jsonlite::write_json(
    evidence,
    report,
    auto_unbox = TRUE,
    pretty = TRUE,
    null = "null"
  )
  results <- testthat::test_dir(
    "integration/smart",
    reporter = "summary",
    stop_on_failure = FALSE,
    stop_on_warning = FALSE
  )
  totals <- colSums(as.data.frame(results)[c(
    "failed",
    "error",
    "warning",
    "skipped",
    "passed"
  )])
  passed <- all(totals[c("failed", "error", "skipped")] == 0) &&
    totals[["passed"]] > 0
  evidence$status <- if (passed) "passed" else "failed"
  evidence$discovery_release_gate <- if (passed && discovery_accepted) {
    "passed"
  } else {
    "not_met"
  }
  evidence$tests <- as.list(totals)
  jsonlite::write_json(
    evidence,
    report,
    auto_unbox = TRUE,
    pretty = TRUE,
    null = "null"
  )
  message("Sandbox evidence: ", report)
  if (!passed) {
    stop("SMART sandbox tests require zero failures, errors and skips")
  }
  if (!discovery_accepted) {
    message(
      "Sandbox discovery acceptance gate is NOT MET; see sandbox.md and evidence.json"
    )
    if ("--require-compatible-discovery" %in% args) {
      stop(
        "The pinned sandbox does not pass strict SMART discovery; release acceptance is required"
      )
    }
  }
  invisible(results)
}

run_smart_sandbox()
