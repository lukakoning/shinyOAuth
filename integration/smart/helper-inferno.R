# Shared orchestration for the pinned local Inferno client suite. This file does
# not replace shinyOAuth protocol code or Inferno's verification assertions.
inferno_image <- "shinyoauth-inferno:980e54e4-simulator1"
inferno_revision <- "980e54e4ed632b28267d797013399a8588772174"

inferno_wait <- function(predicate, description, timeout = 60) {
  deadline <- Sys.time() + timeout
  repeat {
    value <- predicate()
    if (!is.null(value) && !identical(value, FALSE)) return(value)
    if (Sys.time() >= deadline) stop("Timed out: ", description, call. = FALSE)
    Sys.sleep(0.1)
  }
}

inferno_docker <- function(args, log = NULL, timeout = 120000) {
  result <- processx::run("docker", args, error_on_status = FALSE,
    stdout = if (is.null(log)) "|" else log,
    stderr = if (is.null(log)) "|" else paste0(log, ".stderr"),
    timeout = timeout)
  if (result$status != 0L) stop("Inferno Docker operation failed (", result$status,
    "); inspect the local private log: ", log, call. = FALSE)
  result$stdout
}

inferno_build <- function(root, output) {
  inferno_docker(c("build", "--tag", inferno_image,
    file.path(root, "integration/smart/inferno")), file.path(output, "build.log"), 1800000)
  # Only server-simulation files may differ. Client-suite assertions, suite
  # definitions and the dependency lock must remain exactly as upstream.
  changed <- trimws(inferno_docker(c("run", "--rm", "--entrypoint", "git",
    inferno_image, "diff", "--name-only")))
  expected <- c("lib/smart_app_launch/endpoints/mock_smart_server.rb",
    "lib/smart_app_launch/endpoints/mock_smart_server/smart_token_response_creation.rb")
  stopifnot(setequal(strsplit(changed, "\n", fixed = TRUE)[[1L]], expected))
  revision <- trimws(inferno_docker(c("run", "--rm", "--entrypoint", "git",
    inferno_image, "rev-parse", "HEAD")))
  stopifnot(identical(revision, inferno_revision))
  patch <- file.path(root, "integration/smart/inferno/simulator.patch")
  list(upstream_revision = revision, kit_version = "1.0.3", core_version = "1.4.3",
    image_id = trimws(inferno_docker(c("image", "inspect", "--format", "{{.Id}}", inferno_image))),
    simulator_modified = TRUE, upstream_verification_unchanged = TRUE,
    patch_sha256 = paste(openssl::sha256(readBin(patch, "raw", n = file.size(patch)))))
}

inferno_tls <- function(root, target_port, .env = parent.frame()) {
  python <- Sys.which(if (.Platform$OS.type == "windows") "py" else "python3")
  if (!nzchar(python)) stop("Inferno browser integration requires Python 3")
  proxy <- processx::process$new(python,
    c(file.path(root, "integration/connections/tls-proxy.py"),
      "--target-port", as.character(target_port),
      "--cert", file.path(root, "integration/keycloak/tls/server-cert.pem"),
      "--key", file.path(root, "integration/keycloak/tls/server-key.pem")),
    stdout = "|", stderr = "|", supervise = TRUE)
  withr::defer({ if (proxy$is_alive()) proxy$kill() }, envir = .env)
  port <- inferno_wait(function() {
    if (!proxy$is_alive()) stop("Inferno TLS transport did not start")
    proxy$poll_io(100)
    line <- proxy$read_output_lines(n = 1L)
    if (length(line)) as.integer(line) else NULL
  }, "loopback TLS transport", 10)
  stopifnot(length(port) == 1L, !is.na(port), port > 0L, port <= 65535L)
  list(origin = paste0("https://localhost:", port), port = port, process = proxy)
}

inferno_test_simulator <- function(root, output) {
  inferno_docker(c("run", "--rm", "-e", "APP_ENV=test", "--mount", paste0(
    "type=bind,source=", file.path(root, "integration/smart/inferno/simulator_spec.rb"),
    ",target=/opt/inferno/spec/shinyoauth_simulator_spec.rb,readonly"),
    inferno_image, "bundle", "exec", "rspec", "--format", "progress",
    "spec/shinyoauth_simulator_spec.rb", "spec/smart_app_launch/client_suite/mock_smart_server_spec.rb"),
    file.path(output, "simulator-tests.log"))
  stopifnot(any(grepl("^19 examples, 0 failures$",
    readLines(file.path(output, "simulator-tests.log"), warn = FALSE))))
  "passed"
}

inferno_api <- function(stack, path, data = NULL, json = TRUE) {
  req <- httr2::request(paste0(stack$origin, path)) |>
    httr2::req_options(cainfo = stack$ca) |> httr2::req_timeout(10) |>
    httr2::req_error(is_error = function(...) FALSE)
  if (!is.null(data)) req <- httr2::req_body_json(req, data, auto_unbox = TRUE)
  response <- httr2::req_perform(req)
  if (httr2::resp_status(response) >= 400L) {
    stop("Inferno API returned HTTP ", httr2::resp_status(response),
      " for ", sub("\\?.*$", "", path), call. = FALSE)
  }
  if (json) httr2::resp_body_json(response, simplifyVector = FALSE) else response
}

inferno_start <- function(root, output, site = "a", .env = parent.frame()) {
  stopifnot(site %in% c("a", "b"))
  port <- httpuv::randomPort()
  tls <- inferno_tls(root, port, .env)
  project <- paste0("shinyoauth-inferno-", Sys.getpid(), "-",
    format(Sys.time(), "%H%M%S"), "-", site)
  env_file <- file.path(output, paste0(site, ".env"))
  writeLines(c(paste0("SMART_INFERNO_ORIGIN=", tls$origin),
    paste0("SMART_INFERNO_PORT=", port)), env_file)
  compose <- c("compose", "--project-name", project, "--env-file", env_file,
    "--file", file.path(root, "integration/smart/inferno/compose.yml"))
  # Cleanup is registered before starting anything and targets this unique
  # Compose project, including its private SQLite database and Redis instance.
  withr::defer(inferno_docker(c(compose, "down", "--volumes", "--remove-orphans"),
    file.path(output, paste0(site, "-cleanup.log"))), envir = .env)
  inferno_docker(c(compose, "up", "--detach", "redis"), file.path(output, paste0(site, "-redis.log")))
  inferno_docker(c(compose, "run", "--rm", "--no-deps", "inferno", "bundle", "exec",
    "inferno", "migrate"), file.path(output, paste0(site, "-migrate.log")))
  inferno_docker(c(compose, "up", "--detach", "--no-build", "inferno", "worker"),
    file.path(output, paste0(site, "-start.log")))
  stack <- list(origin = tls$origin, ca = file.path(root, "integration/keycloak/tls/ca-cert.pem"),
    fhir_base = paste0(tls$origin, "/custom/", inferno_suite, "/fhir"),
    compose = compose, project = project)
  inferno_wait(function() tryCatch({
    inferno_api(stack, paste0("/custom/", inferno_suite, "/fhir/.well-known/smart-configuration"))
  }, error = function(...) NULL), "Inferno readiness")
  stack
}
