permissions_docker <- function(args, log, timeout = 180000) {
  result <- processx::run(
    "docker",
    args,
    stdout = log,
    stderr = paste0(log, ".stderr"),
    error_on_status = FALSE,
    timeout = timeout
  )
  if (result[["status"]] != 0L) {
    stop(
      "Permission fixture Docker operation failed; inspect private log: ",
      log
    )
  }
}

permissions_start <- function(root, output, app_origin, .env = parent.frame()) {
  directory <- file.path(root, "integration/smart/permissions")
  runtime <- file.path(output, "runtime")
  dir.create(runtime)
  port <- httpuv::randomPort()
  origin <- paste0("https://localhost:", port)
  jsonlite::write_json(
    list(origin = origin, callback = paste0(app_origin, "/callback")),
    file.path(runtime, "config.json"),
    auto_unbox = TRUE
  )
  permissions_docker(
    c("build", "-t", "shinyoauth-permission-fixture:1", directory),
    file.path(output, "build.log"),
    900000
  )
  permissions_docker(
    c(
      "run",
      "--rm",
      "--mount",
      paste0("type=bind,source=", runtime, ",target=/runtime"),
      "shinyoauth-permission-fixture:1",
      "--init"
    ),
    file.path(output, "init.log")
  )
  ca <- file.path(runtime, "ca-bundle.pem")
  writeLines(
    c(
      readLines(file.path(runtime, "ca.pem")),
      readLines(file.path(root, "integration/keycloak/tls/ca-cert.pem"))
    ),
    ca
  )
  project <- paste0(
    "shinyoauth-permissions-",
    Sys.getpid(),
    "-",
    format(Sys.time(), "%H%M%S")
  )
  env <- file.path(output, "compose.env")
  writeLines(
    c(
      paste0("SMART_PERMISSION_RUNTIME=", runtime),
      paste0("SMART_PERMISSION_PORT=", port),
      paste0("SMART_PERMISSION_ORIGIN=", origin),
      paste0(
        "SMART_PERMISSION_SQL_PASSWORD=Test!",
        paste(format(openssl::rand_bytes(24)), collapse = "")
      )
    ),
    env
  )
  compose <- c(
    "compose",
    "--project-name",
    project,
    "--env-file",
    env,
    "--file",
    file.path(directory, "compose.yml")
  )
  withr::defer(
    {
      try(
        permissions_docker(
          c(compose, "logs", "--no-color"),
          file.path(output, "private-services.log")
        ),
        silent = TRUE
      )
      permissions_docker(
        c(compose, "down", "--volumes", "--remove-orphans"),
        file.path(output, "cleanup.log")
      )
    },
    envir = .env
  )
  permissions_docker(
    c(compose, "up", "--detach"),
    file.path(output, "start.log"),
    300000
  )
  stack <- list(origin = origin, ca = ca, fhir_base = paste0(origin, "/fhir"))
  last <- NULL
  inferno_wait(
    function() {
      tryCatch(
        {
          response <- httr2::request(paste0(origin, "/test/seed")) |>
            httr2::req_method("POST") |>
            httr2::req_options(cainfo = ca) |>
            httr2::req_timeout(15) |>
            httr2::req_error(is_error = function(...) FALSE) |>
            httr2::req_perform()
          last <<- httr2::resp_body_json(response)
          httr2::resp_status(response) == 200L
        },
        error = function(...) FALSE
      )
    },
    "protected FHIR startup and synthetic data seeding",
    timeout = 240
  )
  stack[["provenance"]] <- list(
    fhir_image = "mcr.microsoft.com/healthcareapis/r4-fhir-server:5.0.58",
    fhir_digest = "sha256:8440fe711e6f98c633863aacd4a79711e323c3a0d559633c70394d1da569ad4a",
    sql_digest = "sha256:7c29dfbac885ad7519e219c7fe4aee0e67283e21a10e9c252d13b0fbde1866f8",
    authentication_enabled = TRUE,
    authorization_enabled = TRUE,
    synthetic_resources_seeded = length(last[["statuses"]])
  )
  stack
}

permissions_case <- function(root, output, stack, app_tls, port, async, index) {
  message("Protected FHIR / async=", async)
  directory <- file.path(output, paste0("case-", index))
  dir.create(directory)
  before <- length(inferno_api(stack, "/test/metrics")[["requests"]])
  process <- callr::r_bg(
    function(root, origin, port, stack, async) {
      Sys.setenv(
        CURL_SSL_BACKEND = "openssl",
        CURL_CA_BUNDLE = stack[["ca"]],
        R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
      )
      source(file.path(root, "integration/smart/fixture-permissions-app.R"))
      permissions_app(origin, port, stack[["fhir_base"]], stack[["ca"]], async)
    },
    args = list(root, app_tls[["origin"]], port, stack, async),
    libpath = .libPaths(),
    supervise = TRUE,
    stdout = file.path(directory, "app.stdout"),
    stderr = file.path(directory, "app.stderr")
  )
  withr::defer({
    if (process[["is_alive"]]()) {
      process[["kill"]]()
      process[["wait"]](timeout = 5000)
    }
  })
  app <- list(
    origin = app_tls[["origin"]],
    process = process,
    ca = stack[["ca"]]
  )
  chrome <- inferno_open_browser(app)
  browser <- chrome[["browser"]]
  retention_browser_click(browser, "connect_a")
  retention_browser_wait(
    browser,
    function() {
      identical(
        retention_browser_value(
          browser,
          "document.querySelector('#provider')?.textContent"
        ),
        "Protected FHIR fixture"
      )
    },
    "SMART approval"
  )
  retention_browser_click(browser, "approve")
  first <- retention_browser_wait(
    browser,
    function() {
      value <- retention_browser_snapshot(browser)
      if (length(value[["connections"]]) == 1L) value else NULL
    },
    "protected FHIR authorization"
  )
  action <- function(id, status) {
    retention_browser_action(
      browser,
      paste0(id, "_a"),
      paste0(id, "_a:", status)
    )
  }
  action("read", "200")
  action("user", "200")
  action("search", "200")
  action("other", "404")
  action("observation", "403")
  action("narrow", "ok")
  action("read", "200")
  action("user", "200")
  action("search", "403")
  browser[["Page"]][["navigate"]](paste0(app[["origin"]], "/retained"))
  restored <- retention_browser_wait(
    browser,
    function() {
      value <- retention_browser_snapshot(browser)
      if (
        !is.null(value) &&
          value[["session"]] > first[["session"]] &&
          length(value[["connections"]]) == 1L
      ) {
        value
      } else {
        NULL
      }
    },
    "protected FHIR grant restoration"
  )
  stopifnot(identical(
    first[["connections"]][[1L]][["connection_id"]],
    restored[["connections"]][[1L]][["connection_id"]]
  ))
  action("read", "200")
  requests <- inferno_api(stack, "/test/metrics")[["requests"]]
  requests <- requests[seq.int(before + 1L, length(requests))]
  patient <- "/fhir/Patient/synthetic-p1"
  expected_paths <- c(
    patient,
    patient,
    "/fhir/Patient",
    "/fhir/Patient/synthetic-p2",
    "/fhir/Observation/synthetic-observation",
    patient,
    patient,
    "/fhir/Patient",
    patient
  )
  stopifnot(
    length(requests) == 9L,
    identical(
      vapply(requests, function(row) row[["path"]], character(1)),
      expected_paths
    ),
    all(vapply(
      requests,
      function(row) identical(row[["method"]], "GET"),
      logical(1)
    )),
    identical(
      vapply(requests, function(row) row[["status"]], integer(1)),
      c(200L, 200L, 200L, 404L, 403L, 200L, 200L, 403L, 200L)
    ),
    identical(
      vapply(requests, function(row) row[["revision"]], integer(1)),
      c(rep(1L, 5L), rep(2L, 4L))
    )
  )
  list(
    async = async,
    browser = chrome[["version"]],
    passed = TRUE,
    real_fhir_reads = TRUE,
    search_filters_patient = TRUE,
    other_patient_denied = TRUE,
    ungranted_resource_denied = TRUE,
    narrowed_search_denied_by_server = TRUE,
    restored_grant_read = TRUE,
    successful_resource_requests = 6L,
    server_denials = 3L,
    current_tokens_verified = TRUE,
    expected_resource_paths_verified = TRUE
  )
}
