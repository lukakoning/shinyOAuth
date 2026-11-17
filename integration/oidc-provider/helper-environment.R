interop_lock <- function(root = ".") {
  directory <- file.path(root, "integration/oidc-provider")
  lock <- jsonlite::read_json(file.path(directory, "provider-lock.json"))
  package <- jsonlite::read_json(file.path(directory, "package.json"))
  npm <- jsonlite::read_json(file.path(directory, "package-lock.json"))
  if (
    !identical(lock[["schema_version"]], 1L) ||
      !grepl(
        "^node:[0-9.]+-bookworm-slim@sha256:[a-f0-9]{64}$",
        lock[["node_image"]]
      ) ||
      !identical(
        package[["dependencies"]][["oidc-provider"]],
        lock[["provider_version"]]
      ) ||
      !identical(
        npm[["packages"]][["node_modules/oidc-provider"]][["version"]],
        lock[["provider_version"]]
      ) ||
      !identical(
        npm[["packages"]][["node_modules/oidc-provider"]][["integrity"]],
        lock[["provider_integrity"]]
      ) ||
      !identical(
        readLines(file.path(directory, "Dockerfile"), n = 1L),
        paste("FROM", lock[["node_image"]])
      )
  ) {
    stop("Provider runtime or dependency lock mismatch")
  }
  lock
}

interop_output <- function(root = ".") {
  path <- file.path(
    normalizePath(root, winslash = "/"),
    "integration/oidc-provider/.artifacts",
    paste0(
      "basic-",
      format(Sys.time(), "%Y%m%d-%H%M%S", tz = "UTC"),
      "-",
      paste(format(openssl::rand_bytes(6)), collapse = "")
    )
  )
  dir.create(path, recursive = TRUE)
  normalizePath(path, winslash = "/")
}

interop_prepare <- function(root, output) {
  lock <- interop_lock(root)
  executable <- Sys.getenv("SHINYOAUTH_OPENSSL", unset = Sys.which("openssl"))
  if (!nzchar(executable) && .Platform[["OS.type"]] == "windows") {
    executable <- file.path(
      Sys.getenv("ProgramFiles"),
      "Git/usr/bin/openssl.exe"
    )
  }
  if (!nzchar(executable) || !file.exists(executable)) {
    stop("Provider fixtures require the OpenSSL CLI (SHINYOAUTH_OPENSSL)")
  }
  tls <- file.path(output, "tls")
  dir.create(tls)
  result <- processx::run(
    executable,
    c(
      "req",
      "-x509",
      "-nodes",
      "-days",
      "2",
      "-newkey",
      "rsa:2048",
      "-keyout",
      file.path(tls, "key.pem"),
      "-out",
      file.path(tls, "cert.pem"),
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"
    ),
    stdout = file.path(output, "certificate.log"),
    stderr = file.path(output, "certificate.stderr"),
    error_on_status = FALSE
  )
  if (result[["status"]] != 0L) {
    stop("Temporary provider certificate generation failed")
  }
  key <- openssl::read_key(file.path(tls, "key.pem"))
  spki <- as.character(openssl::base64_encode(openssl::sha256(openssl::write_der(key[[
    "pubkey"
  ]]))))
  id_file <- file.path(output, "image-id")
  openid_docker(
    c(
      "build",
      "--iidfile",
      id_file,
      file.path(root, "integration/oidc-provider")
    ),
    file.path(output, "build.log"),
    timeout = 300000
  )
  id <- trimws(readLines(id_file, warn = FALSE))
  if (length(id) != 1L || !grepl("^sha256:[a-f0-9]{64}$", id)) {
    stop("Invalid provider build image identity")
  }
  files <- c(
    "Dockerfile",
    "package.json",
    "package-lock.json",
    "provider-lock.json",
    "provider.mjs",
    "test-provider.mjs",
    ".dockerignore"
  )
  hashes <- setNames(
    lapply(files, function(name) {
      path <- file.path(root, "integration/oidc-provider", name)
      paste(
        openssl::sha256(readBin(path, "raw", n = file.info(path)[["size"]])),
        collapse = ""
      )
    }),
    files
  )
  list(
    output = output,
    ca = file.path(tls, "cert.pem"),
    spki = spki,
    image = id,
    lock = lock,
    source_hashes = hashes
  )
}

interop_request <- function(stack, path, evidence = FALSE) {
  request <- httr2::request(paste0(stack[["origin"]], path)) |>
    httr2::req_options(
      cainfo = stack[["ca"]],
      followlocation = FALSE,
      proxy = ""
    ) |>
    httr2::req_timeout(5)
  if (evidence) {
    request <- httr2::req_headers(
      request,
      `X-Fixture-Key` = stack[["control_key"]]
    )
  }
  httr2::resp_body_json(httr2::req_perform(request), simplifyVector = FALSE)
}

interop_stop <- function(stack) {
  if (isTRUE(stack[["lifecycle"]][["stopped"]])) {
    return(invisible(NULL))
  }
  details <- jsonlite::fromJSON(
    openid_docker(c("inspect", stack[["container"]])),
    simplifyVector = FALSE
  )[[1L]]
  if (
    !identical(
      details[["Config"]][["Labels"]][["shinyoauth.oidc-provider.run_id"]],
      stack[["run_id"]]
    )
  ) {
    stop("Refusing to stop an unrelated provider container")
  }
  openid_docker(
    c("logs", stack[["container"]]),
    file.path(stack[["output"]], paste0(stack[["run_id"]], "-provider.log"))
  )
  openid_docker(c("rm", "--force", stack[["container"]]))
  remaining <- trimws(openid_docker(c(
    "ps",
    "--all",
    "--quiet",
    "--filter",
    paste0("label=shinyoauth.oidc-provider.run_id=", stack[["run_id"]])
  )))
  if (nzchar(remaining)) {
    stop("Provider container remains after cleanup")
  }
  stack[["lifecycle"]][["stopped"]] <- TRUE
  invisible(NULL)
}

interop_start <- function(environment, config, .env = parent.frame()) {
  port <- httpuv::randomPort(min = 20000L, max = 45000L)
  config[["issuer"]] <- paste0("https://localhost:", port)
  config[["control_key"]] <- paste(
    format(openssl::rand_bytes(32)),
    collapse = ""
  )
  path <- file.path(
    environment[["output"]],
    paste0(config[["run_id"]], "-config.json")
  )
  jsonlite::write_json(config, path, auto_unbox = TRUE)
  user <- if (.Platform[["OS.type"]] == "windows") {
    character()
  } else {
    c(
      "--user",
      paste(
        trimws(processx::run("id", "-u")[["stdout"]]),
        trimws(processx::run("id", "-g")[["stdout"]]),
        sep = ":"
      )
    )
  }
  container <- trimws(openid_docker(c(
    "run",
    "--detach",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=16m",
    user,
    "--label",
    paste0("shinyoauth.oidc-provider.run_id=", config[["run_id"]]),
    "--publish",
    paste0("127.0.0.1:", port, ":9443"),
    "--mount",
    paste0("type=bind,source=", path, ",target=/run/config.json,readonly"),
    "--mount",
    paste0(
      "type=bind,source=",
      dirname(environment[["ca"]]),
      ",target=/run/tls,readonly"
    ),
    "--env",
    "FIXTURE_CONFIG=/run/config.json",
    "--env",
    "FIXTURE_TLS_CERT=/run/tls/cert.pem",
    "--env",
    "FIXTURE_TLS_KEY=/run/tls/key.pem",
    environment[["image"]]
  )))
  if (!grepl("^[a-f0-9]{64}$", container)) {
    stop("Invalid provider container identity")
  }
  stack <- c(
    environment,
    list(
      container = container,
      origin = config[["issuer"]],
      run_id = config[["run_id"]],
      control_key = config[["control_key"]],
      lifecycle = new.env(parent = emptyenv())
    )
  )
  withr::defer(interop_stop(stack), envir = .env)
  info <- openid_wait(
    function() {
      running <- trimws(openid_docker(c(
        "inspect",
        "--format",
        "{{.State.Running}}",
        container
      )))
      if (!identical(running, "true")) {
        stop(
          "Provider setup failed during preflight; inspect the private provider log"
        )
      }
      tryCatch(
        interop_request(stack, "/api/server"),
        httr2_error = function(...) NULL
      )
    },
    "Pinned oidc-provider readiness",
    30
  )
  if (
    !isTRUE(info[["ready"]]) ||
      !identical(info[["version"]], stack[["lock"]][["provider_version"]]) ||
      !identical(info[["node_version"]], stack[["lock"]][["node_version"]])
  ) {
    stop("Provider preflight runtime mismatch")
  }
  stack
}
