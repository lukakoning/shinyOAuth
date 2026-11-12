openid_require <- function(packages) {
  for (package in packages) {
    if (!requireNamespace(package, quietly = TRUE)) {
      stop("OpenID tests require R package: ", package, call. = FALSE)
    }
  }
}

openid_lock <- function(root = ".") {
  lock <- jsonlite::read_json(file.path(
    root,
    "integration/openid/suite-lock.json"
  ))
  images <- unlist(lock[["images"]], use.names = FALSE)
  if (
    !identical(lock[["schema_version"]], 1L) ||
      !grepl("^[a-f0-9]{40}$", lock[["source_revision"]]) ||
      length(images) != 3L ||
      !all(grepl("^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$", images))
  ) {
    stop("Invalid OpenID suite lock; every image must use a SHA-256 digest")
  }
  lock
}

openid_wait <- function(predicate, description, timeout = 120) {
  deadline <- Sys.time() + timeout
  repeat {
    result <- predicate()
    if (!is.null(result) && !identical(result, FALSE)) {
      return(result)
    }
    if (Sys.time() >= deadline) {
      stop("Timed out: ", description, call. = FALSE)
    }
    Sys.sleep(0.2)
  }
}

openid_docker <- function(args, log = NULL, timeout = 120000) {
  result <- processx::run(
    "docker",
    args,
    error_on_status = FALSE,
    timeout = timeout,
    stdout = if (is.null(log)) "|" else log,
    stderr = if (is.null(log)) "|" else paste0(log, ".stderr")
  )
  if (result[["status"]] != 0L) {
    stop(
      "OpenID Docker operation failed (",
      result[["status"]],
      "). ",
      if (is.null(log)) result[["stderr"]] else paste("Private log:", log),
      call. = FALSE
    )
  }
  result[["stdout"]]
}

openid_output <- function(root, kind) {
  output <- file.path(
    normalizePath(root, winslash = "/"),
    "integration/openid/.artifacts",
    paste0(
      kind,
      "-",
      format(Sys.time(), "%Y%m%d-%H%M%S"),
      "-",
      paste(format(openssl::rand_bytes(6)), collapse = "")
    )
  )
  dir.create(output, recursive = TRUE)
  normalizePath(output, winslash = "/")
}

openid_compose <- function(stack, args, log = NULL) {
  if (!grepl("^shinyoauth-openid-[0-9]+-[a-f0-9]{12}$", stack[["project"]])) {
    stop("Refusing an unowned OpenID Compose project")
  }
  withr::with_envvar(
    stack[["env"]],
    openid_docker(
      c(
        "compose",
        "--project-name",
        stack[["project"]],
        "--file",
        stack[["compose"]],
        args
      ),
      log
    )
  )
}

openid_image_revision <- function(lock) {
  properties <- openid_docker(c(
    "run",
    "--rm",
    "--network",
    "none",
    "--entrypoint",
    "bash",
    lock[["images"]][["server"]],
    "-c",
    paste(
      "cd /tmp && jar xf /server/fapi-test-suite.jar",
      "BOOT-INF/classes/git.properties && cat BOOT-INF/classes/git.properties"
    )
  ))
  lines <- strsplit(properties, "\n", fixed = TRUE)[[1L]]
  property <- function(name) {
    prefix <- paste0(name, "=")
    matches <- lines[startsWith(lines, prefix)]
    if (length(matches) != 1L) {
      stop("Missing suite build property: ", name)
    }
    trimws(substring(matches, nchar(prefix) + 1L))
  }
  if (
    !identical(property("git.commit.id"), lock[["source_revision"]]) ||
      !identical(property("git.dirty"), "false")
  ) {
    stop("Pinned OpenID image does not match the clean source revision")
  }
  list(
    revision = property("git.commit.id"),
    dirty = FALSE,
    description = property("git.commit.id.describe")
  )
}

openid_start <- function(root, output, .env = parent.frame()) {
  root <- normalizePath(root, winslash = "/")
  lock <- openid_lock(root)
  if (!nzchar(Sys.which("docker"))) {
    stop("OpenID preflight requires Docker Engine and Compose v2")
  }
  platform <- trimws(openid_docker(c("version", "--format", "{{.Server.Os}}")))
  if (!identical(platform, "linux")) {
    stop("OpenID tests require Docker Linux containers")
  }
  openid_docker(c("compose", "version"))
  for (name in names(lock[["images"]])) {
    openid_docker(
      c("pull", lock[["images"]][[name]]),
      file.path(output, paste0("pull-", name, ".log"))
    )
  }
  provenance <- openid_image_revision(lock)
  tls <- file.path(output, "tls")
  dir.create(tls)
  tls <- normalizePath(tls, winslash = "/")
  openid_docker(
    c(
      "run",
      "--rm",
      "--network",
      "none",
      "--entrypoint",
      "openssl",
      "--mount",
      paste0("type=bind,source=", tls, ",target=/output"),
      lock[["images"]][["proxy"]],
      "req",
      "-x509",
      "-nodes",
      "-days",
      "2",
      "-newkey",
      "rsa:2048",
      "-keyout",
      "/output/key.pem",
      "-out",
      "/output/cert.pem",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"
    ),
    file.path(output, "certificate.log")
  )
  pubkey <- openid_docker(c(
    "run",
    "--rm",
    "--network",
    "none",
    "--entrypoint",
    "openssl",
    "--mount",
    paste0("type=bind,source=", tls, ",target=/output,readonly"),
    lock[["images"]][["proxy"]],
    "x509",
    "-in",
    "/output/cert.pem",
    "-pubkey",
    "-noout"
  ))
  spki <- as.character(openssl::base64_encode(openssl::sha256(
    openssl::write_der(openssl::read_pubkey(pubkey))
  )))
  ports <- unique(c(httpuv::randomPort(), httpuv::randomPort()))
  if (length(ports) != 2L) {
    stop("Could not allocate distinct OpenID ports")
  }
  config <- readLines(file.path(root, "integration/openid/nginx.conf"))
  config <- gsub("@HTTPS_PORT@", ports[[1L]], config, fixed = TRUE)
  config <- gsub("@MTLS_PORT@", ports[[2L]], config, fixed = TRUE)
  config_path <- file.path(output, "nginx.conf")
  writeLines(config, config_path)
  stack <- list(
    project = paste0(
      "shinyoauth-openid-",
      Sys.getpid(),
      "-",
      paste(format(openssl::rand_bytes(6)), collapse = "")
    ),
    compose = file.path(root, "integration/openid/compose.yml"),
    origin = paste0("https://localhost:", ports[[1L]]),
    ca = file.path(tls, "cert.pem"),
    spki = spki,
    output = output,
    lock = lock,
    provenance = provenance
  )
  stack[["lifecycle"]] <- new.env(parent = emptyenv())
  stack[["lifecycle"]][["stopped"]] <- FALSE
  stack[["env"]] <- c(
    OPENID_SERVER_IMAGE = lock[["images"]][["server"]],
    OPENID_PROXY_IMAGE = lock[["images"]][["proxy"]],
    OPENID_DATABASE_IMAGE = lock[["images"]][["database"]],
    OPENID_ORIGIN = stack[["origin"]],
    OPENID_MTLS_ORIGIN = paste0("https://localhost:", ports[[2L]]),
    OPENID_HTTPS_PORT = as.character(ports[[1L]]),
    OPENID_MTLS_PORT = as.character(ports[[2L]]),
    OPENID_TLS_DIR = tls,
    OPENID_NGINX_CONFIG = config_path
  )
  withr::defer(openid_stop(stack), envir = .env)
  openid_compose(
    stack,
    c("up", "--detach", "--wait", "--wait-timeout", "120"),
    file.path(output, "start.log")
  )
  openid_wait(
    function() {
      tryCatch(
        openid_api(stack, "/api/server"),
        httr2_failure = function(...) NULL,
        openid_http_error = function(e) {
          if (e[["status"]] %in% c(502L, 503L, 504L)) {
            return(NULL)
          }
          stop(e)
        }
      )
    },
    "OpenID suite API"
  )
  info <- openid_api(stack, "/api/server")
  if (
    !identical(info[["revision"]], substr(lock[["source_revision"]], 1L, 7L))
  ) {
    stop("Running OpenID suite reports an unexpected source revision")
  }
  stack[["server_info"]] <- info
  stack
}

openid_stop <- function(stack) {
  if (isTRUE(stack[["lifecycle"]][["stopped"]])) {
    return(invisible(NULL))
  }
  tryCatch(
    {
      openid_compose(
        stack,
        c("logs", "--no-color"),
        file.path(stack[["output"]], "services.log")
      )
    },
    error = function(e) warning(conditionMessage(e), call. = FALSE)
  )
  openid_compose(
    stack,
    c("down", "--volumes", "--remove-orphans"),
    file.path(stack[["output"]], "stop.log")
  )
  remaining <- trimws(openid_docker(c(
    "ps",
    "--all",
    "--quiet",
    "--filter",
    paste0("label=com.docker.compose.project=", stack[["project"]])
  )))
  if (nzchar(remaining)) {
    stop("OpenID test containers remain after cleanup")
  }
  for (kind in c("network", "volume")) {
    remaining <- trimws(openid_docker(c(
      kind,
      "ls",
      "--quiet",
      "--filter",
      paste0("label=com.docker.compose.project=", stack[["project"]])
    )))
    if (nzchar(remaining)) stop("OpenID test ", kind, " remains after cleanup")
  }
  stack[["lifecycle"]][["stopped"]] <- TRUE
}

openid_plan_ids <- function(plans, required) {
  ids <- vapply(
    plans,
    function(plan) {
      name <- plan[["planName"]]
      if (!is.character(name) || length(name) != 1L || !nzchar(name)) {
        stop("OpenID plan metadata has no planName")
      }
      name
    },
    character(1)
  )
  if (anyDuplicated(ids)) {
    stop("OpenID plan metadata contains duplicate plans")
  }
  missing <- setdiff(unlist(required, use.names = FALSE), ids)
  if (length(missing)) {
    stop(
      "OpenID suite is missing required plans: ",
      paste(missing, collapse = ", ")
    )
  }
  ids
}

openid_api <- function(
  stack,
  path,
  data = NULL,
  query = NULL,
  method = NULL,
  status = 200L
) {
  if (!startsWith(path, "/api/")) {
    stop("Invalid OpenID API path")
  }
  req <- httr2::request(paste0(stack[["origin"]], path)) |>
    httr2::req_options(cainfo = stack[["ca"]], followlocation = FALSE) |>
    httr2::req_timeout(10) |>
    httr2::req_error(is_error = function(...) FALSE)
  if (length(query)) {
    req <- do.call(httr2::req_url_query, c(list(req), query))
  }
  if (!is.null(data)) {
    req <- httr2::req_body_json(req, data, auto_unbox = TRUE)
  }
  if (!is.null(method)) {
    req <- httr2::req_method(req, method)
  }
  response <- httr2::req_perform(req)
  if (!httr2::resp_status(response) %in% status) {
    stop(structure(
      list(
        message = paste0(
          "OpenID API returned HTTP ",
          httr2::resp_status(response),
          " for ",
          sub("\\?.*$", "", path)
        ),
        call = NULL,
        status = httr2::resp_status(response)
      ),
      class = c("openid_http_error", "error", "condition")
    ))
  }
  httr2::resp_body_json(response, simplifyVector = FALSE)
}

openid_browser <- function(spki, .env = parent.frame()) {
  browser <- chromote::Chromote[["new"]](
    browser = chromote::Chrome[["new"]](
      args = c(
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        paste0("--ignore-certificate-errors-spki-list=", spki)
      )
    )
  )
  withr::defer(browser[["close"]](wait = TRUE), envir = .env)
  browser
}

openid_browser_tls <- function(stack) {
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  navigation <- tab[["Page"]][["navigate"]](paste0(
    stack[["origin"]],
    "/api/server"
  ))
  if (!is.null(navigation[["errorText"]])) {
    stop("Chrome rejected the pinned test certificate")
  }
  result <- tab[["Runtime"]][["evaluate"]](
    "fetch('/api/server').then(r => r.json()).then(v => ({revision:v.revision, secure:isSecureContext}))",
    awaitPromise = TRUE,
    returnByValue = TRUE
  )
  value <- result[["result"]][["value"]]
  if (
    !isTRUE(value[["secure"]]) ||
      !identical(value[["revision"]], stack[["server_info"]][["revision"]])
  ) {
    stop("Chrome could not reach the OpenID suite using its certificate pin")
  }
  # A different pin must not grant trust to the test certificate.
  other <- openid_browser(as.character(openssl::base64_encode(openssl::rand_bytes(
    32
  ))))
  other_tab <- other[["new_session"]]()
  rejected <- other_tab[["Page"]][["navigate"]](paste0(
    stack[["origin"]],
    "/api/server"
  ))
  if (!identical(rejected[["errorText"]], "net::ERR_CERT_AUTHORITY_INVALID")) {
    stop("Chrome accepted the test certificate without its matching pin")
  }
  list(
    method = "ephemeral certificate SPKI pin; no system trust changes",
    secure_context = TRUE,
    wrong_pin_rejected = TRUE
  )
}
