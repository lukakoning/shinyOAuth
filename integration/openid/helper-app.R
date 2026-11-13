openid_install <- function(root, output) {
  library <- file.path(output, "library")
  dir.create(library)
  executable <- file.path(
    R.home("bin"),
    if (.Platform[["OS.type"]] == "windows") "R.exe" else "R"
  )
  result <- processx::run(
    executable,
    c(
      "CMD",
      "INSTALL",
      paste0("--library=", library),
      normalizePath(root, winslash = "/")
    ),
    stdout = file.path(output, "install.log"),
    stderr = file.path(output, "install.stderr"),
    error_on_status = FALSE,
    timeout = 180000
  )
  if (result[["status"]] != 0L) {
    stop("Checkout installation failed; inspect the private install log")
  }
  normalizePath(library, winslash = "/")
}

openid_app_transport <- function(
  root,
  stack,
  target_port,
  .env = parent.frame()
) {
  python <- Sys.which(
    if (.Platform[["OS.type"]] == "windows") "py" else "python3"
  )
  if (!nzchar(python)) {
    stop("OpenID browser fixtures require Python 3 for the loopback TLS proxy")
  }
  proxy <- processx::process[["new"]](
    python,
    c(
      normalizePath(
        file.path(root, "integration/connections/tls-proxy.py"),
        winslash = "/"
      ),
      "--target-port",
      as.character(target_port),
      "--cert",
      stack[["ca"]],
      "--key",
      file.path(dirname(stack[["ca"]]), "key.pem")
    ),
    stdout = "|",
    stderr = "|",
    supervise = TRUE
  )
  withr::defer(
    {
      if (proxy[["is_alive"]]()) proxy[["kill"]]()
    },
    envir = .env
  )
  port <- openid_wait(
    function() {
      if (!proxy[["is_alive"]]()) {
        stop("OpenID app TLS proxy exited before readiness")
      }
      proxy[["poll_io"]](100)
      line <- proxy[["read_output_lines"]](1L)
      if (length(line)) as.integer(line) else NULL
    },
    "OpenID app TLS proxy",
    15
  )
  if (length(port) != 1L || is.na(port) || port < 1L || port > 65535L) {
    stop("Invalid app TLS port")
  }
  list(
    origin = paste0("https://localhost:", port),
    target_port = target_port,
    process = proxy
  )
}

openid_app_start <- function(
  root,
  stack,
  transport,
  config,
  library,
  .env = parent.frame()
) {
  root <- normalizePath(root, winslash = "/")
  config[["origin"]] <- transport[["origin"]]
  if (is.null(config[["run_id"]])) {
    config[["run_id"]] <- paste(format(openssl::rand_bytes(12)), collapse = "")
  }
  if (is.null(config[["transport"]])) {
    config[["transport"]] <- "sync"
  }
  config[["audit_directory"]] <- file.path(
    stack[["output"]],
    paste0("audit-", config[["run_id"]])
  )
  if (!dir.create(config[["audit_directory"]])) {
    stop("Cannot create private fixture audit directory")
  }
  app <- callr::r_bg(
    function(root, config, ca, port, expected_package) {
      Sys.setenv(CURL_SSL_BACKEND = "openssl", CURL_CA_BUNDLE = ca)
      Sys.setenv(
        R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
      )
      actual_package <- normalizePath(
        find.package("shinyOAuth"),
        winslash = "/"
      )
      if (!identical(actual_package, expected_package)) {
        stop("App loaded a different shinyOAuth installation")
      }
      source(
        file.path(root, "integration/openid/fixture-transport.R"),
        local = TRUE
      )
      on.exit(
        {
          if (identical(config[["transport"]], "mirai")) {
            mirai::daemons(0L)
          }
          if (identical(config[["transport"]], "future")) {
            future::plan(future::sequential)
          }
        },
        add = TRUE
      )
      config[["worker_probes"]] <- openid_fixture_workers(
        config[["transport"]],
        config[["provider_origin"]],
        ca,
        expected_package,
        config[["audit_directory"]]
      )
      config[["package_path"]] <- expected_package
      config[["ca"]] <- ca
      config[["backend_verified"]] <- identical(
        config[["transport"]],
        "sync"
      ) ||
        identical(
          getFromNamespace("async_backend_available", "shinyOAuth")(),
          config[["transport"]]
        )
      if (!isTRUE(config[["backend_verified"]])) {
        stop("Fixture selected the wrong async backend")
      }
      source(file.path(root, "integration/openid/fixture-app.R"), local = TRUE)
      shiny::runApp(
        openid_fixture_app(config),
        host = "127.0.0.1",
        port = port,
        launch.browser = FALSE,
        quiet = TRUE
      )
    },
    args = list(
      root,
      config,
      stack[["ca"]],
      transport[["target_port"]],
      normalizePath(file.path(library, "shinyOAuth"), winslash = "/")
    ),
    libpath = c(library, .libPaths()),
    supervise = TRUE,
    stdout = file.path(
      stack[["output"]],
      paste0("app-", config[["run_id"]], ".log")
    ),
    stderr = file.path(
      stack[["output"]],
      paste0("app-", config[["run_id"]], ".stderr")
    )
  )
  withr::defer(
    {
      if (app[["is_alive"]]()) app[["kill_tree"]]()
    },
    envir = .env
  )
  openid_wait(
    function() {
      if (!app[["is_alive"]]()) {
        stop("OpenID fixture app exited; inspect its private app log")
      }
      tryCatch(
        {
          response <- httr2::request(paste0(transport[["origin"]], "/")) |>
            httr2::req_options(
              cainfo = stack[["ca"]],
              followlocation = FALSE
            ) |>
            httr2::req_timeout(2) |>
            httr2::req_perform()
          identical(httr2::resp_status(response), 200L)
        },
        httr2_error = function(...) NULL
      )
    },
    "OpenID fixture app",
    60
  )
  list(process = app, config = config, origin = transport[["origin"]])
}

openid_browser_value <- function(tab, js) {
  result <- tab[["Runtime"]][["evaluate"]](js, returnByValue = TRUE)
  if (!is.null(result[["exceptionDetails"]])) {
    return(NULL)
  }
  result[["result"]][["value"]]
}

openid_app_snapshot <- function(tab, run_id) {
  value <- openid_browser_value(
    tab,
    "(() => { const e = document.querySelector('#snapshot'); try { return e && JSON.parse(e.textContent); } catch { return null; } })()"
  )
  if (!is.list(value) || !identical(value[["run_id"]], run_id)) {
    return(NULL)
  }
  value
}
