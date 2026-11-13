openid_fixture_hook <- function(
  directory,
  run_id,
  package,
  ca,
  package_name = "shinyOAuth"
) {
  hook <- function(event) {
    types <- c(
      "audit_token_exchange",
      "audit_userinfo",
      "audit_login_success",
      "audit_login_failed",
      "audit_callback_validation_success",
      "audit_token_refresh",
      "audit_session_cleared"
    )
    classes <- intersect(
      event[["error_class"]],
      c(
        "shinyOAuth_id_token_error",
        "shinyOAuth_userinfo_error",
        "shinyOAuth_userinfo_mismatch",
        "shinyOAuth_state_error",
        "shinyOAuth_token_error",
        "shinyOAuth_callback_error",
        "shinyOAuth_config_error"
      )
    )
    if (!event[["type"]] %in% types && !length(classes)) {
      return(invisible(NULL))
    }
    record <- list(
      run_id = run_id,
      pid = Sys.getpid(),
      package_version = as.character(utils::packageVersion(package_name)),
      package_matches = identical(
        normalizePath(
          getNamespaceInfo(asNamespace(package_name), "path"),
          winslash = "/"
        ),
        package
      ),
      ca_matches = identical(Sys.getenv("CURL_CA_BUNDLE"), ca),
      type = if (event[["type"]] %in% types) {
        event[["type"]]
      } else {
        "validation_error"
      },
      errors = as.list(classes),
      claims = as.list(intersect(
        event[["claim"]],
        c(
          "iss",
          "aud",
          "sub",
          "nonce",
          "exp",
          "iat",
          "azp",
          "auth_time",
          "at_hash"
        )
      )),
      reasons = as.list(intersect(
        event[["reason"]],
        c(
          "disallowed_algorithm",
          "invalid_signature",
          "discovery_issuer_mismatch"
        )
      ))
    )
    path <- tempfile(
      paste0("event-", Sys.getpid(), "-"),
      tmpdir = directory,
      fileext = ".json"
    )
    pending <- paste0(path, ".pending")
    jsonlite::write_json(record, pending, auto_unbox = TRUE, null = "null")
    if (!file.rename(pending, path)) {
      stop("Cannot publish sanitized fixture audit event")
    }
    invisible(NULL)
  }
  environment(hook) <- list2env(
    list(
      directory = directory,
      run_id = run_id,
      package = package,
      ca = ca,
      package_name = package_name
    ),
    parent = baseenv()
  )
  hook
}

openid_fixture_probe <- function(origin, ca, package, directory) {
  # The barrier makes both future multisession workers participate before either
  # task can finish. The mirai everywhere call already addresses every daemon.
  file.create(file.path(directory, paste0("probe-ready-", Sys.getpid())))
  deadline <- Sys.time() + 20
  while (length(list.files(directory, pattern = "^probe-ready-")) < 2L) {
    if (Sys.time() > deadline) {
      stop("Both fixture workers must join the TLS probe")
    }
    Sys.sleep(0.05)
  }
  request <- function(url, ...) {
    httr2::request(url) |>
      httr2::req_options(
        cainfo = ca,
        followlocation = FALSE,
        proxy = "",
        ...
      ) |>
      httr2::req_timeout(5) |>
      httr2::req_perform()
  }
  verified <- identical(
    httr2::resp_status(request(paste0(origin, "/api/server"))),
    200L
  )
  port <- sub("^https://localhost:", "", origin)
  hostname_rejected <- tryCatch(
    {
      request(
        paste0("https://wrong-hostname.invalid:", port, "/api/server"),
        resolve = paste0("wrong-hostname.invalid:", port, ":127.0.0.1")
      )
      FALSE
    },
    error = function(error) {
      inherits(error[["parent"]], "curl_error_peer_failed_verification") ||
        inherits(error, "curl_error_peer_failed_verification")
    }
  )
  list(
    pid = Sys.getpid(),
    package_version = as.character(utils::packageVersion("shinyOAuth")),
    package_matches = identical(
      normalizePath(
        getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
        winslash = "/"
      ),
      package
    ),
    ca_matches = identical(Sys.getenv("CURL_CA_BUNDLE"), ca),
    tls_verified = verified,
    hostname_rejected = hostname_rejected
  )
}
environment(openid_fixture_probe) <- baseenv()

openid_fixture_workers <- function(transport, origin, ca, package, directory) {
  if (identical(transport, "sync")) {
    return(list())
  }
  if (identical(transport, "mirai")) {
    mirai::daemons(2L)
    tasks <- mirai::everywhere(
      probe(origin, ca, package, directory),
      .min = 2L,
      .args = list(
        probe = openid_fixture_probe,
        origin = origin,
        ca = ca,
        package = package,
        directory = directory
      )
    )
    deadline <- Sys.time() + 30
    while (any(vapply(tasks, mirai::unresolved, logical(1)))) {
      if (Sys.time() > deadline) {
        stop("Fixture mirai probes did not finish")
      }
      Sys.sleep(0.05)
    }
    probes <- lapply(tasks, function(task) task[["data"]])
  } else if (identical(transport, "future")) {
    if (requireNamespace("mirai", quietly = TRUE)) {
      mirai::daemons(0L)
    }
    future::plan(future::multisession, workers = 2L)
    tasks <- lapply(seq_len(2L), function(i) {
      future::future(
        probe(origin, ca, package, directory),
        globals = list(
          probe = openid_fixture_probe,
          origin = origin,
          ca = ca,
          package = package,
          directory = directory
        ),
        seed = TRUE
      )
    })
    probes <- lapply(tasks, future::value)
  } else {
    stop("Unknown fixture transport")
  }
  if (
    length(probes) != 2L ||
      !all(vapply(
        probes,
        function(probe) {
          is.list(probe) &&
            all(vapply(
              probe[c(
                "package_matches",
                "ca_matches",
                "tls_verified",
                "hostname_rejected"
              )],
              isTRUE,
              logical(1)
            )) &&
            length(probe) == 6L &&
            is.numeric(probe[["pid"]]) &&
            probe[["pid"]] != Sys.getpid()
        },
        logical(1)
      )) ||
      length(unique(vapply(
        probes,
        function(probe) probe[["pid"]],
        integer(1)
      ))) !=
        2L
  ) {
    stop("Fixture workers failed package identity or TLS checks")
  }
  probes
}

openid_fixture_audit <- function(directory, run_id, version, probes) {
  events <- lapply(
    list.files(directory, pattern = "^event-.*[.]json$", full.names = TRUE),
    jsonlite::read_json
  )
  types <- c(
    "audit_token_exchange",
    "audit_userinfo",
    "audit_login_success",
    "audit_login_failed",
    "audit_callback_validation_success",
    "audit_token_refresh",
    "audit_session_cleared"
  )
  count <- function(events) {
    stats::setNames(
      lapply(types, function(type) {
        sum(vapply(
          events,
          function(event) identical(event[["type"]], type),
          logical(1)
        ))
      }),
      types
    )
  }
  worker <- Filter(function(event) event[["pid"]] != Sys.getpid(), events)
  main <- Filter(function(event) event[["pid"]] == Sys.getpid(), events)
  labels <- function(name) {
    as.list(unique(unlist(lapply(events, function(event) event[[name]]))))
  }
  list(
    counts = count(events),
    errors = labels("errors"),
    claims = labels("claims"),
    reasons = labels("reasons"),
    transport = list(
      app_pid = Sys.getpid(),
      probes = probes,
      worker_pids = as.list(unique(vapply(
        worker,
        function(event) event[["pid"]],
        integer(1)
      ))),
      events_verified = all(vapply(
        events,
        function(event) {
          identical(event[["run_id"]], run_id) &&
            identical(event[["package_version"]], version) &&
            isTRUE(event[["package_matches"]]) &&
            isTRUE(event[["ca_matches"]])
        },
        logical(1)
      )),
      main_operations = count(main),
      worker_operations = count(worker),
      worker_validation_errors = sum(vapply(
        worker,
        function(event) identical(event[["type"]], "validation_error"),
        logical(1)
      ))
    )
  )
}
