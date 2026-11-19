openid_shared_sequence <- function() {
  list(
    list(selection = 1L, case = 1L),
    list(selection = 2L, case = 1L),
    list(selection = 1L, case = 2L),
    list(selection = 2L, case = 2L),
    list(selection = 3L, case = 1L),
    list(selection = 4L, case = 1L),
    list(selection = 3L, case = 2L),
    list(selection = 4L, case = 2L)
  )
}

openid_shared_profiles <- function() {
  c("auth-post", "auth-private-jwt", "auth-post", "auth-private-jwt")
}

openid_shared_issuers_match <- function(configs) {
  sequence <- openid_shared_sequence()
  if (length(configs) != length(sequence)) {
    return(FALSE)
  }
  issuers <- lapply(seq_len(4L), function(i) {
    indices <- which(vapply(
      sequence,
      function(step) step[["selection"]] == i,
      logical(1)
    ))
    unique(vapply(
      configs[indices],
      function(config) config[["issuer"]],
      character(1)
    ))
  })
  all(lengths(issuers) == 1L) &&
    all(vapply(unlist(issuers), openid_string, logical(1))) &&
    !anyDuplicated(unlist(issuers))
}

openid_shared_worker_state <- function() {
  inspect <- function() {
    ns <- asNamespace("shinyOAuth")
    list(
      pid = Sys.getpid(),
      options_clean = all(vapply(
        c("shinyOAuth.audit_hook", "shinyOAuth.timeout"),
        function(name) is.null(getOption(name)),
        logical(1)
      )),
      session_clean = is.null(ns[["get_async_session_context"]]()),
      worker_context_clean = !ns[["is_async_worker_context"]]()
    )
  }
  environment(inspect) <- baseenv()
  tasks <- mirai::everywhere(
    inspect(),
    .min = 2L,
    .args = list(inspect = inspect)
  )
  deadline <- Sys.time() + 20
  while (any(vapply(tasks, mirai::unresolved, logical(1)))) {
    if (Sys.time() > deadline) {
      stop("Shared-pool state inspection timed out")
    }
    Sys.sleep(0.05)
  }
  lapply(tasks, function(task) task[["data"]])
}

openid_shared_state_matches <- function(state, probes) {
  if (length(state) != 2L || length(probes) != 2L) {
    return(FALSE)
  }
  pids <- vapply(probes, function(probe) probe[["pid"]], numeric(1))
  observed <- vapply(
    state,
    function(row) {
      if (openid_count(row[["pid"]], 1L)) row[["pid"]] else -1
    },
    numeric(1)
  )
  !anyDuplicated(observed) &&
    setequal(pids, observed) &&
    all(vapply(
      state,
      function(row) {
        all(vapply(
          c("options_clean", "session_clean", "worker_context_clean"),
          function(name) isTRUE(row[[name]]),
          logical(1)
        ))
      },
      logical(1)
    ))
}

openid_shared_write <- function(value, path) {
  pending <- paste0(path, ".pending")
  saveRDS(value, pending)
  if (!file.rename(pending, path)) stop("Cannot publish private pool command")
}

openid_shared_read <- function(process, path) {
  openid_wait(
    function() {
      if (!process[["is_alive"]]()) {
        stop("Shared fixture process stopped unexpectedly")
      }
      if (file.exists(path)) readRDS(path) else NULL
    },
    "Shared fixture handoff",
    90
  )
}

openid_shared_start <- function(
  root,
  stack,
  transport,
  library,
  .env = parent.frame()
) {
  directory <- file.path(stack[["output"]], "shared-pool")
  dir.create(directory)
  process <- callr::r_bg(
    function(root, directory, origin, ca, port, package) {
      Sys.setenv(
        CURL_SSL_BACKEND = "openssl",
        CURL_CA_BUNDLE = ca,
        R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
      )
      if (
        !identical(
          normalizePath(
            getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
            winslash = "/"
          ),
          package
        )
      ) {
        stop("Shared app loaded a different shinyOAuth installation")
      }
      source(
        file.path(root, "integration/openid/fixture-transport.R"),
        local = TRUE
      )
      source(
        file.path(root, "integration/openid/helper-configuration.R"),
        local = TRUE
      )
      source(file.path(root, "integration/openid/fixture-app.R"), local = TRUE)
      source(
        file.path(root, "integration/openid/helper-shared-pool.R"),
        local = TRUE
      )
      on.exit(mirai::daemons(0L), add = TRUE)
      probes <- openid_fixture_workers("mirai", origin, ca, package, directory)
      openid_shared_write(
        list(probes = probes, state = openid_shared_worker_state()),
        file.path(directory, "ready.rds")
      )
      for (i in seq_len(8L)) {
        command <- file.path(directory, paste0("case-", i, ".rds"))
        deadline <- Sys.time() + 120
        while (!file.exists(command)) {
          if (Sys.time() > deadline) {
            stop("Shared fixture command timed out")
          }
          Sys.sleep(0.05)
        }
        config <- readRDS(command)
        before <- openid_shared_worker_state()
        config[["worker_probes"]] <- probes
        config[["package_path"]] <- package
        config[["ca"]] <- ca
        config[["backend_verified"]] <- identical(
          getFromNamespace("async_backend_available", "shinyOAuth")(),
          "mirai"
        )
        options(shinyOAuth.timeout = config[["expected_timeout"]])
        shiny::runApp(
          openid_fixture_app(config),
          host = "127.0.0.1",
          port = port,
          launch.browser = FALSE,
          quiet = TRUE
        )
        if (!file.exists(config[["stop_file"]])) {
          stop("Shared fixture returned before its requested stop")
        }
        if (!file.remove(config[["stop_file"]])) {
          stop("Cannot retire the completed fixture's stop signal")
        }
        options(shinyOAuth.timeout = NULL, shinyOAuth.audit_hook = NULL)
        openid_shared_write(
          list(before = before, after = openid_shared_worker_state()),
          paste0(command, ".done")
        )
      }
      # Keep the same process and daemons available for parent-side cleanup proof.
      repeat {
        Sys.sleep(0.1)
      }
    },
    args = list(
      normalizePath(root, winslash = "/"),
      directory,
      stack[["origin"]],
      stack[["ca"]],
      transport[["target_port"]],
      normalizePath(file.path(library, "shinyOAuth"), winslash = "/")
    ),
    libpath = c(library, .libPaths()),
    supervise = TRUE,
    stdout = file.path(directory, "app.log"),
    stderr = file.path(directory, "app.stderr")
  )
  withr::defer(
    {
      if (process[["is_alive"]]()) process[["kill_tree"]]()
    },
    envir = .env
  )
  ready <- openid_shared_read(process, file.path(directory, "ready.rds"))
  if (!openid_shared_state_matches(ready[["state"]], ready[["probes"]])) {
    stop("Shared workers did not start with clean options and session context")
  }
  pool <- new.env(parent = emptyenv())
  pool[["process"]] <- process
  pool[["directory"]] <- directory
  pool[["probes"]] <- ready[["probes"]]
  pool[["initial_state"]] <- ready[["state"]]
  pool[["worker_handles"]] <- lapply(ready[["probes"]], function(probe) {
    ps::ps_handle(probe[["pid"]])
  })
  pool[["configs"]] <- list()
  pool[["states"]] <- list()
  pool
}

openid_shared_app_start <- function(
  pool,
  root,
  stack,
  transport,
  config,
  library
) {
  i <- length(pool[["configs"]]) + 1L
  config[["origin"]] <- transport[["origin"]]
  config[["audit_directory"]] <- file.path(
    stack[["output"]],
    paste0("audit-", config[["run_id"]])
  )
  if (!dir.create(config[["audit_directory"]])) {
    stop("Cannot create shared fixture audit directory")
  }
  config[["stop_file"]] <- file.path(pool[["directory"]], paste0("stop-", i))
  config[["expected_timeout"]] <- if (i %% 2L) 17L else 23L
  pool[["configs"]][[i]] <- config
  openid_shared_write(
    config,
    file.path(pool[["directory"]], paste0("case-", i, ".rds"))
  )
  openid_wait(
    function() {
      if (!pool[["process"]][["is_alive"]]()) {
        stop("Shared fixture process stopped before readiness")
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
    "Shared fixture app",
    60
  )
  list(
    process = pool[["process"]],
    config = config,
    origin = transport[["origin"]]
  )
}

openid_shared_app_stop <- function(pool, app) {
  if (!file.create(app[["config"]][["stop_file"]])) {
    stop("Cannot request shared fixture stop")
  }
  i <- length(pool[["configs"]])
  state <- openid_shared_read(
    pool[["process"]],
    file.path(pool[["directory"]], paste0("case-", i, ".rds.done"))
  )
  if (
    !all(vapply(
      state,
      openid_shared_state_matches,
      logical(1),
      probes = pool[["probes"]]
    ))
  ) {
    stop("Worker identity, options or session context leaked across a fixture")
  }
  pool[["states"]][[i]] <- state
}

openid_shared_audit_fingerprint <- function(config) {
  paths <- list.files(
    config[["audit_directory"]],
    pattern = "^event-.*[.]json$",
    full.names = TRUE
  )
  setNames(
    lapply(paths, function(path) {
      connection <- file(path, "rb")
      on.exit(close(connection))
      as.character(openssl::sha256(connection))
    }),
    basename(paths)
  )
}

openid_check_shared_report <- function(report, context, manifest) {
  tryCatch(
    {
      openid_check_provenance(report, context, manifest[["suite_lock"]])
      if (identical(report[["schema_version"]], 4L)) {
        openid_check_source(report, context)
      }
      for (name in c(
        "schema_version",
        "run_id",
        "attempt_id",
        "checkout_revision",
        "source_revision",
        "package_version",
        "profile",
        "transport",
        "plan_ids"
      )) {
        if (
          is.null(context[[name]]) ||
            !identical(report[[name]], context[[name]])
        ) {
          stop("Shared-pool evidence does not belong to this run")
        }
      }
      profiles <- openid_shared_profiles()
      if (
        !identical(context[["profile"]], "shared-pool") ||
          !identical(context[["transport"]], "mirai") ||
          length(context[["plan_ids"]]) != 4L ||
          !all(vapply(context[["plan_ids"]], openid_string, logical(1))) ||
          anyDuplicated(unlist(context[["plan_ids"]])) ||
          length(report[["selections"]]) != 4L
      ) {
        stop("Missing distinct shared-pool selections")
      }
      selection_checks <- vector("list", length(profiles))
      for (i in seq_along(profiles)) {
        trusted <- context
        trusted[["profile"]] <- profiles[[i]]
        trusted[["plan_id"]] <- context[["plan_ids"]][[i]]
        selection_checks[[i]] <- openid_check_report(
          report[["selections"]][[i]],
          trusted,
          manifest
        )
        if (!isTRUE(selection_checks[[i]][["gate_passed"]])) {
          stop(
            "A shared-pool client selection failed its protocol evidence gate"
          )
        }
      }
      sequence <- openid_shared_sequence()
      rows <- lapply(sequence, function(step) {
        report[["selections"]][[step[["selection"]]]][["results"]][[step[[
          "case"
        ]]]]
      })
      ids <- vapply(rows, function(row) row[["suite_id"]], character(1))
      if (
        anyDuplicated(ids) ||
          !identical(report[["execution_order"]], as.list(ids))
      ) {
        stop("Shared fixture order changed")
      }
      probes <- rows[[1L]][["app"]][["transport"]][["probes"]]
      app_pid <- rows[[1L]][["app"]][["transport"]][["app_pid"]]
      if (
        !all(vapply(
          rows,
          function(row) {
            identical(row[["app"]][["transport"]][["app_pid"]], app_pid) &&
              identical(row[["app"]][["transport"]][["probes"]], probes)
          },
          logical(1)
        ))
      ) {
        stop("Shared process or pool was replaced")
      }
      for (name in c("app_instance", "cache_instance")) {
        instances <- vapply(
          rows,
          function(row) row[["app"]][[name]],
          character(1)
        )
        if (
          anyDuplicated(instances) ||
            !all(vapply(
              rows,
              function(row) {
                identical(row[["initial"]][[name]], row[["app"]][[name]])
              },
              logical(1)
            ))
        ) {
          stop("Client app or cache scope was reused across issuers")
        }
      }
      pids_for <- function(index) {
        unique(unlist(lapply(rows[index], function(row) {
          row[["app"]][["transport"]][["worker_pids"]]
        })))
      }
      if (
        !length(intersect(
          pids_for(c(1L, 3L, 5L, 7L)),
          pids_for(c(2L, 4L, 6L, 8L))
        ))
      ) {
        stop("No worker performed protocol work for both client methods")
      }
      if (
        length(report[["worker_states"]]) != 8L ||
          !openid_shared_state_matches(
            report[["initial_worker_state"]],
            probes
          ) ||
          !all(vapply(
            report[["worker_states"]],
            function(state) {
              identical(sort(names(state)), c("after", "before")) &&
                all(vapply(
                  state,
                  openid_shared_state_matches,
                  logical(1),
                  probes = probes
                ))
            },
            logical(1)
          ))
      ) {
        stop("Worker cleanup between cases was not established")
      }
      for (name in c(
        "registrations_distinct",
        "issuers_distinct",
        "audit_files_unchanged",
        "driver_failure_control_passed",
        "cleanup_verified"
      )) {
        if (!isTRUE(report[[name]])) {
          stop("Shared-pool isolation or cleanup proof is missing")
        }
      }
      check <- list(
        gate_passed = TRUE,
        selection_complete = TRUE,
        coverage_complete = FALSE,
        coverage_limitations = list(
          "shared_pool_sequential_reuse_only",
          "comprehensive_plan_selection_only",
          "suite_public_variant_omits_none_in_discovery",
          "suite_skips_pkce_verifier_check_companion_verifies_requests"
        ),
        reason = NULL
      )
      sums <- function(name) {
        fields <- names(selection_checks[[1L]][["assessment"]][[name]])
        setNames(
          lapply(fields, function(field) {
            sum(vapply(
              selection_checks,
              function(selection) {
                selection[["assessment"]][[name]][[field]]
              },
              numeric(1)
            ))
          }),
          fields
        )
      }
      c(
        check,
        list(
          upstream_plan_complete = all(vapply(
            selection_checks,
            function(selection) selection[["upstream_plan_complete"]],
            logical(1)
          )),
          assessment = list(
            schema_version = 1L,
            status = "validated",
            certification_status = "not_assessed",
            plan_count = length(selection_checks),
            module_counts = sums("module_counts"),
            suite_verdict_counts = sums("suite_verdict_counts"),
            accepted_non_passed_results = as.list(unlist(
              lapply(
                selection_checks,
                function(selection) {
                  selection[["assessment"]][["accepted_non_passed_results"]]
                }
              ),
              recursive = FALSE
            )),
            limitations = openid_assessment_limitations(c(
              check[["coverage_limitations"]],
              unlist(
                lapply(selection_checks, function(selection) {
                  selection[["assessment"]][["limitations"]]
                }),
                use.names = FALSE
              )
            ))
          )
        )
      )
    },
    error = function(error) {
      c(
        list(
          gate_passed = FALSE,
          selection_complete = FALSE,
          coverage_complete = FALSE,
          reason = conditionMessage(error)
        ),
        openid_failed_assessment()
      )
    }
  )
}
