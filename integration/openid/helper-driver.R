openid_stop_app <- function(app) {
  process <- app[["process"]]
  if (process[["is_alive"]]()) {
    process[["kill"]]()
  }
  process[["wait"]](timeout = 5000)
  if (process[["is_alive"]]()) {
    stop("OpenID fixture app did not stop")
  }
  invisible(NULL)
}

openid_wait_app <- function(app, browser, tab, terminal = FALSE, timeout = 30) {
  openid_wait(
    function() {
      if (!app[["process"]][["is_alive"]]()) {
        stop("OpenID fixture app stopped before an outcome")
      }
      if (!browser[["get_browser"]]()[["get_process"]]()[["is_alive"]]()) {
        stop("OpenID fixture browser stopped")
      }
      value <- tryCatch(
        openid_app_snapshot(tab, app[["config"]][["run_id"]]),
        error = function(...) NULL
      )
      if (is.null(value)) {
        return(NULL)
      }
      if (
        !terminal ||
          isTRUE(value[["authenticated"]]) ||
          !is.null(value[["error_code"]])
      ) {
        return(value)
      }
      NULL
    },
    "OpenID app outcome",
    timeout
  )
}

openid_run_case <- function(
  root,
  stack,
  plan,
  expectation,
  context,
  transport,
  library,
  .after_login = NULL
) {
  module <- openid_suite_module(stack, plan, expectation[["module"]])
  config <- list(
    issuer = module[["issuer"]],
    client_id = plan[["registration"]][["client_id"]],
    client_secret = plan[["registration"]][["client_secret"]],
    response_mode = "query",
    run_id = paste0(context[["run_id"]], "-", module[["id"]])
  )
  app <- openid_app_start(root, stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  initial <- openid_wait_app(app, browser, tab)
  if (
    !isTRUE(initial[["ready"]]) ||
      isTRUE(initial[["authenticated"]]) ||
      isTRUE(initial[["has_token"]]) ||
      !is.null(initial[["error_code"]])
  ) {
    stop("OpenID fixture did not start in a clean state")
  }
  chrome <- tab[["Browser"]][["getVersion"]]()[["product"]]
  openid_browser_value(tab, "document.querySelector('#login').click()")
  if (!is.null(.after_login)) {
    .after_login(app)
  }
  snapshot <- openid_wait_app(app, browser, tab, terminal = TRUE)
  info <- openid_suite_wait(stack, module, "FINISHED", timeout = 45)
  runtime <- openid_api(stack, paste0("/api/runner/", module[["id"]]))
  if (!identical(runtime[["id"]], module[["id"]])) {
    stop("OpenID runner instance changed during the flow")
  }
  if (!identical(openid_browser_value(tab, "location.search"), "")) {
    stop("OpenID callback URL was not cleaned")
  }
  row <- context[c(
    "run_id",
    "attempt_id",
    "checkout_revision",
    "source_revision",
    "plan_id"
  )]
  row[["module"]] <- module[["name"]]
  row[["suite_id"]] <- module[["id"]]
  row[["variant"]] <- info[["variant"]]
  row[["suite_status"]] <- info[["status"]]
  row[["suite_result"]] <- info[["result"]]
  row[["exception"]] <- if (is.null(runtime[["error"]])) {
    NULL
  } else {
    "suite_exception"
  }
  row[["app"]] <- snapshot
  row[["browser_version"]] <- chrome
  row[["callback_cleaned"]] <- TRUE
  row[["optional_policy"]] <- expectation[["optional_policy"]]
  openid_stop_app(app)
  openid_close_browser(browser)
  cat(
    "OpenID module ",
    module[["name"]],
    ": ",
    info[["status"]],
    "/",
    info[["result"]],
    "\n",
    sep = ""
  )
  row
}

openid_driver_failure_control <- function(
  root,
  stack,
  manifest,
  context,
  transport,
  library
) {
  plan <- openid_suite_plan(stack, manifest, paste0(transport[["origin"]], "/"))
  control_context <- context
  control_context[["plan_id"]] <- plan[["id"]]
  failure <- tryCatch(
    openid_run_case(
      root,
      stack,
      plan,
      manifest[["profiles"]][["smoke"]][["modules"]][[1L]],
      control_context,
      transport,
      library,
      .after_login = openid_stop_app
    ),
    error = identity
  )
  if (
    !inherits(failure, "error") ||
      !identical(
        conditionMessage(failure),
        "OpenID fixture app stopped before an outcome"
      )
  ) {
    stop("Stopping the real app did not fail the browser driver as expected")
  }
  TRUE
}
