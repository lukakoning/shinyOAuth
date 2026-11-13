openid_stop_app <- function(app) {
  process <- app[["process"]]
  children <- if (process[["is_alive"]]()) {
    ps::ps_children(ps::ps_handle(process[["get_pid"]]()), recursive = TRUE)
  } else {
    list()
  }
  children <- c(children, app[["worker_handles"]])
  if (process[["is_alive"]]() && .Platform[["OS.type"]] != "windows") {
    process[["interrupt"]]()
    process[["wait"]](timeout = 5000)
  }
  if (process[["is_alive"]]()) {
    process[["kill_tree"]]()
  }
  process[["wait"]](timeout = 5000)
  if (process[["is_alive"]]()) {
    stop("OpenID fixture app did not stop")
  }
  openid_wait(
    function() !any(vapply(children, ps::ps_is_running, logical(1))),
    "OpenID fixture worker cleanup",
    15
  )
  invisible(NULL)
}

openid_wait_app <- function(
  app,
  browser,
  tab,
  terminal = FALSE,
  timeout = 30,
  after_session = NULL
) {
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
        !is.null(after_session) &&
          !openid_count(value[["session_number"]], after_session + 1L)
      ) {
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

openid_form_post_navigation <- function(
  tab,
  issuer,
  provider_origin,
  app_origin
) {
  observation <- new.env(parent = emptyenv())
  observation[["provider_origin"]] <- provider_origin
  observation[["app_origin"]] <- app_origin
  observation[["bridge_redirect_303"]] <- FALSE
  root <- paste0(app_origin, "/")
  tab[["Network"]][["enable"]]()
  tab[["Network"]][["requestWillBeSent"]](function(params) {
    if (!identical(params[["type"]], "Document")) {
      return(invisible(NULL))
    }
    request <- params[["request"]]
    url <- request[["url"]]
    if (!openid_string(url)) {
      return(invisible(NULL))
    }
    endpoint <- sub("[?#].*$", "", url)
    if (identical(endpoint, paste0(issuer, "authorize"))) {
      observation[["authorization_method"]] <- request[["method"]]
    }
    if (identical(endpoint, root) && identical(request[["method"]], "POST")) {
      observation[["callback_method"]] <- "POST"
    }
    redirect <- params[["redirectResponse"]]
    if (
      identical(endpoint, root) &&
        identical(request[["method"]], "GET") &&
        identical(redirect[["url"]], root) &&
        isTRUE(redirect[["status"]] == 303)
    ) {
      observation[["bridge_redirect_303"]] <- TRUE
    }
    invisible(NULL)
  })
  observation
}

openid_form_post_cookie <- function(tab, app_origin) {
  openid_wait(
    function() {
      cookies <- tab[["Network"]][["getCookies"]](urls = list(app_origin))[[
        "cookies"
      ]]
      cookies <- Filter(
        function(cookie) {
          startsWith(cookie[["name"]], "__Host-shinyOAuth_sid-auth-")
        },
        cookies
      )
      if (!length(cookies)) {
        return(NULL)
      }
      policies <- unique(vapply(
        cookies,
        function(cookie) {
          if (is.null(cookie[["sameSite"]])) "missing" else cookie[["sameSite"]]
        },
        character(1)
      ))
      list(
        binding_cookie_count = length(cookies),
        secure = all(vapply(
          cookies,
          function(cookie) isTRUE(cookie[["secure"]]),
          logical(1)
        )),
        same_site = if (length(policies) == 1L) policies else "mixed",
        http_only = all(vapply(
          cookies,
          function(cookie) isTRUE(cookie[["httpOnly"]]),
          logical(1)
        ))
      )
    },
    "OpenID browser binding cookie",
    15
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
  form_post <- identical(
    plan[["spec"]][["module_variant"]][["response_mode"]],
    "form_post"
  )
  config <- list(
    issuer = module[["issuer"]],
    client_id = plan[["registration"]][["client_id"]],
    client_secret = plan[["registration"]][["client_secret"]],
    response_mode = if (form_post) "form_post" else "query",
    provider_origin = stack[["origin"]],
    transport = context[["transport"]],
    run_id = paste0(context[["run_id"]], "-", module[["id"]]),
    preload_jwks = isTRUE(expectation[["preload_jwks"]]),
    report_setup_failure = identical(
      expectation[["outcome"]],
      "discovery_rejected"
    )
  )
  app <- openid_app_start(root, stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  navigation <- if (form_post) {
    openid_form_post_navigation(
      tab,
      module[["issuer"]],
      stack[["origin"]],
      app[["origin"]]
    )
  } else {
    NULL
  }
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  initial <- openid_wait_app(app, browser, tab)
  app[["worker_handles"]] <- lapply(
    initial[["transport"]][["probes"]],
    function(probe) ps::ps_handle(probe[["pid"]])
  )
  discovery <- identical(expectation[["action"]], "discovery")
  if (
    (!discovery && !isTRUE(initial[["ready"]])) ||
      isTRUE(initial[["authenticated"]]) ||
      isTRUE(initial[["has_token"]]) ||
      (!discovery && !is.null(initial[["error_code"]]))
  ) {
    stop("OpenID fixture did not start in a clean state")
  }
  chrome <- tab[["Browser"]][["getVersion"]]()[["product"]]
  cookie <- if (form_post) {
    openid_form_post_cookie(tab, app[["origin"]])
  } else {
    NULL
  }
  secure_context <- if (form_post) {
    openid_browser_value(tab, "window.isSecureContext")
  } else {
    NULL
  }
  steps <- list()
  between <- list()
  snapshot <- initial
  if (!discovery) {
    logins <- expectation[["logins"]]
    if (is.null(logins)) {
      logins <- 1L
    }
    for (i in seq_len(logins)) {
      before_login <- initial
      if (i > 1L) {
        openid_browser_value(tab, "document.querySelector('#logout').click()")
        between[[length(between) + 1L]] <- openid_wait(
          function() {
            value <- openid_wait_app(app, browser, tab)
            if (
              identical(value[["authenticated"]], FALSE) &&
                identical(value[["has_token"]], FALSE)
            ) {
              value
            } else {
              NULL
            }
          },
          "OpenID local logout",
          15
        )
        before_login <- between[[length(between)]]
      }
      openid_browser_value(tab, "document.querySelector('#login').click()")
      if (!is.null(.after_login)) {
        .after_login(app)
      }
      snapshot <- openid_wait_app(
        app,
        browser,
        tab,
        terminal = TRUE,
        after_session = before_login[["session_number"]]
      )
      steps[[i]] <- snapshot
      if (!identical(openid_browser_value(tab, "location.search"), "")) {
        stop("OpenID callback URL was not cleaned")
      }
    }
  }
  before_refresh <- NULL
  refreshing <- identical(expectation[["action"]], "refresh")
  if (refreshing) {
    before_refresh <- snapshot
    if (
      !openid_app_matches(
        before_refresh,
        list(outcome = "authenticated"),
        config[["run_id"]],
        context[["package_version"]]
      ) ||
        !isTRUE(before_refresh[["has_refresh_token"]])
    ) {
      stop(
        "OpenID refresh requires the original validated login and refresh grant"
      )
    }
    openid_browser_value(tab, "document.querySelector('#refresh').click()")
    snapshot <- openid_wait(
      function() {
        value <- openid_wait_app(app, browser, tab)
        if (isTRUE(value[["refresh"]][["done"]])) value else NULL
      },
      "OpenID public connection refresh",
      30
    )
  }
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
  row[["action"]] <- if (discovery) {
    "discovery"
  } else if (refreshing) {
    "refresh"
  } else {
    "login"
  }
  row[["before_refresh"]] <- before_refresh
  if (discovery) {
    row[["no_callback"]] <- TRUE
  } else {
    row[["callback_cleaned"]] <- TRUE
  }
  row[["initial"]] <- initial
  row[["steps"]] <- steps
  row[["between_logins"]] <- between
  row[["optional_policy"]] <- expectation[["optional_policy"]]
  if (form_post) {
    row[["form_post"]] <- as.list(navigation)
    row[["form_post"]][["cookie"]] <- cookie
    row[["form_post"]][["secure_context"]] <- secure_context
    row[["form_post"]][["cross_origin"]] <- !identical(
      stack[["origin"]],
      app[["origin"]]
    )
    row[["form_post"]][["cross_site"]] <- identical(
      snapshot[["form_post"]][["sec_fetch_site"]],
      "cross-site"
    )
  }
  openid_stop_app(app)
  row[["worker_cleanup_verified"]] <- TRUE
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
    writeLines(
      if (inherits(failure, "error")) {
        conditionMessage(failure)
      } else {
        "Unexpected driver success"
      },
      file.path(stack[["output"]], "driver-control.stderr")
    )
    stop(
      "Stopping the real app did not fail the browser driver as expected; inspect private driver-control.stderr"
    )
  }
  TRUE
}
