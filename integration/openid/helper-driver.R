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

openid_trusted_login_click <- function(tab, origin) {
  if (!identical(openid_browser_value(tab, "location.origin"), origin)) {
    stop("Login button is outside the fixture origin")
  }
  binding <- paste0(
    "openidLoginActivation",
    paste(format(openssl::rand_bytes(8)), collapse = "")
  )
  observed <- NULL
  tab[["Runtime"]][["addBinding"]](name = binding)
  tab[["Runtime"]][["bindingCalled"]](function(event) {
    if (is.null(observed) && identical(event[["name"]], binding)) {
      observed <<- event[["payload"]]
    }
  })
  point <- openid_browser_value(
    tab,
    paste0(
      "(() => {",
      " const button = document.querySelector('#login');",
      " if (!button || button.disabled) return null;",
      " button.scrollIntoView({block: 'center'});",
      " const {left, top, width, height} = button.getBoundingClientRect();",
      " const x = left + width / 2, y = top + height / 2;",
      " if (!button.contains(document.elementFromPoint(x, y))) return null;",
      " const report = window.",
      binding,
      ";",
      " button.addEventListener('click', event => {",
      "   report(event.isTrusted && navigator.userActivation.isActive ? 'active' : 'inactive');",
      " }, {once: true, capture: true});",
      " return {x, y};",
      "})()"
    )
  )
  if (is.null(point)) {
    stop("Chrome could not locate the visible fixture login button")
  }
  for (type in c("mousePressed", "mouseReleased")) {
    tab[["Input"]][["dispatchMouseEvent"]](
      type = type,
      x = point[["x"]],
      y = point[["y"]],
      button = "left",
      clickCount = 1L
    )
  }
  activated <- openid_wait(
    function() {
      later::run_now(0)
      observed
    },
    "Chrome login click activation",
    timeout = 5
  )
  if (!identical(activated, "active")) {
    stop("Chrome did not report a trusted login click with user activation")
  }
  TRUE
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
  .after_login = NULL,
  .start_app = openid_app_start,
  .stop_app = openid_stop_app,
  .shared_pool = FALSE,
  .resource_control = NULL
) {
  module <- openid_suite_module(stack, plan, expectation[["module"]])
  form_post <- identical(
    utils::modifyList(
      plan[["spec"]][["plan_variant"]],
      as.list(plan[["spec"]][["module_variant"]])
    )[["response_mode"]],
    "form_post"
  )
  config <- list(
    state_transport = plan[["state_transport"]],
    sender_constraint = plan[["spec"]][["plan_variant"]][["sender_constrain"]],
    mtls = plan[["credentials"]][["mtls"]],
    resource_control = .resource_control,
    issuer = module[["issuer"]],
    client_id = plan[["registration"]][["client_id"]],
    client_secret = plan[["credentials"]][["client_secret"]],
    client_auth_type = utils::modifyList(
      plan[["spec"]][["plan_variant"]],
      as.list(plan[["spec"]][["module_variant"]])
    )[["client_auth_type"]],
    client_assertion_private_key = plan[["credentials"]][["private_key"]],
    client_assertion_private_key_kid = plan[["credentials"]][["key_id"]],
    client_assertion_alg = plan[["spec"]][["client_assertion_alg"]],
    fapi = openid_fapi_plan(plan[["spec"]][["plan"]]),
    direct_configuration = isTRUE(expectation[["direct_configuration"]]),
    message_signing = identical(
      plan[["spec"]][["plan"]],
      "fapi2-message-signing-final-client-test-plan"
    ),
    resource_endpoint = module[["resource_endpoint"]],
    oauth_only = identical(
      plan[["spec"]][["plan_variant"]][["fapi_client_type"]],
      "plain_oauth"
    ),
    scopes = strsplit(plan[["registration"]][["scope"]], " ", fixed = TRUE)[[
      1L
    ]],
    callback_rejection = identical(
      expectation[["outcome"]],
      "callback_rejected"
    ),
    response_mode = if (
      identical(
        plan[["spec"]][["plan_variant"]][["fapi_response_mode"]],
        "jarm"
      )
    ) {
      "jwt"
    } else if (form_post) {
      "form_post"
    } else {
      "query"
    },
    provider_origin = stack[["origin"]],
    cross_site_form_post = identical(
      context[["profile"]],
      "form-post-cross-site"
    ),
    extra_auth_params = if (
      identical(expectation[["outcome"]], "authorization_error")
    ) {
      list(prompt = "none", max_age = 0)
    } else {
      NULL
    },
    transport = context[["transport"]],
    run_id = paste0(context[["run_id"]], "-", module[["id"]]),
    preload_jwks = isTRUE(expectation[["preload_jwks"]]),
    report_setup_failure = identical(
      expectation[["outcome"]],
      "discovery_rejected"
    )
  )
  app <- .start_app(root, stack, transport, config, library)
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
  http_observation <- if (isTRUE(config[["callback_rejection"]])) {
    openid_observe_http_callback(tab, app[["origin"]])
  } else {
    NULL
  }
  callback_http <- NULL
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
  initiation <- NULL
  if (isTRUE(expectation[["manual_initiation"]])) {
    observed <- openid_fapi_pre_token_evidence(
      openid_api(stack, paste0("/api/log/", module[["id"]])),
      module,
      plan,
      expectation
    )
    initiation <- observed[c(
      "discovery_request_count",
      "par_request_count",
      "authorization_request_count",
      "token_request_count"
    )]
    initiation[["login_control_ready"]] <-
      identical(
        openid_browser_value(tab, "location.origin"),
        app[["origin"]]
      ) &&
      isTRUE(openid_browser_value(
        tab,
        "(() => { const button = document.querySelector('#login'); return !!button && !button.disabled && button.getClientRects().length > 0; })()"
      ))
  }
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
      if (i == 1L && isTRUE(expectation[["trusted_initiation"]])) {
        initiation[["trusted_user_activation"]] <- openid_trusted_login_click(
          tab,
          app[["origin"]]
        )
      } else {
        openid_browser_value(tab, "document.querySelector('#login').click()")
      }
      if (!is.null(.after_login)) {
        .after_login(app)
      }
      snapshot <- if (isTRUE(config[["callback_rejection"]])) {
        rejected <- openid_wait_http_callback(
          app,
          browser,
          tab,
          initial,
          http_observation
        )
        callback_http <- rejected[["http"]]
        rejected[["app"]]
      } else {
        openid_wait_app(
          app,
          browser,
          tab,
          terminal = TRUE,
          after_session = before_login[["session_number"]]
        )
      }
      steps[[i]] <- snapshot
      if (
        is.null(callback_http) &&
          !identical(openid_browser_value(tab, "location.search"), "")
      ) {
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
  if (
    isTRUE(config[["fapi"]]) &&
      expectation[["outcome"]] %in% c("authenticated", "authorized")
  ) {
    openid_browser_value(tab, "document.querySelector('#resource').click()")
    snapshot <- openid_wait(
      function() {
        value <- openid_wait_app(app, browser, tab)
        if (isTRUE(value[["resource"]][["done"]])) value else NULL
      },
      "FAPI public connection resource request",
      30
    )
  }
  info <- openid_suite_wait(
    stack,
    module,
    if (is.null(.resource_control)) {
      "FINISHED"
    } else {
      c("FINISHED", "INTERRUPTED")
    },
    timeout = 45
  )
  runtime <- openid_api(stack, paste0("/api/runner/", module[["id"]]))
  if (!identical(runtime[["id"]], module[["id"]])) {
    stop("OpenID runner instance changed during the flow")
  }
  if (
    is.null(callback_http) &&
      !identical(openid_browser_value(tab, "location.search"), "")
  ) {
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
  if (!is.null(initiation)) {
    row[["authorization_initiation"]] <- initiation
  }
  row[["callback_http"]] <- callback_http
  if (openid_auth_profile(context[["profile"]])) {
    row[["client_auth"]] <- openid_auth_evidence(
      openid_api(stack, paste0("/api/log/", module[["id"]])),
      module,
      plan
    )
  }
  if (identical(context[["profile"]], "form-post-cross-site")) {
    if (identical(expectation[["outcome"]], "authorization_error")) {
      row[["form_post_error"]] <- list(
        visible = identical(
          openid_browser_value(
            tab,
            "document.querySelector('#authorization_error').textContent"
          ),
          "Authorization requires login."
        ),
        provider_description_absent = !grepl(
          "This is a login_required error response",
          openid_browser_value(tab, "document.body.textContent"),
          fixed = TRUE
        )
      )
    }
    row[["form_post_tls"]] <- list(
      app_origin = app[["origin"]],
      ca_verified = isTRUE(app[["tls_verified"]]),
      wrong_pin_rejected = openid_app_wrong_pin(stack, app[["origin"]])
    )
    row[["form_post_requests"]] <- openid_form_post_requests(
      openid_api(stack, paste0("/api/log/", module[["id"]])),
      module,
      plan,
      expectation
    )
  }
  row[["browser_version"]] <- chrome
  if (isTRUE(config[["fapi"]])) {
    logs <- openid_api(stack, paste0("/api/log/", module[["id"]]))
    if (isTRUE(config[["message_signing"]])) {
      row[["message_signing"]] <- openid_signing_evidence(
        logs,
        module,
        plan,
        expectation
      )
    }
    row[["fapi"]] <- if (identical(config[["sender_constraint"]], "mtls")) {
      openid_mtls_evidence(
        logs,
        module,
        plan,
        openid_mtls_peers(stack),
        expectation
      )
    } else {
      openid_fapi_evidence(
        logs,
        module,
        plan,
        expectation
      )
    }
  }
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
    row[["callback_cleaned"]] <- if (!is.null(callback_http)) {
      isTRUE(callback_http[["final_url_verified"]])
    } else {
      identical(openid_browser_value(tab, "location.search"), "")
    }
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
  .stop_app(app)
  row[["worker_cleanup_verified"]] <- !.shared_pool
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
