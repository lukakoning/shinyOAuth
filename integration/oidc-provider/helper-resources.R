interop_run_resources <- function(
  root,
  environment,
  transport,
  library,
  context,
  selection
) {
  id <- paste(format(openssl::rand_bytes(16)), collapse = "")
  config <- list(
    run_id = id,
    client_id = paste0("client-", id),
    client_secret = paste(format(openssl::rand_bytes(32)), collapse = ""),
    client_auth_type = "client_secret_basic",
    response_mode = "query",
    redirect_uri = paste0(transport[["origin"]], "/"),
    scopes = c("openid", "profile", "offline_access", "api.read"),
    extra_auth_params = list(prompt = "consent"),
    resource_indicators = list(target = selection[["target"]]),
    transport = context[["transport"]]
  )
  stack <- interop_start(environment, config)
  config[["issuer"]] <- config[["provider_origin"]] <- stack[["origin"]]
  config[["resource"]] <- paste0(
    stack[["origin"]],
    "/resource/",
    selection[["target"]]
  )
  metadata <- interop_request(stack, "/.well-known/openid-configuration")
  if (
    !is.null(metadata[["userinfo_endpoint"]]) ||
      !is.null(metadata[["pushed_authorization_request_endpoint"]]) ||
      !identical(metadata[["issuer"]], stack[["origin"]]) ||
      !identical(
        metadata[["introspection_endpoint"]],
        paste0(stack[["origin"]], "/token/introspection")
      )
  ) {
    stop("Resource profile discovery failed preflight")
  }
  app <- openid_app_start(root, stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  initial <- openid_wait_app(app, browser, tab)
  app[["worker_handles"]] <- lapply(
    initial[["transport"]][["probes"]],
    function(probe) ps::ps_handle(probe[["pid"]])
  )
  positive <- identical(selection[["outcome"]], "authenticated")
  request_evidence <- new.env(parent = emptyenv())
  tab[["Network"]][["enable"]]()
  tab[["Network"]][["requestWillBeSent"]](function(params) {
    request <- params[["request"]]
    url <- request[["url"]]
    if (!startsWith(url, paste0(stack[["origin"]], "/authorize?"))) {
      return(invisible(NULL))
    }
    query <- httr2::url_parse(url)[["query"]]
    request_evidence[["method"]] <- request[["method"]]
    request_evidence[["resource_matches"]] <- identical(
      query[["resource"]],
      config[["resource"]]
    )
    request_evidence[["direct"]] <- is.null(query[["request"]]) &&
      is.null(query[["request_uri"]])
    request_evidence[["pkce_s256"]] <- identical(
      query[["code_challenge_method"]],
      "S256"
    ) &&
      isTRUE(grepl("^[A-Za-z0-9_-]{43}$", query[["code_challenge"]]))
  })
  openid_browser_value(tab, "document.querySelector('#login').click()")
  if (positive) {
    for (prompt in c("login", "consent")) {
      selector <- paste0("#fixture-", prompt)
      openid_wait(
        function() {
          isTRUE(openid_browser_value(
            tab,
            paste0("!!document.querySelector('", selector, "')")
          ))
        },
        paste("Resource", prompt),
        30
      )
      openid_browser_value(
        tab,
        paste0("document.querySelector('", selector, "').click()")
      )
    }
  }
  before <- openid_wait_app(
    app,
    browser,
    tab,
    terminal = TRUE,
    after_session = initial[["session_number"]]
  )
  after <- before
  reads <- probes <- NULL
  if (positive) {
    if (!isTRUE(before[["id_token_validated"]])) {
      stop("Resource login did not validate its ID token")
    }
    for (phase in 1:2) {
      if (phase == 2L) {
        openid_browser_value(tab, "document.querySelector('#refresh').click()")
        after <- openid_wait(
          function() {
            value <- openid_wait_app(app, browser, tab)
            if (isTRUE(value[["refresh"]][["done"]])) value else NULL
          },
          "Resource connection refresh",
          30
        )
      }
      openid_browser_value(tab, "document.querySelector('#resource').click()")
      value <- openid_wait(
        function() {
          value <- openid_wait_app(app, browser, tab)
          if (length(value[["resource_checks"]][["reads"]]) == phase) {
            value
          } else {
            NULL
          }
        },
        "Resource connection request",
        30
      )
      reads <- value[["resource_checks"]][["reads"]]
    }
    openid_browser_value(
      tab,
      "document.querySelector('#resource_probes').click()"
    )
    value <- openid_wait(
      function() {
        value <- openid_wait_app(app, browser, tab)
        if (isTRUE(value[["resource_checks"]][["probes"]][["done"]])) {
          value
        } else {
          NULL
        }
      },
      "Resource audience rejection controls",
      30
    )
    probes <- value[["resource_checks"]][["probes"]]
  }
  row <- list(
    id = selection[["id"]],
    target = selection[["target"]],
    outcome = selection[["outcome"]],
    case_id = id,
    run_id = context[["run_id"]],
    checkout_revision = context[["checkout_revision"]],
    provider_origin = stack[["origin"]],
    app_origin = app[["origin"]],
    resource_uri = config[["resource"]],
    discovery = metadata[intersect(
      names(metadata),
      c(
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "introspection_endpoint"
      )
    )],
    initial = initial,
    before_refresh = before,
    app = after,
    reads = reads,
    probes = probes,
    authorization_request = as.list(request_evidence),
    provider = interop_request(stack, "/fixture/evidence", TRUE),
    callback_cleaned = identical(
      openid_browser_value(tab, "location.search"),
      ""
    ),
    browser_version = tab[["Browser"]][["getVersion"]]()[["product"]]
  )
  openid_stop_app(app)
  row[["worker_cleanup_verified"]] <- TRUE
  openid_close_browser(browser)
  interop_stop(stack)
  row[["cleanup_verified"]] <- TRUE
  cat("Resource case", row[["id"]], context[["transport"]], "completed\n")
  row
}
