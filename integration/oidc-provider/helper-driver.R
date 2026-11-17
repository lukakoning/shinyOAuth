interop_discovery <- function(stack) {
  metadata <- interop_request(stack, "/.well-known/openid-configuration")
  selected <- metadata[c(
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "response_types_supported",
    "response_modes_supported",
    "code_challenge_methods_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "id_token_signing_alg_values_supported"
  )]
  if (
    !identical(selected[["issuer"]], stack[["origin"]]) ||
      !all(
        c("query", "form_post") %in%
          unlist(selected[["response_modes_supported"]])
      ) ||
      !identical(
        unlist(selected[["code_challenge_methods_supported"]]),
        "S256"
      ) ||
      !all(
        c("authorization_code", "refresh_token") %in%
          unlist(selected[["grant_types_supported"]])
      ) ||
      !all(
        c("none", "client_secret_basic") %in%
          unlist(selected[["token_endpoint_auth_methods_supported"]])
      ) ||
      !"RS256" %in% unlist(selected[["id_token_signing_alg_values_supported"]])
  ) {
    stop("Provider discovery failed required capability preflight")
  }
  for (name in c(
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri"
  )) {
    if (
      !openid_string(selected[[name]]) ||
        !startsWith(selected[[name]], paste0(stack[["origin"]], "/"))
    ) {
      stop("Provider endpoint is outside its local issuer")
    }
  }
  selected
}

interop_pkce_control <- function(stack, config) {
  response <- httr2::request(paste0(stack[["origin"]], "/authorize")) |>
    httr2::req_url_query(
      client_id = config[["client_id"]],
      redirect_uri = config[["redirect_uri"]],
      response_type = "code",
      scope = "openid",
      response_mode = "query"
    ) |>
    httr2::req_options(cainfo = stack[["ca"]], followlocation = FALSE) |>
    httr2::req_timeout(5) |>
    httr2::req_perform()
  location <- httr2::resp_header(response, "location")
  query <- if (openid_string(location)) {
    httr2::url_parse(location)[["query"]]
  } else {
    list()
  }
  httr2::resp_status(response) %in%
    c(302L, 303L) &&
    identical(sub("\\?.*$", "", location), config[["redirect_uri"]]) &&
    identical(query[["error"]], "invalid_request") &&
    !"code" %in% names(query)
}

interop_run_case <- function(
  root,
  environment,
  transport,
  library,
  context,
  selection,
  .stop_before_login = FALSE
) {
  run_id <- paste(format(openssl::rand_bytes(16)), collapse = "")
  config <- list(
    run_id = run_id,
    issuer = NULL,
    provider_origin = NULL,
    client_id = paste0("client-", run_id),
    client_secret = if (identical(selection[["client_auth_type"]], "none")) {
      NULL
    } else {
      paste(format(openssl::rand_bytes(32)), collapse = "")
    },
    client_auth_type = selection[["client_auth_type"]],
    response_mode = selection[["response_mode"]],
    redirect_uri = paste0(transport[["origin"]], "/"),
    scopes = c("openid", "profile", "email", "offline_access"),
    extra_auth_params = list(prompt = "consent"),
    transport = context[["transport"]]
  )
  stack <- interop_start(environment, config)
  config[["issuer"]] <- config[["provider_origin"]] <- stack[["origin"]]
  discovery <- interop_discovery(stack)
  pkce_control <- interop_pkce_control(stack, config)
  if (!isTRUE(pkce_control)) {
    stop("Provider accepted a request without required PKCE")
  }
  app <- openid_app_start(root, stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  form_post <- identical(selection[["response_mode"]], "form_post")
  navigation <- if (form_post) {
    openid_form_post_navigation(
      tab,
      paste0(stack[["origin"]], "/"),
      stack[["origin"]],
      app[["origin"]]
    )
  } else {
    NULL
  }
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  initial <- openid_wait_app(app, browser, tab)
  if (
    isTRUE(initial[["authenticated"]]) ||
      isTRUE(initial[["has_token"]]) ||
      !is.null(initial[["error_code"]])
  ) {
    stop("Provider app did not start cleanly")
  }
  app[["worker_handles"]] <- lapply(
    initial[["transport"]][["probes"]],
    function(probe) ps::ps_handle(probe[["pid"]])
  )
  if (.stop_before_login) {
    openid_stop_app(app)
    openid_wait_app(app, browser, tab, terminal = TRUE)
    stop("Stopped app unexpectedly produced an outcome")
  }
  cookie <- if (form_post) {
    openid_form_post_cookie(tab, app[["origin"]])
  } else {
    NULL
  }
  openid_browser_value(tab, "document.querySelector('#login').click()")
  for (prompt in c("login", "consent")) {
    selector <- paste0("#fixture-", prompt)
    openid_wait(
      function() {
        isTRUE(openid_browser_value(
          tab,
          paste0("!!document.querySelector('", selector, "')")
        ))
      },
      paste("Provider", prompt, "interaction"),
      30
    )
    openid_browser_value(
      tab,
      paste0("document.querySelector('", selector, "').click()")
    )
  }
  before <- openid_wait_app(
    app,
    browser,
    tab,
    terminal = TRUE,
    after_session = initial[["session_number"]]
  )
  if (
    !openid_app_matches(
      before,
      list(outcome = "authenticated"),
      run_id,
      context[["package_version"]]
    ) ||
      !isTRUE(before[["has_refresh_token"]])
  ) {
    stop("Provider login did not yield validated identity and refresh grant")
  }
  openid_browser_value(tab, "document.querySelector('#refresh').click()")
  after <- openid_wait(
    function() {
      value <- openid_wait_app(app, browser, tab)
      if (isTRUE(value[["refresh"]][["done"]])) value else NULL
    },
    "Provider public connection refresh",
    30
  )
  row <- list(
    id = selection[["id"]],
    case_id = run_id,
    run_id = context[["run_id"]],
    checkout_revision = context[["checkout_revision"]],
    client_auth_type = selection[["client_auth_type"]],
    response_mode = selection[["response_mode"]],
    provider_origin = stack[["origin"]],
    app_origin = app[["origin"]],
    discovery = discovery,
    initial = initial,
    steps = list(before),
    before_refresh = before,
    app = after,
    between_logins = list(),
    action = "refresh",
    pkce_control_passed = pkce_control,
    provider = interop_request(stack, "/fixture/evidence", TRUE),
    callback_cleaned = identical(
      openid_browser_value(tab, "location.search"),
      ""
    ),
    browser_version = tab[["Browser"]][["getVersion"]]()[["product"]]
  )
  if (form_post) {
    row[["form_post"]] <- c(
      as.list(navigation),
      list(
        cookie = cookie,
        secure_context = openid_browser_value(tab, "window.isSecureContext"),
        cross_origin = !identical(stack[["origin"]], app[["origin"]]),
        cross_site = identical(
          after[["form_post"]][["sec_fetch_site"]],
          "cross-site"
        )
      )
    )
  }
  openid_stop_app(app)
  row[["worker_cleanup_verified"]] <- TRUE
  openid_close_browser(browser)
  interop_stop(stack)
  row[["cleanup_verified"]] <- TRUE
  cat(
    "oidc-provider case",
    selection[["id"]],
    context[["transport"]],
    "completed\n"
  )
  row
}
