interop_retention_action <- function(app, browser, tab, action) {
  before <- openid_wait_app(app, browser, tab)
  openid_browser_value(
    tab,
    paste0("document.querySelector('#", action, "').click()")
  )
  openid_wait(
    function() {
      value <- openid_wait_app(app, browser, tab)
      if (
        value[["result_revision"]] == before[["result_revision"]] + 1L &&
          identical(value[["result"]][["action"]], action) &&
          isTRUE(value[["result"]][["done"]])
      ) {
        value
      } else {
        NULL
      }
    },
    paste("Retained", action),
    30
  )
}

interop_retention_probe_id <- function(tab, id) {
  openid_browser_value(
    tab,
    paste0(
      "Shiny.setInputValue('probe_id',",
      jsonlite::toJSON(id, auto_unbox = TRUE),
      ",{priority:'event'})"
    )
  )
}

interop_run_retention <- function(
  root,
  environment,
  transport,
  library,
  context,
  selection,
  .stop_before_login = FALSE
) {
  id <- paste(format(openssl::rand_bytes(16)), collapse = "")
  config <- list(
    run_id = id,
    client_id = paste0("client-", id),
    client_secret = paste(format(openssl::rand_bytes(32)), collapse = ""),
    client_auth_type = "client_secret_basic",
    redirect_uri = paste0(transport[["origin"]], "/"),
    response_mode = selection[["response_mode"]],
    scopes = c("openid", "profile", "email", "offline_access"),
    transport = context[["transport"]],
    retention = TRUE
  )
  stack <- interop_start(environment, config)
  config[["issuer"]] <- config[["provider_origin"]] <- stack[["origin"]]
  discovery <- interop_discovery(stack)
  if (!isTRUE(interop_pkce_control(stack, config))) {
    stop("Retained provider PKCE control failed")
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
  app[["worker_handles"]] <- lapply(
    initial[["transport"]][["probes"]],
    function(probe) ps::ps_handle(probe[["pid"]])
  )
  if (.stop_before_login) {
    openid_stop_app(app)
    openid_wait_app(app, browser, tab, terminal = TRUE)
    stop("Stopped retained app unexpectedly produced an outcome")
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
      paste("Retained", prompt),
      30
    )
    openid_browser_value(
      tab,
      paste0("document.querySelector('", selector, "').click()")
    )
  }
  connected <- openid_wait(
    function() {
      value <- openid_wait_app(app, browser, tab)
      if (
        identical(value[["connection_count"]], 1L) &&
          isTRUE(value[["identity_verified"]]) &&
          value[["session_number"]] > initial[["session_number"]]
      ) {
        value
      } else {
        NULL
      }
    },
    "Managed OIDC authorization",
    30
  )
  callback_cleaned <- identical(
    openid_browser_value(tab, "location.search"),
    ""
  )
  connection_id <- connected[["connection_id"]]
  initial_read <- interop_retention_action(app, browser, tab, "read")
  page <- function(path, previous) {
    tab[["Page"]][["navigate"]](paste0(app[["origin"]], path))
    openid_wait_app(
      app,
      browser,
      tab,
      after_session = previous[["session_number"]]
    )
  }
  page_two <- page("/second/", initial_read)
  restored_read <- interop_retention_action(app, browser, tab, "read")
  refreshed <- interop_retention_action(app, browser, tab, "refresh")
  refreshed_read <- interop_retention_action(app, browser, tab, "read")
  page_one <- page("/", refreshed_read)
  returned_read <- interop_retention_action(app, browser, tab, "read")
  cookies <- tab[["Network"]][["getCookies"]](urls = list(app[["origin"]]))[[
    "cookies"
  ]]
  owners <- Filter(
    function(cookie) grepl("shinyOAuth-owner-", cookie[["name"]], fixed = TRUE),
    cookies
  )
  owner_cookie <- list(
    count = length(owners),
    secure = length(owners) == 1L && isTRUE(owners[[1L]][["secure"]]),
    http_only = length(owners) == 1L && isTRUE(owners[[1L]][["httpOnly"]]),
    same_site = if (length(owners) == 1L) owners[[1L]][["sameSite"]] else NULL,
    path = if (length(owners) == 1L) owners[[1L]][["path"]] else NULL,
    hidden_from_javascript = length(owners) == 1L &&
      !isTRUE(openid_browser_value(
        tab,
        paste0(
          "document.cookie.includes(",
          jsonlite::toJSON(owners[[1L]][["name"]], auto_unbox = TRUE),
          ")"
        )
      ))
  )
  foreign_browser <- openid_browser(stack[["spki"]])
  foreign_tab <- foreign_browser[["new_session"]]()
  foreign_tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  foreign <- openid_wait_app(app, foreign_browser, foreign_tab)
  interop_retention_probe_id(foreign_tab, connection_id)
  foreign_probe <- interop_retention_action(
    app,
    foreign_browser,
    foreign_tab,
    "probe"
  )
  openid_close_browser(foreign_browser)
  logged_out <- interop_retention_action(app, browser, tab, "logout")
  new_owner <- page("/", logged_out)
  interop_retention_probe_id(tab, connection_id)
  old_id_probe <- interop_retention_action(app, browser, tab, "probe")
  row <- list(
    id = selection[["id"]],
    response_mode = selection[["response_mode"]],
    case_id = id,
    run_id = context[["run_id"]],
    checkout_revision = context[["checkout_revision"]],
    provider_origin = stack[["origin"]],
    app_origin = app[["origin"]],
    discovery = discovery,
    initial = initial,
    app = returned_read,
    snapshots = list(
      connected = connected,
      initial_read = initial_read,
      page_two = page_two,
      restored_read = restored_read,
      refreshed = refreshed,
      refreshed_read = refreshed_read,
      page_one = page_one,
      returned_read = returned_read,
      foreign = foreign,
      foreign_probe = foreign_probe,
      logged_out = logged_out,
      new_owner = new_owner,
      old_id_probe = old_id_probe
    ),
    owner_cookie = owner_cookie,
    callback_cleaned = callback_cleaned,
    form_post = if (form_post) as.list(navigation) else NULL,
    provider = interop_request(stack, "/fixture/evidence", TRUE),
    browser_version = tab[["Browser"]][["getVersion"]]()[["product"]]
  )
  openid_stop_app(app)
  row[["worker_cleanup_verified"]] <- TRUE
  openid_close_browser(browser)
  interop_stop(stack)
  row[["cleanup_verified"]] <- TRUE
  cat("Retention case", row[["id"]], context[["transport"]], "completed\n")
  row
}
