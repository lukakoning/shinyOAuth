inferno_start_account_app <- function(root, output, registrations, async, .env = parent.frame()) {
  port <- httpuv::randomPort()
  tls <- inferno_tls(root, port, .env)
  process <- callr::r_bg(function(root, origin, port, registrations, async) {
    Sys.setenv(CURL_SSL_BACKEND = "openssl", CURL_CA_BUNDLE = file.path(root, "integration/keycloak/tls/ca-cert.pem"),
      R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]]))
    options(shinyOAuth.max_id_token_lifetime = 366 * 86400,
      shinyOAuth.allowed_hosts = c("localhost", "127.0.0.1"))
    source(file.path(root, "integration/connections/fixture-account-app.R"))
    account_fixture_app(origin, lapply(registrations, function(reg) reg[["fhir_base"]]), async,
      listen_port = port, smart_registrations = registrations)
  }, args = list(root, tls[["origin"]], port, registrations, async), libpath = .libPaths(), supervise = TRUE,
    stdout = file.path(output, "app.stdout"), stderr = file.path(output, "app.stderr"))
  withr::defer({ if (process[["is_alive"]]()) process[["kill"]]() }, envir = .env)
  list(origin = tls[["origin"]], process = process, ca = file.path(root, "integration/keycloak/tls/ca-cert.pem"))
}

inferno_account_case <- function(root, output, stacks, async, index) {
  message("Inferno account retention / async=", async)
  directory <- file.path(output, paste0("case-", index))
  dir.create(directory)
  registrations <- lapply(names(stacks), function(site) inferno_registration(stacks[[site]], "public", "RS384", site))
  names(registrations) <- names(stacks)
  app <- inferno_start_account_app(root, directory, registrations, async)
  sessions <- lapply(names(stacks), function(site)
    inferno_begin_session(stacks[[site]], registrations[[site]], app[["origin"]], site, "standalone"))
  names(sessions) <- names(stacks)
  chrome <- inferno_open_browser(app)
  browser <- chrome[["browser"]]
  login <- function(account) {
    retention_browser_value(browser, paste0("document.getElementById('username').value=",
      jsonlite::toJSON(account, auto_unbox = TRUE), ";document.getElementById('password').value=",
      jsonlite::toJSON(paste0(account, "-fixture-password"), auto_unbox = TRUE), ";"))
    retention_browser_click(browser, "login")
    retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      if (identical(value[["account"]], account)) value else NULL
    }, "local account login")
  }
  logout <- function() {
    retention_browser_click(browser, "local_logout")
    retention_browser_wait(browser, function() identical(retention_browser_snapshot(browser)[["result"]], "login"),
      "local account logout")
  }
  authorize <- function(site) {
    retention_browser_click(browser, paste0("connect_", site))
    retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      if (length(value[["connections"]]) == 1L && identical(value[["connections"]][[1L]][["client_label"]], site)) value else NULL
    }, "account SMART callback")
  }
  stopifnot(length(login("alice")[["connections"]]) == 0L)
  alice <- authorize("a")
  retention_browser_action(browser, "read_a", "a:patient")
  context <- chrome[["chrome"]][["Target"]][["getTargetInfo"]](targetId = browser[["get_target_id"]]())[["targetInfo"]][["browserContextId"]]
  target <- chrome[["chrome"]][["Target"]][["createTarget"]]("about:blank", browserContextId = context)[["targetId"]]
  old <- chromote::ChromoteSession[["new"]](parent = chrome[["chrome"]], targetId = target)
  withr::defer(old[["close"]]())
  old[["Security"]][["setIgnoreCertificateErrors"]](ignore = TRUE)
  old[["Page"]][["navigate"]](app[["origin"]])
  retention_browser_wait(old, function() length(retention_browser_snapshot(old)[["connections"]]) == 1L, "old Alice tab")
  logout()
  stopifnot(length(login("bob")[["connections"]]) == 0L)
  retention_browser_action(browser, "read_a", "unavailable")
  retention_browser_action(old, "read_a", "unavailable")
  bob <- authorize("b")
  retention_browser_action(browser, "read_b", "b:patient")
  logout()
  restored <- login("alice")
  stopifnot(length(restored[["connections"]]) == 1L,
    identical(restored[["connections"]][[1L]][["connection_id"]], alice[["connections"]][[1L]][["connection_id"]]))
  retention_browser_action(old, "read_a", "unavailable")
  retention_browser_action(browser, "refresh_a", "refreshed")
  retention_browser_action(browser, "read_a", "a:patient")
  retention_browser_action(browser, "read_b", "unavailable")
  retention_browser_action(browser, "manager_logout", "disconnected")
  retention_browser_action(browser, "read_a", "unavailable")
  logout()
  restored <- login("bob")
  stopifnot(length(restored[["connections"]]) == 1L,
    identical(restored[["connections"]][[1L]][["connection_id"]], bob[["connections"]][[1L]][["connection_id"]]))
  retention_browser_action(browser, "read_b", "b:patient")
  verification <- lapply(names(stacks), function(site) {
    result <- inferno_finish_session(stacks[[site]], sessions[[site]])
    stopifnot(result[["passed"]])
    result[["exchanges"]] <- inferno_account_exchanges(stacks[[site]], sessions[[site]], registrations[[site]], site == "a")
    result
  })
  list(async = async, browser = chrome[["version"]], passed = TRUE, account_isolation = TRUE,
    old_generation_rejected = TRUE, restored_refresh = TRUE, other_account_survives_disconnect = TRUE,
    verification = setNames(verification, names(stacks)))
}

inferno_account_exchanges <- function(stack, session, registration, refreshed) {
  requests <- inferno_session_requests(stack, session)
  path <- function(request) httr2::url_parse(request[["url"]])[["path"]]
  base <- httr2::url_parse(stack[["fhir_base"]])[["path"]]
  tokens <- Filter(function(request) endsWith(path(request), "/auth/token"), requests)
  reads <- Filter(function(request) startsWith(path(request), paste0(base, "/")), requests)
  stopifnot(length(tokens) == if (refreshed) 2L else 1L, length(reads) == 4L,
    all(vapply(tokens, function(request) request[["status"]] == 200L, logical(1))))
  stopifnot(identical(vapply(tokens, function(request)
    shiny::parseQueryString(request[["request_body"]])[["grant_type"]], character(1)),
    c("authorization_code", if (refreshed) "refresh_token")))
  if (refreshed) stopifnot(sum(vapply(reads, function(request)
    request[["index"]] < tokens[[2L]][["index"]], logical(1))) == 2L)
  expected <- c(paste0(base, "/Patient/", registration[["patient"]]),
    paste0(base, "/Practitioner/", registration[["practitioner"]]))
  for (wanted in expected) stopifnot(sum(vapply(reads, function(request) path(request) == wanted, logical(1))) == 2L)
  for (request in reads) {
    preceding <- Filter(function(token) token[["index"]] < request[["index"]], tokens)
    body <- jsonlite::fromJSON(tail(preceding, 1L)[[1L]][["response_body"]])
    headers <- Filter(function(header) tolower(header[["name"]]) == "authorization", request[["request_headers"]])
    stopifnot(request[["status"]] == 200L, length(headers) == 1L,
      identical(headers[[1L]][["value"]], paste("Bearer", body[["access_token"]])))
  }
  list(code_exchanges = 1L, refreshes = as.integer(refreshed), resource_reads = 4L,
    current_token_and_account_isolation = TRUE)
}
