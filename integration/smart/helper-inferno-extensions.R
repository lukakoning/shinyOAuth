inferno_identity_case <- function(root, output, stack, row, index) {
  directory <- file.path(output, paste0("case-", index))
  dir.create(directory)
  registration <- inferno_registration(
    stack,
    "public",
    "RS384",
    "a",
    row[["user_type"]],
    "synthetic-encounter"
  )
  app <- inferno_start_app(
    root,
    directory,
    list(a = registration),
    row[["launch"]],
    row[["async"]]
  )
  session <- inferno_begin_session(
    stack,
    registration,
    app[["origin"]],
    "a",
    row[["launch"]]
  )
  chrome <- inferno_open_browser(app)
  browser <- chrome[["browser"]]
  if (row[["launch"]] == "ehr") {
    browser[["Page"]][["navigate"]](session[["launch_url"]])
  } else {
    retention_browser_click(browser, "connect_a")
  }
  first <- retention_browser_wait(
    browser,
    function() {
      value <- retention_browser_snapshot(browser)
      if (!is.null(value) && length(value[["connections"]]) == 1L) {
        value
      } else {
        NULL
      }
    },
    "identity callback"
  )
  stopifnot(length(first[["errors"]]) == 0L)
  for (id in c("read_a", "user_a", "refresh_a", "read_a", "user_a")) {
    retention_browser_action(browser, id, paste0(id, ":ok"))
  }
  browser[["Page"]][["navigate"]](paste0(app[["origin"]], "/retained"))
  retained <- retention_browser_wait(
    browser,
    function() {
      value <- retention_browser_snapshot(browser)
      if (
        !is.null(value) &&
          value[["session"]] > first[["session"]] &&
          length(value[["connections"]]) == 1L
      ) {
        value
      } else {
        NULL
      }
    },
    "identity restoration"
  )
  stopifnot(identical(
    first[["connections"]][[1L]][["connection_id"]],
    retained[["connections"]][[1L]][["connection_id"]]
  ))
  for (id in c("read_a", "user_a")) {
    retention_browser_action(browser, id, paste0(id, ":ok"))
  }
  verification <- inferno_finish_session(stack, session)
  exchanges <- inferno_identity_exchanges(stack, session, registration)
  stopifnot(verification[["passed"]])
  list(
    user_type = row[["user_type"]],
    launch = row[["launch"]],
    async = row[["async"]],
    browser = chrome[["version"]],
    encounter_preserved = TRUE,
    identity_and_patient_checked = TRUE,
    retained_after_refresh = TRUE,
    verification = verification,
    exchanges = exchanges
  )
}

inferno_identity_exchanges <- function(stack, session, registration) {
  requests <- inferno_session_requests(stack, session)
  path <- function(request) httr2::url_parse(request[["url"]])[["path"]]
  base <- httr2::url_parse(stack[["fhir_base"]])[["path"]]
  tokens <- Filter(
    function(request) endsWith(path(request), "/auth/token"),
    requests
  )
  reads <- Filter(
    function(request) startsWith(path(request), paste0(base, "/")),
    requests
  )
  stopifnot(length(tokens) == 2L, length(reads) == 6L)
  patient <- paste0(base, "/Patient/", registration[["patient"]])
  user <- paste0(
    base,
    "/",
    registration[["user_type"]],
    "/",
    registration[["user_id"]]
  )
  for (index in seq_along(tokens)) {
    token <- tokens[[index]]
    params <- shiny::parseQueryString(token[["request_body"]])
    stopifnot(
      token[["status"]] == 200L,
      identical(
        params[["grant_type"]],
        if (index == 1L) "authorization_code" else "refresh_token"
      )
    )
    body <- jsonlite::fromJSON(token[["response_body"]])
    end <- if (index == 1L) tokens[[2L]][["index"]] else Inf
    following <- Filter(
      function(request) {
        request[["index"]] > token[["index"]] && request[["index"]] < end
      },
      reads
    )
    expected <- if (index == 1L) 1L else 2L
    stopifnot(
      length(following) == 2L * expected,
      all(vapply(following, path, character(1)) %in% c(patient, user))
    )
    if (patient != user) {
      for (wanted in c(patient, user)) {
        stopifnot(
          sum(vapply(
            following,
            function(request) path(request) == wanted,
            logical(1)
          )) ==
            expected
        )
      }
    }
    for (request in following) {
      headers <- Filter(
        function(header) tolower(header[["name"]]) == "authorization",
        request[["request_headers"]]
      )
      stopifnot(
        request[["status"]] == 200L,
        length(headers) == 1L,
        identical(
          headers[[1L]][["value"]],
          paste("Bearer", body[["access_token"]])
        )
      )
    }
  }
  list(
    code_exchanges = 1L,
    refreshes = 1L,
    resource_reads = 6L,
    every_read_uses_current_token = TRUE
  )
}
