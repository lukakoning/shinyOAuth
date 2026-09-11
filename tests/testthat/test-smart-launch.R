smart_launch_test_fixture <- function() {
  client <- smart_client(smart_client_fixture(), "example", "https://app.example/callback",
    scopes = "patient/Patient.r", launch = "ehr")
  manager <- oauth_connections(list(hospital = client), "https://app.example",
    retention = "browser", owner = oauth_browser_owner(),
    store = oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  rendered <- new.env(parent = emptyenv())
  rendered$count <- 0L
  ui <- oauth_connections_ui(function(req) {
    rendered$count <- rendered$count + 1L
    rendered$query <- req$QUERY_STRING
    shiny::fluidPage("Synthetic SMART app")
  }, "health", manager, launch_routes = list(smart_launch_route("/launch", "hospital")))
  list(manager = manager, ui = ui, rendered = rendered)
}

smart_launch_test_entry <- function(f, handle = "synthetic-launch", cookie = NULL) {
  query <- paste0("iss=", utils::URLencode(f$manager$clients$hospital@smart$fhir_base, reserved = TRUE),
    "&launch=", utils::URLencode(handle, reserved = TRUE))
  f$ui(manager_test_request(cookie, path = "/launch", query = query))
}

test_that("EHR HTTP entry redirects before UI and binds an encrypted launch to its owner", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f)
  expect_identical(response$status, 303L)
  expect_identical(f$rendered$count, 0L)
  expect_identical(response$headers[["Cache-Control"]], "no-store")
  expect_identical(response$headers[["Referrer-Policy"]], "no-referrer")
  expect_false(grepl("synthetic-launch|ehr.example", response$headers$Location))
  cookie <- sub(";.*$", "", response$headers[["Set-Cookie"]])
  expect_match(cookie, "^__Host-")
  query <- sub("^.*[?]", "", response$headers$Location)
  continuation <- f$ui(manager_test_request(cookie, query = query))
  expect_equal(continuation$status, 200L)
  expect_identical(f$rendered$count, 1L)
  expect_identical(f$rendered$query, "")
  expect_false(grepl("synthetic-launch|ehr.example", continuation$content))
  expect_match(continuation$content, "history.replaceState", fixed = TRUE)
  expect_match(continuation$content, "health-smart_launch", fixed = TRUE)
  entries <- as.list(f$manager$state$launches)
  expect_length(entries, 1L)
  expect_false(grepl("synthetic-launch", entries[[1L]]$sealed, fixed = TRUE))
  expect_identical(f$ui(manager_test_request(query = query))$status, 400L)
  foreign <- manager_test_cookie(f)
  expect_identical(f$ui(manager_test_request(foreign, query = query))$status, 400L)
  expect_length(f$manager$state$launches, 1L)
})

test_that("unapproved and mixed EHR entry fails before network or UI", {
  f <- smart_launch_test_fixture()
  local_mocked_bindings(req_with_retry = function(...) stop("Unexpected network call"),
    .package = "shinyOAuth")
  base <- "iss=https%3A%2F%2Fehr.example%2Ffhir%2FR4&launch=example"
  for (query in c("", "iss=https://ehr.example/fhir/R4", "launch=example",
      paste0(base, "&code=example"), paste0(base, "&state=example"),
      paste0(base, "&response=example"), paste0(base, "&error=example"),
      paste0(base, "&iss=https://ehr.example/fhir/R4"), paste0(base, "&%6caunch=other"),
      sub("ehr.example", "unapproved.example", base, fixed = TRUE),
      sub("R4&", "R4%2F&", base, fixed = TRUE),
      paste0("iss=https://ehr.example/fhir/R4&launch=", strrep("x", 2049)),
      "iss=https://ehr.example/fhir/R4&launch=%0A")) {
    expect_identical(f$ui(manager_test_request(path = "/launch", query = query))$status, 400L)
  }
  expect_identical(f$ui(manager_test_request(method = "POST", path = "/launch", query = base))$status, 400L)
  iframe <- manager_test_request(path = "/launch", query = base)
  iframe$HTTP_SEC_FETCH_DEST <- "iframe"
  expect_identical(f$ui(iframe)$status, 400L)
  expect_identical(f$rendered$count, 0L)
  expect_length(f$manager$state$launches, 0L)
  expect_identical(f$ui(manager_test_request(path = "/callback", query = base))$status, 400L)
})

test_that("launch routes reject callback collisions and ambiguous registrations", {
  f <- smart_launch_test_fixture()
  expect_error(smart_launch_routes_validate(list(smart_launch_route("/callback", "hospital")),
    f$manager, "/"), "distinct")
  expect_error(smart_launch_routes_validate(list(smart_launch_route("/", "hospital")),
    f$manager, "/"), "distinct")
  expect_error(smart_launch_routes_validate(list(smart_launch_route("/launch", "unknown")),
    f$manager, "/"), "configured EHR")
  for (path in c("//other.example", "/../launch", "/launch?x=1", "/%2e%2e/launch")) {
    expect_error(smart_launch_route(path, "hospital"))
  }
})

test_that("launch is consumed once and the handle belongs to one state transaction", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f, "first-launch")
  cookie <- sub(";.*$", "", response$headers[["Set-Cookie"]])
  first <- sub("^.*=", "", response$headers$Location)
  second_response <- smart_launch_test_entry(f, "second-launch", cookie)
  second <- sub("^.*=", "", second_response$headers$Location)
  expect_false(identical(first, second))
  expect_null(second_response$headers[["Set-Cookie"]])
  saved <- new.env(parent = emptyenv())
  shiny::testServer(session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f$manager, session)
    }, {
      expect_identical(ctl$resume_launch(first), "hospital")
      expect_error(ctl$resume_launch(first), "unavailable")
      hooks <- ctl$hooks("hospital")
      context <- hooks$prepare()
      expect_identical(context$smart$launch_id, first)
      expect_false(grepl("first-launch", authorization_context_json(context), fixed = TRUE))
      params <- hooks$parameters(context)
      expect_identical(params$launch, "first-launch")
      expect_error(hooks$parameters(context), "fresh EHR launch")
      client <- f$manager$clients$hospital
      browser <- valid_browser_token()
      url <- prepare_call(client, browser_token = browser,
        .transaction_context = context, .smart_launch = params$launch)
      query <- httr2::url_parse(url)$query
      expect_identical(query$launch, "first-launch")
      expect_identical(query$aud, client@smart$fhir_base)
      expect_identical(query$code_challenge_method, "S256")
      expect_identical(client@provider@extra_auth_params, list(aud = client@smart$fhir_base))
      expect_error(prepare_call(client, browser_token = browser,
        .transaction_context = context, .smart_launch = "second-launch"), "fresh registered")
      expect_error(hooks$prepare(), "fresh EHR launch")
      expect_true(hooks$validate(context))
      expect_identical(ctl$resume_launch(second), "hospital")
      next_context <- hooks$prepare()
      expect_false(identical(next_context$transaction, context$transaction))
      expect_identical(hooks$parameters(next_context)$launch, "second-launch")
      hooks$cancel(context)
      expect_false(hooks$validate(context))
      saved$context <- next_context
      ctl$logout(revoke = FALSE)
      expect_false(hooks$validate(next_context))
    })
  expect_length(f$manager$state$launches, 0L)
})

test_that("expired and foreign-owner handoffs cannot consume a launch", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f)
  cookie <- sub(";.*$", "", response$headers[["Set-Cookie"]])
  id <- sub("^.*=", "", response$headers$Location)
  foreign <- manager_test_cookie(f)
  shiny::testServer(session = manager_test_session(foreign),
    function(input, output, session) ctl <- connection_manager_controller(f$manager, session), {
      expect_error(ctl$resume_launch(id), "unavailable")
    })
  expect_length(f$manager$state$launches, 1L)
  entries <- f$manager$state$launches
  entries[[id]]$expires_at <- as.numeric(Sys.time()) - 1
  shiny::testServer(session = manager_test_session(cookie),
    function(input, output, session) ctl <- connection_manager_controller(f$manager, session), {
      expect_error(ctl$resume_launch(id), "unavailable")
    })
  expect_length(f$manager$state$launches, 0L)
})

test_that("encrypted handoffs retain their original ID and logout removes unused launches", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f, strrep("x", 2048))
  expect_identical(response$status, 303L)
  cookie <- sub(";.*$", "", response$headers[["Set-Cookie"]])
  first <- sub("^.*=", "", response$headers$Location)
  second_response <- smart_launch_test_entry(f, "unused-launch", cookie)
  second <- sub("^.*=", "", second_response$headers$Location)
  entries <- f$manager$state$launches
  original <- entries[[second]]
  entries[[second]] <- entries[[first]]
  shiny::testServer(session = manager_test_session(cookie),
    function(input, output, session) ctl <- connection_manager_controller(f$manager, session), {
      expect_error(ctl$resume_launch(second), "unavailable")
      expect_length(entries, 2L)
      entries[[second]] <- original
      expect_identical(ctl$resume_launch(first), "hospital")
      expect_length(entries, 1L)
      ctl$logout(revoke = FALSE)
      expect_length(entries, 0L)
      expect_error(ctl$resume_launch(second), "owner")
    })
})

test_that("the public manager requires a fresh EHR entry before starting browser login", {
  f <- smart_launch_test_fixture()
  cookie <- manager_test_cookie(f)
  shiny::testServer(session = manager_test_session(cookie),
    function(input, output, session) {
      health <- oauth_connections_server("health", f$manager)
    }, {
      expect_false(health$connect("hospital"))
      expect_identical(health$errors()$smart_launch, "fresh_ehr_launch_required")
      expect_length(f$manager$state$pending, 0L)
      expect_length(f$manager$state$launches, 0L)
    })
})
