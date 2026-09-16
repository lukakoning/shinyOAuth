smart_launch_test_fixture <- function() {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "patient/Patient.r",
    launch = "ehr"
  )
  manager <- oauth_connections(
    list(hospital = client),
    "https://app.example",
    retention = "browser",
    owner_policy = oauth_browser_owner(),
    store = oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  rendered <- new.env(parent = emptyenv())
  rendered[["count"]] <- 0L
  ui <- oauth_connections_ui(
    function(req) {
      rendered[["count"]] <- rendered[["count"]] + 1L
      rendered[["query"]] <- req[["QUERY_STRING"]]
      shiny::fluidPage("Synthetic SMART app")
    },
    "health",
    manager,
    launch_routes = list(smart_launch_route("/launch", "hospital"))
  )
  list(manager = manager, ui = ui, rendered = rendered)
}

smart_launch_test_entry <- function(
  f,
  handle = "synthetic-launch",
  cookie = NULL
) {
  query <- paste0(
    "iss=",
    utils::URLencode(
      f[["manager"]][["clients"]][["hospital"]]@smart[["fhir_base"]],
      reserved = TRUE
    ),
    "&launch=",
    utils::URLencode(handle, reserved = TRUE)
  )
  f[["ui"]](manager_test_request(cookie, path = "/launch", query = query))
}

test_that("EHR HTTP entry redirects before UI and binds an encrypted launch to its owner", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f)
  expect_identical(response[["status"]], 303L)
  expect_identical(f[["rendered"]][["count"]], 0L)
  expect_identical(response[["headers"]][["Cache-Control"]], "no-store")
  expect_identical(response[["headers"]][["Referrer-Policy"]], "no-referrer")
  expect_false(grepl(
    "synthetic-launch|ehr.example",
    response[["headers"]][["Location"]]
  ))
  cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
  expect_match(cookie, "^__Host-")
  query <- sub("^.*[?]", "", response[["headers"]][["Location"]])
  continuation <- f[["ui"]](manager_test_request(cookie, query = query))
  expect_equal(continuation[["status"]], 200L)
  expect_identical(f[["rendered"]][["count"]], 1L)
  expect_identical(f[["rendered"]][["query"]], "")
  expect_false(grepl("synthetic-launch|ehr.example", continuation[["content"]]))
  expect_false(grepl(
    "history.replaceState",
    continuation[["content"]],
    fixed = TRUE
  ))
  expect_match(
    continuation[["content"]],
    'name="shinyOAuth-smart-launch"',
    fixed = TRUE
  )
  expect_lt(
    regexpr(
      'name="shinyOAuth-smart-launch"',
      continuation[["content"]],
      fixed = TRUE
    )[[1]],
    regexpr("<script", continuation[["content"]], fixed = TRUE)[[1]]
  )
  expect_match(continuation[["content"]], "shinyOAuth.js", fixed = TRUE)
  expect_match(continuation[["content"]], "health-smart_launch", fixed = TRUE)
  entries <- as.list(f[["manager"]][["state"]][["launches"]])
  expect_length(entries, 1L)
  expect_false(grepl(
    "synthetic-launch",
    entries[[1L]][["sealed"]],
    fixed = TRUE
  ))
  expect_identical(
    f[["ui"]](manager_test_request(query = query))[["status"]],
    400L
  )
  foreign <- manager_test_cookie(f)
  expect_identical(
    f[["ui"]](manager_test_request(foreign, query = query))[["status"]],
    400L
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 1L)
})

test_that("unapproved and mixed EHR entry fails before network or UI", {
  f <- smart_launch_test_fixture()
  local_mocked_bindings(
    req_with_retry = function(...) stop("Unexpected network call"),
    .package = "shinyOAuth"
  )
  base <- "iss=https%3A%2F%2Fehr.example%2Ffhir%2FR4&launch=example"
  for (query in c(
    "",
    "iss=https://ehr.example/fhir/R4",
    "launch=example",
    paste0(base, "&code=example"),
    paste0(base, "&state=example"),
    paste0(base, "&response=example"),
    paste0(base, "&error=example"),
    paste0(base, "&iss=https://ehr.example/fhir/R4"),
    paste0(base, "&%6caunch=other"),
    sub("ehr.example", "unapproved.example", base, fixed = TRUE),
    sub("R4&", "R4%2F&", base, fixed = TRUE),
    paste0("iss=https://ehr.example/fhir/R4&launch=", strrep("x", 2049)),
    "iss=https://ehr.example/fhir/R4&launch=%0A"
  )) {
    expect_identical(
      f[["ui"]](manager_test_request(path = "/launch", query = query))[[
        "status"
      ]],
      400L
    )
  }
  expect_identical(
    f[["ui"]](manager_test_request(
      method = "POST",
      path = "/launch",
      query = base
    ))[["status"]],
    400L
  )
  iframe <- manager_test_request(path = "/launch", query = base)
  iframe[["HTTP_SEC_FETCH_DEST"]] <- "iframe"
  expect_identical(f[["ui"]](iframe)[["status"]], 400L)
  expect_identical(f[["rendered"]][["count"]], 0L)
  expect_length(f[["manager"]][["state"]][["launches"]], 0L)
  expect_identical(
    f[["ui"]](manager_test_request(path = "/callback", query = base))[[
      "status"
    ]],
    400L
  )
})

test_that("launch routes reject callback collisions and ambiguous registrations", {
  f <- smart_launch_test_fixture()
  expect_error(
    smart_launch_routes_validate(
      list(smart_launch_route("/callback", "hospital")),
      f[["manager"]],
      "/"
    ),
    "distinct"
  )
  expect_error(
    smart_launch_routes_validate(
      list(smart_launch_route("/", "hospital")),
      f[["manager"]],
      "/"
    ),
    "distinct"
  )
  expect_error(
    smart_launch_routes_validate(
      list(smart_launch_route("/launch", "unknown")),
      f[["manager"]],
      "/"
    ),
    "configured EHR"
  )
  for (path in c(
    "//other.example",
    "/../launch",
    "/launch?x=1",
    "/%2e%2e/launch"
  )) {
    expect_error(smart_launch_route(path, "hospital"))
  }
})

test_that("launch paths do not require a placeholder host in the network allowlist", {
  withr::local_options(shinyOAuth.allowed_hosts = "registered-app.example")
  expect_identical(
    smart_launch_route("/%6caunch", "hospital")[["path"]],
    "/launch"
  )
  for (path in c(
    "//other.example",
    "/../launch",
    "/%2e%2e/launch",
    "/%2flaunch",
    "/launch?x=1",
    "/launch#fragment",
    "/launch path",
    "/launch\n",
    "/%zz",
    "/launch;param",
    paste0("/", strrep("x", 8192))
  )) {
    expect_error(smart_launch_route(path, "hospital"))
  }
})

test_that("escaped launch paths use the same spelling for routing and collisions", {
  f <- smart_launch_test_fixture()
  route <- smart_launch_route("/%6Caunch", "hospital")
  expect_identical(route[["path"]], "/launch")
  f[["ui"]] <- oauth_connections_ui(
    shiny::fluidPage("Synthetic SMART app"),
    "health",
    f[["manager"]],
    launch_routes = list(route)
  )
  query <- "iss=https%3A%2F%2Fehr.example%2Ffhir%2FR4&launch=example"
  for (path in c("/launch", "/%6caunch", "/%6Caunch")) {
    expect_identical(
      f[["ui"]](manager_test_request(path = path, query = query))[["status"]],
      303L
    )
  }
  expect_error(
    smart_launch_routes_validate(
      list(route, smart_launch_route("/launch", "hospital")),
      f[["manager"]],
      "/"
    ),
    "distinct"
  )
  expect_error(
    smart_launch_routes_validate(
      list(smart_launch_route("/%63allback", "hospital")),
      f[["manager"]],
      "/"
    ),
    "distinct"
  )
  route[["path"]] <- "/%6caunch"
  expect_error(
    smart_launch_routes_validate(list(route), f[["manager"]], "/"),
    "canonicalize"
  )
})

test_that("launch is consumed once and the handle belongs to one state transaction", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f, "first-launch")
  cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
  first <- sub("^.*=", "", response[["headers"]][["Location"]])
  second_response <- smart_launch_test_entry(f, "second-launch", cookie)
  second <- sub("^.*=", "", second_response[["headers"]][["Location"]])
  expect_false(identical(first, second))
  expect_null(second_response[["headers"]][["Set-Cookie"]])
  saved <- new.env(parent = emptyenv())
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_identical(ctl[["resume_launch"]](first), "hospital")
      expect_error(ctl[["resume_launch"]](first), "unavailable")
      hooks <- ctl[["hooks"]]("hospital")
      context <- hooks[["prepare"]]()
      expect_identical(context[["smart"]][["launch_id"]], first)
      expect_false(grepl(
        "first-launch",
        authorization_context_json(context),
        fixed = TRUE
      ))
      params <- hooks[["parameters"]](context)
      expect_identical(params[["launch"]], "first-launch")
      expect_error(hooks[["parameters"]](context), "fresh EHR launch")
      client <- f[["manager"]][["clients"]][["hospital"]]
      browser <- valid_browser_token()
      url <- prepare_call_internal(
        client,
        browser_token = browser,
        .transaction_context = context,
        .smart_launch = params[["launch"]]
      )
      query <- httr2::url_parse(url)[["query"]]
      expect_identical(query[["launch"]], "first-launch")
      expect_identical(query[["aud"]], client@smart[["fhir_base"]])
      expect_identical(query[["code_challenge_method"]], "S256")
      expect_identical(
        client@provider@extra_auth_params,
        list(aud = client@smart[["fhir_base"]])
      )
      expect_error(
        prepare_call_internal(
          client,
          browser_token = browser,
          .transaction_context = context,
          .smart_launch = "second-launch"
        ),
        "fresh registered"
      )
      expect_error(hooks[["prepare"]](), "fresh EHR launch")
      expect_true(hooks[["validate"]](context))
      expect_identical(ctl[["resume_launch"]](second), "hospital")
      next_context <- hooks[["prepare"]]()
      expect_false(identical(
        next_context[["transaction"]],
        context[["transaction"]]
      ))
      expect_identical(
        hooks[["parameters"]](next_context)[["launch"]],
        "second-launch"
      )
      hooks[["cancel"]](context)
      expect_false(hooks[["validate"]](context))
      saved[["context"]] <- next_context
      ctl[["logout"]](revoke = FALSE)
      expect_false(hooks[["validate"]](next_context))
    }
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 0L)
})

for (delay in c(121, 301)) {
  test_that(paste("prepared EHR logins use the OAuth deadline", delay), {
    clock <- new.env(parent = emptyenv())
    clock[["now"]] <- as.numeric(Sys.time())
    local_mocked_bindings(
      Sys.time = function() {
        as.POSIXct(clock[["now"]], origin = "1970-01-01", tz = "UTC")
      },
      .package = "base"
    )
    local_mocked_bindings(req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "example-access",
            token_type = "Bearer",
            expires_in = 300,
            scope = "patient/Patient.r launch",
            patient = "example-patient"
          ),
          auto_unbox = TRUE
        ))
      )
    })
    f <- smart_launch_test_fixture()
    response <- smart_launch_test_entry(f)
    cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
    id <- sub("^.*=", "", response[["headers"]][["Location"]])
    shiny::testServer(
      session = manager_test_session(cookie),
      function(input, output, session) {
        ctl <- connection_manager_controller(f[["manager"]], session)
      },
      {
        ctl[["resume_launch"]](id)
        hooks <- ctl[["hooks"]]("hospital")
        context <- hooks[["prepare"]]()
        params <- hooks[["parameters"]](context)
        client <- f[["manager"]][["clients"]][["hospital"]]
        browser <- valid_browser_token()
        url <- prepare_call_internal(
          client,
          browser,
          .transaction_context = context,
          .smart_launch = params[["launch"]]
        )
        clock[["now"]] <- clock[["now"]] + delay
        callback <- function() {
          handle_callback_internal(
            client,
            code = "example-code",
            payload = parse_query_param(url, "state"),
            browser_token = browser,
            .transaction_context = authorization_context_json(context)
          )
        }
        if (delay < client@state_payload_max_age) {
          expect_true(hooks[["validate"]](context))
          token <- callback()
          expect_no_error(hooks[["accept"]](token, context, clock[["now"]]))
          expect_length(ctl[["records"]](), 1L)
        } else {
          expect_false(hooks[["validate"]](context))
          expect_error(callback(), class = "shinyOAuth_state_error")
          expect_error(ctl[["records"]](), "owner is unavailable")
          expect_length(
            f[["manager"]][["store"]][["list"]](context[["owner"]]),
            0L
          )
        }
      }
    )
  })
}

for (phase in c("entry", "queued", "prepared")) {
  test_that(
    paste("unconsumed EHR parameters retain the short handoff deadline", phase),
    {
      clock <- new.env(parent = emptyenv())
      clock[["now"]] <- as.numeric(Sys.time())
      local_mocked_bindings(
        Sys.time = function() {
          as.POSIXct(clock[["now"]], origin = "1970-01-01", tz = "UTC")
        },
        .package = "base"
      )
      f <- smart_launch_test_fixture()
      response <- smart_launch_test_entry(f)
      cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
      id <- sub("^.*=", "", response[["headers"]][["Location"]])
      shiny::testServer(
        session = manager_test_session(cookie),
        function(input, output, session) {
          ctl <- connection_manager_controller(f[["manager"]], session)
        },
        {
          hooks <- ctl[["hooks"]]("hospital")
          if (phase != "entry") {
            ctl[["resume_launch"]](id)
          }
          if (phase == "prepared") {
            context <- hooks[["prepare"]]()
          }
          clock[["now"]] <- clock[["now"]] + 121
          if (phase == "entry") {
            expect_error(ctl[["resume_launch"]](id), "unavailable")
          }
          if (phase == "queued") {
            expect_error(hooks[["prepare"]](), "unavailable")
          }
          if (phase == "prepared") {
            expect_error(hooks[["parameters"]](context), "unavailable")
          }
          expect_length(ctl[["records"]](), 0L)
        }
      )
    }
  )
}

test_that("expired and foreign-owner handoffs cannot consume a launch", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f)
  cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
  id <- sub("^.*=", "", response[["headers"]][["Location"]])
  foreign <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(foreign),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_error(ctl[["resume_launch"]](id), "unavailable")
    }
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 1L)
  entries <- f[["manager"]][["state"]][["launches"]]
  entries[[id]][["expires_at"]] <- as.numeric(Sys.time()) - 1
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_error(ctl[["resume_launch"]](id), "unavailable")
    }
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 0L)
})

test_that("encrypted handoffs retain their original ID and logout removes unused launches", {
  f <- smart_launch_test_fixture()
  response <- smart_launch_test_entry(f, strrep("x", 2048))
  expect_identical(response[["status"]], 303L)
  cookie <- sub(";.*$", "", response[["headers"]][["Set-Cookie"]])
  first <- sub("^.*=", "", response[["headers"]][["Location"]])
  second_response <- smart_launch_test_entry(f, "unused-launch", cookie)
  second <- sub("^.*=", "", second_response[["headers"]][["Location"]])
  entries <- f[["manager"]][["state"]][["launches"]]
  original <- entries[[second]]
  entries[[second]] <- entries[[first]]
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_error(ctl[["resume_launch"]](second), "unavailable")
      expect_length(entries, 2L)
      entries[[second]] <- original
      expect_identical(ctl[["resume_launch"]](first), "hospital")
      expect_length(entries, 1L)
      ctl[["logout"]](revoke = FALSE)
      expect_length(entries, 0L)
      expect_error(ctl[["resume_launch"]](second), "owner")
    }
  )
})

test_that("the public manager requires a fresh EHR entry before starting browser login", {
  f <- smart_launch_test_fixture()
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      health <- oauth_connections_server("health", f[["manager"]])
    },
    {
      expect_false(health[["connect"]]("hospital"))
      expect_identical(
        health[["errors"]]()[["smart_launch"]],
        "fresh_ehr_launch_required"
      )
      expect_length(f[["manager"]][["state"]][["pending"]], 0L)
      expect_length(f[["manager"]][["state"]][["launches"]], 0L)
    }
  )
})

test_that("EHR admission limits each owner across routes without displacing pending work", {
  f <- smart_launch_test_fixture()
  f[["ui"]] <- oauth_connections_ui(
    shiny::fluidPage("Synthetic SMART app"),
    "health",
    f[["manager"]],
    launch_routes = list(
      smart_launch_route("/launch", "hospital"),
      smart_launch_route("/another-launch", "hospital")
    )
  )
  cookie <- manager_test_cookie(f)
  first <- smart_launch_test_entry(f, cookie = cookie)
  continuation_id <- sub("^.*=", "", first[["headers"]][["Location"]])
  expect_identical(first[["status"]], 303L)
  for (i in seq_len(6L)) {
    expect_identical(
      smart_launch_test_entry(f, cookie = cookie)[["status"]],
      303L
    )
  }
  query <- paste0(
    "iss=",
    utils::URLencode(
      f[["manager"]][["clients"]][["hospital"]]@smart[["fhir_base"]],
      reserved = TRUE
    ),
    "&launch=synthetic-launch"
  )
  alternate <- f[["ui"]](manager_test_request(
    cookie,
    path = "/another-launch",
    query = query
  ))
  expect_identical(alternate[["status"]], 303L)
  pending <- as.list(f[["manager"]][["state"]][["launches"]])
  expect_length(pending, 8L)

  for (path in c("/launch", "/another-launch")) {
    response <- f[["ui"]](manager_test_request(
      cookie,
      path = path,
      query = query
    ))
    expect_identical(response[["status"]], 400L)
    expect_null(response[["headers"]][["Set-Cookie"]])
    expect_identical(as.list(f[["manager"]][["state"]][["launches"]]), pending)
  }
  other_cookie <- manager_test_cookie(f)
  expect_identical(
    smart_launch_test_entry(f, cookie = other_cookie)[["status"]],
    303L
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 9L)

  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_identical(ctl[["resume_launch"]](continuation_id), "hospital")
    }
  )
  expect_identical(
    smart_launch_test_entry(f, cookie = cookie)[["status"]],
    303L
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 9L)
})

test_that("expired EHR handoffs release owner admission capacity", {
  clock <- new.env(parent = emptyenv())
  clock[["now"]] <- as.numeric(Sys.time())
  local_mocked_bindings(
    Sys.time = function() {
      as.POSIXct(clock[["now"]], origin = "1970-01-01", tz = "UTC")
    },
    .package = "base"
  )
  f <- smart_launch_test_fixture()
  cookie <- manager_test_cookie(f)
  for (i in seq_len(8L)) {
    expect_identical(
      smart_launch_test_entry(f, cookie = cookie)[["status"]],
      303L
    )
  }
  expect_identical(
    smart_launch_test_entry(f, cookie = cookie)[["status"]],
    400L
  )
  clock[["now"]] <- clock[["now"]] + 121
  expect_identical(
    smart_launch_test_entry(f, cookie = cookie)[["status"]],
    303L
  )
  expect_length(f[["manager"]][["state"]][["launches"]], 1L)
})
