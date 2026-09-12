manager_test_fixture <- function(retention = "browser", owner = NULL) {
  redirects <- paste0("https://app.example/callback/", c("a", "b"))
  clients <- lapply(c("a", "b"), function(id) {
    client <- oauth_client(
      provider = make_test_provider(),
      client_id = paste0("client-", id),
      client_secret = "",
      redirect_uri = paste0("https://app.example/callback/", id),
      scopes = c("read", "write"),
      state_key = strrep(id, 64L),
      authorization_server_mode = "multi_redirect_uri",
      authorization_server_redirect_uris = redirects
    )
    connection_test_client(
      client,
      c(api = paste0("https://api.example/", id)),
      "read",
      paste("Site", id)
    )
  })
  names(clients) <- c("a", "b")
  owner <- owner %||%
    if (retention == "browser") oauth_browser_owner() else NULL
  manager <- oauth_connections(
    clients,
    "https://app.example",
    retention = retention,
    store = oauth_connection_store_memory(),
    owner = owner,
    keys = list(
      credentials = openssl::rand_bytes(32L),
      owner = openssl::rand_bytes(32L)
    )
  )
  ui <- oauth_connections_ui(shiny::fluidPage("Connections"), "health", manager)
  list(manager = manager, ui = ui)
}

manager_test_token <- function(
  access = "synthetic-access",
  refresh = "synthetic-refresh"
) {
  OAuthToken(
    access_token = access,
    refresh_token = refresh,
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = c("read", "write"),
    granted_scopes_verified = TRUE,
    extra_fields = list(patient = "synthetic-patient")
  )
}

manager_test_accept <- function(
  controller,
  client = "a",
  token = manager_test_token()
) {
  before <- vapply(
    controller$records(),
    function(row) row$stored$id,
    character(1)
  )
  hooks <- controller$hooks(client)
  context <- hooks$prepare()
  hooks$accept(token, context, as.numeric(Sys.time()) - 100)
  rows <- controller$records()
  ids <- vapply(rows, function(row) row$stored$id, character(1))
  setdiff(ids, before)[[1L]]
}

test_that("manager configuration requires explicit retention and distinct registered routes", {
  f <- manager_test_fixture()
  expect_match(capture.output(print(f$manager)), "2 client")
  expect_false(grepl(
    "app.example|api.example|synthetic",
    paste(capture.output(print(f$manager)), collapse = "")
  ))
  expect_error(
    oauth_connections(
      f$manager$clients,
      "https://app.example",
      retention = "browser"
    ),
    "owner policy"
  )
  expect_error(
    oauth_connections(f$manager$clients, "https://other.example"),
    "application origin"
  )
  expect_error(
    oauth_connections(
      f$manager$clients,
      "https://app.example",
      callback_policy = "shared"
    ),
    "distinct"
  )
  expect_error(
    connection_manager_bind(f$manager, "other"),
    "one module namespace"
  )
  expect_error(
    oauth_connections(f$manager$clients, "https://app.example", keys = list()),
    "32-byte"
  )
})

test_that("browser UI establishes and clears cookies only at the ordinary HTTP boundary", {
  f <- manager_test_fixture()
  response <- f$ui(manager_test_request())
  expect_equal(response$status, 200L)
  expect_match(
    response$headers[["Set-Cookie"]],
    "HttpOnly; SameSite=Lax; Secure",
    fixed = TRUE
  )
  expect_false(grepl("patient|access_token", response$headers[["Set-Cookie"]]))
  cookie <- sub(";.*$", "", response$headers[["Set-Cookie"]])
  expect_null(f$ui(manager_test_request(cookie))$headers[["Set-Cookie"]])
  bad_origin <- manager_test_request()
  bad_origin$HTTP_HOST <- "other.example"
  expect_identical(f$ui(bad_origin)$status, 400L)
  cross_origin <- manager_test_request()
  cross_origin$HTTP_ORIGIN <- "https://other.example"
  expect_identical(f$ui(cross_origin)$status, 400L)
  unknown <- paste0(
    f$manager$state$owners$cookie_name,
    "=",
    random_urlsafe(43L)
  )
  cleared <- f$ui(manager_test_request(unknown))
  expect_identical(cleared$status, 303L)
  expect_match(cleared$headers[["Set-Cookie"]], "Max-Age=0")
  expect_identical(cleared$headers$Location, "https://app.example/")
  continuation <- paste0(oauth_form_post_handle_param, "=", random_urlsafe(32L))
  expect_identical(
    f$ui(manager_test_request(query = continuation))$status,
    400L
  )
  raw <- f$ui(manager_test_request(
    path = "/callback/a",
    query = "code=invalid&state=invalid"
  ))
  expect_null(raw$headers[["Set-Cookie"]])
  plain <- manager_test_fixture("shiny")
  expect_null(plain$ui(manager_test_request())$headers[["Set-Cookie"]])
})

test_that("browser owner capacity is configurable independently of the store", {
  f <- manager_test_fixture(owner = oauth_browser_owner(max_entries = 1L))
  cookie <- manager_test_cookie(f)
  expect_identical(f$ui(manager_test_request())$status, 400L)
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f$manager),
    session = manager_test_session(cookie),
    {
      id <- manager_test_accept(controller)
      health <- session$getReturned()
      expect_identical(health$connection(id)$is_usable(), TRUE)
      health$logout(revoke = FALSE, reload = FALSE)
    }
  )
  expect_equal(f$ui(manager_test_request())$status, 200L)
})

test_that("configured account capacity includes logged-out generations", {
  now <- as.numeric(Sys.time())
  auth <- new.env(parent = emptyenv())
  auth$login <- list(
    subject = "local-account",
    session_id = "login",
    generation = "one",
    authenticated_at = now - 10,
    expires_at = now + 3600
  )
  policy <- oauth_account_owner(
    function(session) auth$login,
    idle_timeout = 600,
    absolute_timeout = 3600,
    reauth_after_seconds = 3600,
    max_entries = 2L
  )
  f <- manager_test_fixture("account", policy)
  for (generation in c("one", "two")) {
    auth$login$generation <- generation
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = f$manager),
      session = manager_test_session(),
      {
        health <- session$getReturned()
        expect_length(health$connections(), 0L)
        health$logout(revoke = FALSE, reload = FALSE)
      }
    )
  }
  auth$login$generation <- "three"
  expect_snapshot(
    error = TRUE,
    transform = function(lines) {
      gsub("Trace ID: [A-Za-z0-9_-]+", "Trace ID: <redacted>", lines)
    },
    {
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = f$manager),
        session = manager_test_session(),
        {}
      )
    }
  )
})

test_that("the same browser restores both grants across separate Shiny sessions", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  kept <- new.env(parent = emptyenv())
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
      session$onSessionEnded(ctl$end)
    },
    {
      kept$a <- manager_test_accept(ctl, "a", manager_test_token("access-a"))
      kept$b <- manager_test_accept(ctl, "b", manager_test_token("access-b"))
      expect_length(ctl$records(), 2L)
      kept$first_controller <- ctl
    }
  )
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      expect_length(ctl$records(), 2L)
      expect_identical(ctl$read(kept$a)$token@access_token, "access-a")
      expect_identical(ctl$read(kept$b)$client, f$manager$clients$b)
      expect_error(kept$first_controller$read(kept$a), "owner is unavailable")
      result <- ctl$disconnect(kept$b, revoke = FALSE)
      expect_identical(result$local, "disconnected")
      expect_identical(ctl$read(kept$b)$status, "disconnected")
      expect_identical(ctl$read(kept$a)$token@access_token, "access-a")
    }
  )
  foreign <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = foreign
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      expect_length(ctl$records(), 0L)
      expect_error(ctl$read(kept$a), "Connection is unavailable")
      expect_error(ctl$disconnect(kept$a, FALSE), "Connection is unavailable")
    }
  )
})

test_that("owner rotation and disconnect-all invalidate pending managed commits", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      hooks <- ctl$hooks("a")
      first <- hooks$prepare()
      expect_false(ctl$hooks("b")$validate(first))
      ctl$disconnect_all(FALSE)
      expect_false(hooks$validate(first))
      expect_error(
        hooks$accept(manager_test_token(), first, as.numeric(Sys.time())),
        "owner is unavailable"
      )
      pending <- hooks$prepare()
      owners <- f$manager$state$owners
      verified <- owners$resolve(connection_owner_cookie_read(
        session$request,
        owners$cookie_name
      ))
      owners$rotate(verified)
      expect_false(hooks$validate(pending))
      expect_error(ctl$records(), "owner is unavailable")
    }
  )
})

test_that("refresh preserves grant identity and original retention time", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  local_mocked_bindings(refresh_token = function(client, token, ...) {
    manager_test_token("refreshed", "rotated")
  })
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      id <- manager_test_accept(ctl)
      before <- ctl$read(id)
      expect_true(ctl$refresh(id))
      after <- ctl$read(id)
      expect_identical(after$token@access_token, "refreshed")
      expect_identical(after$token@refresh_token, "rotated")
      expect_identical(after$authenticated_at, before$authenticated_at)
      expect_identical(after$stored$expires_at, before$stored$expires_at)
      expect_gt(after$stored$revision, before$stored$revision)
    }
  )
})

for (outcome in c("not_consumed", "possibly_consumed", "consumed")) {
  test_that(paste("manager refresh follows the", outcome, "outcome"), {
    f <- manager_test_fixture()
    cookie <- manager_test_cookie(f)
    calls <- 0L
    local_mocked_bindings(refresh_token = function(...) {
      calls <<- calls + 1L
      stop(refresh_outcome_error(
        simpleError("sensitive provider response"),
        outcome
      ))
    })
    shiny::testServer(
      session = manager_test_session(),
      function(input, output, session) {
        session$request <- list(
          HTTP_ORIGIN = "https://app.example",
          HTTP_COOKIE = cookie
        )
        ctl <- connection_manager_controller(f$manager, session)
      },
      {
        id <- manager_test_accept(ctl)
        error <- tryCatch(ctl$refresh(id), error = identity)
        expect_match(conditionMessage(error), "Connection refresh failed")
        expect_false(grepl("sensitive", conditionMessage(error)))
        row <- ctl$read(id)
        expect_identical(
          row$status,
          if (outcome == "not_consumed") "active" else "uncertain"
        )
        if (outcome != "not_consumed") {
          expect_null(row$token)
          expect_error(ctl$refresh(id), "current state")
          expect_identical(calls, 1L)
        }
      }
    )
  })
}

test_that("disconnect wins against a competing async refresh result", {
  skip_if_not_installed("promises")
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  finish <- NULL
  calls <- 0L
  revoked <- 0L
  local_mocked_bindings(
    refresh_token = function(...) {
      calls <<- calls + 1L
      promises::promise(function(resolve, reject) {
        finish <<- resolve
      })
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
      list(supported = TRUE, revoked = TRUE)
    }
  )
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      id <- manager_test_accept(ctl)
      failure <- NULL
      promises::catch(ctl$refresh(id, async = TRUE), function(error) {
        failure <<- error
      })
      expect_identical(ctl$read(id)$status, "refreshing")
      expect_error(ctl$refresh(id, async = TRUE), "current state")
      expect_identical(calls, 1L)
      ctl$disconnect(id, FALSE)
      finish(manager_test_token("late", "late-rotated"))
      poll_for_async(function() !is.null(failure), session)
      expect_identical(ctl$read(id)$status, "disconnected")
      expect_null(ctl$read(id)$token)
      expect_identical(revoked, 2L)
    }
  )
})

test_that("logout invalidates the owner before bounded remote cleanup", {
  local_options(
    shinyOAuth.tls_min_version = "1.2",
    shinyOAuth.retry_max_tries = 5L
  )
  # Construct under the same validation policy that will be used for requests.
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  seen <- list()
  local_mocked_bindings(revoke_token = function(...) {
    seen[[length(seen) + 1L]] <<- list(
      owner = f$manager$state$owners$resolve(sub("^[^=]+=", "", cookie)),
      timeout = getOption("shinyOAuth.timeout"),
      retries = getOption("shinyOAuth.retry_max_tries"),
      tls = getOption("shinyOAuth.tls_min_version")
    )
    stop("private provider response")
  })
  shiny::testServer(
    session = manager_test_session(),
    function(input, output, session) {
      session$request <- list(
        HTTP_ORIGIN = "https://app.example",
        HTTP_COOKIE = cookie
      )
      ctl <- connection_manager_controller(f$manager, session)
    },
    {
      manager_test_accept(ctl)
      result <- ctl$logout()
      expect_identical(result[[1L]]$local, "disconnected")
      expect_identical(
        result[[1L]]$remote,
        list(refresh = "failed", access = "failed")
      )
      expect_length(seen, 2L)
      expect_null(seen[[1L]]$owner)
      expect_lte(seen[[1L]]$timeout, 2)
      expect_identical(seen[[1L]]$retries, 1L)
      expect_identical(seen[[1L]]$tls, "1.2")
      expect_identical(getOption("shinyOAuth.retry_max_tries"), 5L)
      expect_error(ctl$records(), "owner is unavailable")
    }
  )
})

test_that("public manager references use latest credentials and redact summaries", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      list(
        access_token = "public-managed-access",
        refresh_token = "public-managed-refresh",
        token_type = "Bearer",
        expires_in = 3600,
        scope = "read write",
        patient = "private-patient"
      )
    },
    req_with_retry = function(req, ...) req,
    refresh_token = function(...) {
      manager_test_token("public-rotated", "refresh-rotated")
    }
  )
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f$manager),
    session = manager_test_session(cookie),
    {
      # Drive the same module callback entry used by the browser bridge. This unit
      # test does not claim real browser navigation or sandbox interoperability.
      health <- session$getReturned()
      values <- modules$a
      state <- parse_query_param(values$build_auth_url(), "state")
      values$.process_query(paste0("?code=ok&state=", state))
      session$flushReact()
      rows <- health$connections()
      expect_length(rows, 1L)
      id <- rows[[1L]]$connection_id
      connection <- health$connection(id)
      expect_true(connection$is_usable())
      request <- connection$request("api", "records")
      expect_identical(request$url, "https://api.example/a/records")
      expect_true(connection$refresh())
      expect_identical(connection$summary()$connection_id, id)
      expect_false(grepl(
        "public-managed|private-patient|refresh-rotated",
        paste(capture.output(str(rows)), collapse = "")
      ))
      expect_error(
        connection$request("api", "https://api.example/b/records"),
        "approved base"
      )
      health$disconnect(id, FALSE)
      expect_false(connection$is_usable())
      expect_null(values$token)
    }
  )
})

test_that("account restoration requires the trusted current login and stable subject", {
  now <- as.numeric(Sys.time())
  auth <- new.env(parent = emptyenv())
  auth$login <- list(
    subject = "local-account-a",
    session_id = "login-one",
    generation = "one",
    authenticated_at = now - 10,
    expires_at = now + 3600
  )
  owner <- oauth_account_owner(function(session) auth$login, 600, 3600, 3600)
  f <- manager_test_fixture("account", owner)
  expect_null(f$ui(manager_test_request())$headers[["Set-Cookie"]])
  kept <- new.env(parent = emptyenv())
  server <- function(input, output, session) {
    ctl <- connection_manager_controller(f$manager, session)
    session$onSessionEnded(ctl$end)
  }
  shiny::testServer(server, session = manager_test_session(), {
    kept$id <- manager_test_accept(ctl)
    kept$pending <- ctl$hooks("b")$prepare()
    auth$login$generation <- "two"
    expect_error(ctl$read(kept$id), "owner is unavailable")
    expect_false(ctl$hooks("b")$validate(kept$pending))
  })
  shiny::testServer(server, session = manager_test_session(), {
    expect_length(ctl$records(), 1L)
    expect_identical(ctl$read(kept$id)$token@access_token, "synthetic-access")
    expect_false(ctl$hooks("b")$validate(kept$pending))
    auth$login$subject <- "local-account-b"
    expect_error(ctl$records(), "owner is unavailable")
  })
  shiny::testServer(server, session = manager_test_session(), {
    expect_length(ctl$records(), 0L)
    expect_error(ctl$read(kept$id), "Connection is unavailable")
  })
  auth$login$subject <- "local-account-a"
  auth$login$session_id <- "login-three"
  shiny::testServer(server, session = manager_test_session(), {
    expect_length(ctl$records(), 1L)
    ctl$logout(FALSE)
    expect_error(ctl$read(kept$id), "owner is unavailable")
  })
  expect_error(
    shiny::testServer(server, session = manager_test_session(), {}),
    "No active local owner"
  )
  auth$login$session_id <- "login-four"
  shiny::testServer(server, session = manager_test_session(), {
    expect_identical(ctl$read(kept$id)$status, "disconnected")
    expect_null(ctl$read(kept$id)$token)
  })
})

test_that("session-only navigation retains pending state but drops old grants", {
  f <- manager_test_fixture("shiny")
  kept <- new.env(parent = emptyenv())
  server <- function(input, output, session) {
    ctl <- connection_manager_controller(f$manager, session)
    session$onSessionEnded(ctl$end)
  }
  shiny::testServer(server, session = manager_test_session(), {
    kept$id <- manager_test_accept(ctl)
    kept$pending <- ctl$hooks("b")$prepare()
    kept$controller <- ctl
  })
  shiny::testServer(server, session = manager_test_session(), {
    expect_length(ctl$records(), 0L)
    expect_error(ctl$read(kept$id), "Connection is unavailable")
    expect_error(kept$controller$read(kept$id), "owner is unavailable")
    # Only the core callback, after browser/state proof, invokes this commit.
    hooks <- ctl$hooks("b")
    expect_true(hooks$validate(kept$pending))
    hooks$accept(manager_test_token(), kept$pending, as.numeric(Sys.time()))
    expect_false(hooks$validate(kept$pending))
    expect_length(ctl$records(), 1L)
  })
  shiny::testServer(server, session = manager_test_session(), {
    expect_length(ctl$records(), 0L)
  })
})

test_that("owner expiry rejects a completed refresh and polling cannot extend idle time", {
  clock <- new.env(parent = emptyenv())
  clock$now <- as.numeric(Sys.time())
  policy <- oauth_browser_owner(idle_timeout = 10, absolute_timeout = 60)
  f <- manager_test_fixture(owner = policy)
  state <- f$manager$state
  state$owners <- connection_browser_sessions(
    policy,
    f$manager$app_origin,
    "health",
    f$manager$keys$owner,
    clock = function() clock$now
  )
  cookie <- manager_test_cookie(f)
  finish <- NULL
  revoked <- 0L
  local_mocked_bindings(
    refresh_token = function(...) {
      promises::promise(function(resolve, reject) {
        finish <<- resolve
      })
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
      list(supported = TRUE, revoked = TRUE)
    }
  )
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f$manager, async = TRUE),
    session = manager_test_session(cookie),
    {
      health <- session$getReturned()
      id <- manager_test_accept(controller)
      row <- controller$read(id)$stored
      failure <- NULL
      promises::catch(controller$refresh(id, async = TRUE), function(error) {
        failure <<- error
      })
      clock$now <- clock$now + 9
      expect_length(health$connections(), 1L)
      clock$now <- clock$now + 2
      session$elapse(10000)
      expect_length(health$connections(), 0L)
      expect_identical(health$errors(), list(owner = "owner_unavailable"))
      finish(manager_test_token("late-expiry", "late-expiry-refresh"))
      poll_for_async(function() !is.null(failure), session)
      expect_identical(f$manager$store$read(row$owner, id)$status, "uncertain")
      expect_identical(revoked, 2L)
    }
  )
})

test_that("automatic refresh retry cooldown survives new sessions", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  calls <- 0L
  local_mocked_bindings(refresh_token = function(...) {
    calls <<- calls + 1L
    stop(refresh_outcome_error(
      simpleError("offline before send"),
      "not_consumed"
    ))
  })
  # This token remains acceptable at import and becomes due under proactive refresh.
  token <- manager_test_token()
  token@expires_at <- as.numeric(Sys.time()) + 45
  args <- list(id = "health", manager = f$manager, refresh_proactively = TRUE)
  shiny::testServer(
    oauth_connections_server,
    args = args,
    session = manager_test_session(cookie),
    {
      manager_test_accept(controller, token = token)
      session$flushReact()
      expect_identical(calls, 1L)
    }
  )
  shiny::testServer(
    oauth_connections_server,
    args = args,
    session = manager_test_session(cookie),
    {
      session$flushReact()
      expect_identical(calls, 1L)
      expect_length(controller$records(), 1L)
    }
  )
})

test_that("fixed connection outputs recheck owner, token and retention expiry", {
  check_expiry <- function(boundary) {
    clock <- new.env(parent = emptyenv())
    clock$now <- as.numeric(Sys.time())
    local_mocked_bindings(
      Sys.time = function() {
        as.POSIXct(clock$now, origin = "1970-01-01", tz = "UTC")
      },
      .package = "base"
    )
    f <- manager_test_fixture(
      owner = oauth_browser_owner(
        idle_timeout = if (boundary == "owner") 10 else 60000,
        absolute_timeout = 60000
      )
    )
    cookie <- manager_test_cookie(f)
    requests <- 0L
    local_mocked_bindings(perform_resource_req = function(...) {
      requests <<- requests + 1L
      "synthetic records"
    })
    shiny::testServer(
      oauth_connections_server,
      args = list(
        id = "health",
        manager = f$manager,
        refresh_check_interval = 100
      ),
      session = manager_test_session(cookie),
      {
        token <- manager_test_token(refresh = NA_character_)
        token@expires_at <- clock$now + if (boundary == "token") 10 else 100000
        id <- manager_test_accept(controller, token = token)
        health <- session$getReturned()
        fixed <- health$connection(id)
        output$status <- shiny::renderText({
          if (fixed$is_usable()) fixed$summary()$status else "unavailable"
        })
        output$data <- shiny::renderText({
          if (!fixed$is_usable()) {
            return("unavailable")
          }
          fixed$request("api", "records")
        })
        session$flushReact()
        expect_identical(output$status, "active", info = boundary)
        expect_identical(output$data, "synthetic records", info = boundary)
        expect_identical(requests, 1L, info = boundary)

        clock$now <- clock$now + 5
        session$elapse(100)
        expect_identical(output$status, "active", info = boundary)
        expect_identical(output$data, "synthetic records", info = boundary)
        expect_identical(requests, 1L, info = boundary)

        clock$now <- clock$now + if (boundary == "retention") 28796 else 6
        session$elapse(100)
        expect_identical(output$status, "unavailable", info = boundary)
        expect_identical(output$data, "unavailable", info = boundary)
        expect_identical(requests, 1L, info = boundary)
      }
    )
  }
  invisible(lapply(c("owner", "token", "retention"), check_expiry))
})

test_that("repeated authorizations create independent grants at the same client", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f$manager),
    session = manager_test_session(cookie),
    {
      health <- session$getReturned()
      first <- manager_test_accept(
        controller,
        token = manager_test_token("first")
      )
      second <- manager_test_accept(
        controller,
        token = manager_test_token("second")
      )
      expect_false(identical(first, second))
      expect_length(health$connections(), 2L)
      health$disconnect(second, FALSE)
      expect_true(health$connection(first)$is_usable())
      expect_false(health$connection(second)$is_usable())
      expect_identical(controller$read(first)$token@access_token, "first")
    }
  )
})

test_that("Shiny setup rejects missing or cross-origin request headers", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  for (origin in list(
    NULL,
    "https://other.example",
    "https://app.example/path"
  )) {
    session <- manager_test_session(cookie)
    session$request <- list(HTTP_COOKIE = cookie, HTTP_ORIGIN = origin)
    expect_error(
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = f$manager),
        session = session,
        {}
      ),
      "configured application Origin"
    )
  }
})

test_that("HTTP continuations route to the manager's nested module namespace", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  local_mocked_bindings(swap_code_for_token_set = function(...) {
    list(
      access_token = "bridge-access",
      token_type = "Bearer",
      expires_in = 3600,
      scope = "read write"
    )
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f$manager),
    session = manager_test_session(cookie),
    {
      health <- session$getReturned()
      for (site in c("a", "b")) {
        state <- parse_query_param(modules[[site]]$build_auth_url(), "state")
        response <- f$ui(manager_test_request(
          cookie,
          path = paste0("/callback/", site),
          query = paste0("code=ok&state=", state)
        ))
        expect_identical(response$status, 303L)
        query <- response$headers$Location
        expect_match(query, paste0("health-", site), fixed = TRUE)
        for (module in modules) {
          module$.process_query(
            query,
            current_uri = paste0(
              f$manager$clients[[site]]@redirect_uri,
              query
            )
          )
        }
        session$flushReact()
        expect_length(health$errors(), 0L)
      }
      expect_length(health$connections(), 2L)
      expect_null(modules$a$token)
      expect_null(modules$b$token)
    }
  )
})

test_that("nested callback documents load dependencies from the public app directory", {
  f <- manager_test_fixture()
  response <- f$ui(manager_test_request(path = "/callback/a"))
  expect_match(
    response$content,
    '<head><base href="https://app.example/">',
    fixed = TRUE
  )
  expect_lt(
    regexpr("<base ", response$content)[[1L]],
    regexpr("<script", response$content)[[1L]]
  )
  ui <- oauth_connections_ui(
    shiny::fluidPage("App"),
    "health",
    f$manager,
    app_base_path = "/callback/"
  )
  response <- ui(manager_test_request(path = "/callback/a"))
  expect_match(
    response$content,
    '<base href="https://app.example/callback/">',
    fixed = TRUE
  )
  expect_error(
    oauth_connections_ui(
      shiny::fluidPage(),
      "health",
      f$manager,
      app_base_path = "/other/"
    ),
    "inside app_base_path"
  )
  expect_error(
    oauth_connections_ui(
      shiny::fluidPage(),
      "health",
      f$manager,
      app_base_path = "/callback"
    ),
    "directory path"
  )
})

test_that("document base insertion invalidates old HTML length and validators", {
  response <- shiny::httpResponse(
    content = "<html><head></head><body>App</body></html>",
    headers = list(
      "Content-Length" = "41",
      ETag = "old",
      "Content-MD5" = "old",
      "X-Frame-Options" = "DENY"
    )
  )
  updated <- connection_manager_document_base(response, "https://app.example/")
  expect_null(updated$headers[["Content-Length"]])
  expect_null(updated$headers$ETag)
  expect_null(updated$headers[["Content-MD5"]])
  expect_identical(updated$headers[["X-Frame-Options"]], "DENY")
  expect_match(
    updated$content,
    '<base href="https://app.example/">',
    fixed = TRUE
  )
})
