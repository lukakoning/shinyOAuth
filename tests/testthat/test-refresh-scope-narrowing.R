narrowing_client <- function(scopes = c("read", "write"), smart = FALSE) {
  client <- make_test_client(scopes = scopes, use_nonce = FALSE)
  client@scope_validation <- "none"
  if (smart) client@scope_policy <- list(profile = "smart", version = 1L,
    allow_v1 = FALSE, required_scopes = scopes[[1L]])
  client
}

narrowing_token <- function(scopes = c("read", "write")) {
  OAuthToken(access_token = "synthetic-before", refresh_token = "synthetic-refresh",
    token_type = "Bearer", expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = scopes, granted_scopes_verified = TRUE,
    initial_extra_fields = list(marker = "initial"))
}

narrowing_response <- function(req, scope = "read", rotate = TRUE) {
  body <- list(access_token = "synthetic-after", token_type = "Bearer", expires_in = 3600)
  if (!is.null(scope)) body$scope <- scope
  if (rotate) body$refresh_token <- "synthetic-rotated"
  httr2::response(url = req$url, status = 200L,
    headers = list("content-type" = "application/json"),
    body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE)))
}

narrowing_manager <- function() {
  client <- narrowing_client()
  client@redirect_uri <- "https://app.example/callback"
  target <- oauth_target(client, c(api = "https://api.example/v1"), "read")
  manager <- oauth_connections(list(a = target), "https://app.example", retention = "browser",
    owner = oauth_browser_owner(), store = oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  ui <- oauth_connections_ui(shiny::fluidPage("Refresh narrowing"), "health", manager)
  list(manager = manager, ui = ui)
}

narrowing_accept <- function(controller) {
  hooks <- controller$hooks("a")
  hooks$accept(narrowing_token(), hooks$prepare(), as.numeric(Sys.time()) - 60)
  controller$records()[[1L]]$stored$id
}

test_that("explicit narrowing validates syntax, grant, configuration and required scopes", {
  client <- narrowing_client()
  token <- narrowing_token()
  request <- refresh_scope_request(client, token, "read read", "read")
  expect_identical(request, list(scopes = "read", required_scopes = "read"))
  for (scopes in list(character(), "", NA_character_, list("read"), 1, "bad\\scope", strrep("x", 8193))) {
    expect_error(refresh_scope_request(client, token, scopes, "read"))
  }
  expect_error(refresh_scope_request(client, token, "admin", "read"), "covered")
  expect_error(refresh_scope_request(client, token, "write", "read"), "required")
  expect_error(refresh_scope_request(client, narrowing_token("read"), c("read", "write")), "covered")
  expect_error(refresh_scope_request(client, narrowing_token(c("read", "admin")), "admin"), "configuration")
  expect_error(validate_refresh_scope_request(client, token, list(scopes = "read")), "internal")
})

for (omitted in c(FALSE, TRUE)) test_that(paste("scope request controls explicit and omitted responses", omitted), {
  client <- narrowing_client()
  client@scope_validation <- "strict"
  token <- narrowing_token()
  seen <- NULL
  local_mocked_bindings(req_with_retry = function(req, ...) {
    seen <<- req$body$data
    narrowing_response(req, if (omitted) NULL else "read")
  })
  result <- refresh_token_dispatch(client, token,
    scope_request = refresh_scope_request(client, token, "read", "read"))
  expect_identical(as.character(seen$scope), "read")
  expect_identical(as.character(seen$grant_type), "refresh_token")
  expect_identical(result@granted_scopes, "read")
  expect_identical(result@granted_scopes_verified, !omitted)
  expect_identical(result@refresh_token, "synthetic-rotated")
  expect_identical(result@initial_extra_fields, token@initial_extra_fields)
  expect_setequal(effective_client_scopes(client), c("read", "write"))
})

test_that("legacy refresh still omits scope and carries its previous grant", {
  client <- narrowing_client()
  token <- narrowing_token()
  seen <- NULL
  local_mocked_bindings(req_with_retry = function(req, ...) {
    seen <<- req$body$data
    narrowing_response(req, NULL)
  })
  result <- refresh_token(client, token)
  expect_false("scope" %in% names(seen))
  expect_identical(result@granted_scopes, token@granted_scopes)
  expect_false(result@granted_scopes_verified)
})

for (scope in c("read write", "admin", "write")) test_that(paste("requested limit is enforced before UserInfo", scope), {
  client <- narrowing_client()
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@userinfo_required <- TRUE
  token <- narrowing_token()
  userinfo <- 0L
  local_mocked_bindings(req_with_retry = function(req, ...) narrowing_response(req, scope),
    get_userinfo = function(...) { userinfo <<- userinfo + 1L; list() })
  error <- tryCatch(refresh_token_dispatch(client, token,
    scope_request = refresh_scope_request(client, token, "read", "read")), error = identity)
  expect_s3_class(error, "shinyOAuth_token_error")
  expect_identical(error$refresh_credential_outcome, "consumed")
  expect_identical(userinfo, 0L)
  expect_identical(token@access_token, "synthetic-before")
})

test_that("introspection cannot restore permissions outside the requested limit", {
  client <- narrowing_client()
  client@provider@introspection_url <- "https://example.com/introspect"
  token <- narrowing_token()
  local_mocked_bindings(req_with_retry = function(req, ...) narrowing_response(req),
    introspect_token = function(...) list(supported = TRUE, active = TRUE, raw = list(scope = "read write")))
  expect_error(refresh_token_dispatch(client, token, introspect = TRUE,
    scope_request = refresh_scope_request(client, token, "read", "read")), "scope")
})

test_that("SMART narrowing uses interaction coverage and keeps explicit response evidence", {
  client <- narrowing_client(c("patient/Patient.r", "patient/*.rs"), smart = TRUE)
  token <- narrowing_token(c("patient/Patient.r", "patient/Observation.rs"))
  scopes <- c("patient/Patient.r", "patient/Observation.r")
  request <- refresh_scope_request(client, token, scopes, "patient/Patient.r")
  expect_setequal(request$scopes, scopes)
  expect_error(refresh_scope_request(client, token, "patient/*.r"), "covered")
  expect_error(refresh_scope_request(client, token, "patient/Observation.r"), "required")
  expect_error(refresh_scope_request(client, token, c("patient/Patient.r", "patient/Observation.rr")), "covered")
  local_mocked_bindings(req_with_retry = function(req, ...) narrowing_response(req, paste(scopes, collapse = " ")))
  result <- refresh_token_dispatch(client, token, scope_request = request)
  expect_setequal(result@granted_scopes, scopes)
  expect_true(result@granted_scopes_verified)
  expect_no_error(validate_refresh_scope_grant(client, scopes, request))
  expect_error(validate_refresh_scope_grant(client, token@granted_scopes, request), "scope limit")
  expect_error(resolve_granted_scope_state(NULL, request$scopes, smart = TRUE), "explicit scope")
})

test_that("encrypted narrowing policy survives sessions and prevents widening before a claim", {
  f <- narrowing_manager()
  cookie <- manager_test_cookie(f)
  kept <- new.env(parent = emptyenv())
  requests <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    requests[[length(requests) + 1L]] <<- req$body$data
    narrowing_response(req)
  })
  server <- function(input, output, session) {
    controller <- connection_manager_controller(f$manager, session)
  }
  shiny::testServer(server, session = manager_test_session(cookie), {
    kept$id <- narrowing_accept(controller)
    before <- controller$read(kept$id)
    expect_error(controller$refresh(kept$id, scopes = "write"), "required")
    expect_length(requests, 0L)
    expect_identical(controller$read(kept$id)$stored$revision, before$stored$revision)
    expect_true(controller$refresh(kept$id, scopes = "read"))
    after <- controller$read(kept$id)
    expect_true(after$refresh_scope_narrowed)
    expect_identical(after$authenticated_at, before$authenticated_at)
    expect_identical(after$stored$expires_at, before$stored$expires_at)
    expect_null(after$stored$refresh_scope_narrowed)
    expect_error(controller$refresh(kept$id, scopes = c("read", "write")), "covered")
    expect_length(requests, 1L)
    expect_identical(controller$read(kept$id)$stored$revision, after$stored$revision)
  })
  shiny::testServer(server, session = manager_test_session(cookie), {
    expect_true(controller$read(kept$id)$refresh_scope_narrowed)
    expect_true(controller$refresh(kept$id, touch = FALSE))
    expect_identical(as.character(requests[[2L]]$scope), "read")
    expect_identical(controller$read(kept$id)$token@granted_scopes, "read")
  })
})

test_that("provider rejection never retries without scope or activates a failed narrowing", {
  f <- narrowing_manager()
  calls <- 0L
  local_mocked_bindings(req_with_retry = function(req, ...) {
    calls <<- calls + 1L
    stop(refresh_outcome_error(simpleError("provider declined requested permissions"), "not_consumed"))
  })
  shiny::testServer(function(input, output, session) {
    controller <- connection_manager_controller(f$manager, session)
  }, session = manager_test_session(manager_test_cookie(f)), {
    id <- narrowing_accept(controller)
    expect_error(controller$refresh(id, scopes = "read"), "Connection refresh failed")
    expect_identical(calls, 1L)
    row <- controller$read(id)
    expect_identical(row$status, "active")
    expect_false(row$refresh_scope_narrowed)
    expect_setequal(row$token@granted_scopes, c("read", "write"))
  })
})

test_that("a rejected rotated grant makes the connection uncertain", {
  f <- narrowing_manager()
  local_mocked_bindings(req_with_retry = function(req, ...) narrowing_response(req, "read write"))
  shiny::testServer(function(input, output, session) {
    controller <- connection_manager_controller(f$manager, session)
  }, session = manager_test_session(manager_test_cookie(f)), {
    id <- narrowing_accept(controller)
    expect_error(controller$refresh(id, scopes = "read"), "Connection refresh failed")
    expect_identical(controller$read(id)$status, "uncertain")
    expect_null(controller$read(id)$token)
    expect_error(controller$refresh(id), "current state")
  })
})

test_that("different pending scope requests cannot join one refresh flight", {
  client <- narrowing_client()
  token <- narrowing_token()
  finish <- NULL
  deferred <- promises::promise(function(resolve, reject) finish <<- resolve)
  local_mocked_bindings(refresh_token_impl = function(...) deferred)
  request <- refresh_scope_request(client, token, "read")
  p <- refresh_token_dispatch(client, token, async = TRUE, scope_request = request)
  expect_identical(refresh_token_dispatch(client, token, async = TRUE, scope_request = request), p)
  expect_error(refresh_token_dispatch(client, token, async = TRUE,
    scope_request = refresh_scope_request(client, token, "write")), "different")
  expect_error(refresh_token(client, token, async = TRUE), "different")
  finish(narrowing_token("read"))
  done <- FALSE
  promises::then(p, function(...) done <<- TRUE)
  poll_for_async(function() done)
  expect_true(done)
})

test_that("disconnect prevents a pending narrowed grant from being installed", {
  f <- narrowing_manager()
  finish <- NULL
  revoked <- 0L
  local_mocked_bindings(
    refresh_token_dispatch = function(...) promises::promise(function(resolve, reject) finish <<- resolve),
    revoke_token = function(...) {
      revoked <<- revoked + 1L
      list(supported = TRUE, revoked = TRUE)
    }
  )
  shiny::testServer(function(input, output, session) {
    controller <- connection_manager_controller(f$manager, session)
  }, session = manager_test_session(manager_test_cookie(f)), {
    id <- narrowing_accept(controller)
    failure <- NULL
    promises::catch(controller$refresh(id, async = TRUE, scopes = "read"),
      function(error) failure <<- error)
    expect_identical(controller$read(id)$status, "refreshing")
    controller$disconnect(id, FALSE)
    finish(narrowing_token("read"))
    poll_for_async(function() !is.null(failure), session)
    expect_s3_class(failure, "shinyOAuth_token_error")
    expect_identical(controller$read(id)$status, "disconnected")
    expect_null(controller$read(id)$token)
    expect_identical(revoked, 2L)
  })
})
