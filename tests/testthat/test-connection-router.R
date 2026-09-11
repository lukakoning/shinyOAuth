router_controller <- function(manager, cookie) {
  session <- manager_test_session(cookie)
  controller <- shiny::withReactiveDomain(session, connection_manager_controller(manager, session))
  # Give direct fixture calls the same owning reactive domain as a Shiny module.
  wrap <- function(value) {
    if (is.list(value)) return(lapply(value, wrap))
    if (!is.function(value)) return(value)
    function(...) shiny::withReactiveDomain(session, shiny::isolate(wrap(value(...))))
  }
  wrap(controller)
}

router_fixture <- function(post = FALSE, jarm = FALSE, policy = "shared_routes",
                           distinct_issuers = FALSE, par = FALSE, same_registration = FALSE,
                           encrypted = FALSE) {
  targets <- lapply(c("a", "b"), function(id) {
    issuer <- paste0("https://issuer.example", if (distinct_issuers) paste0("/", id))
    provider <- oauth_provider(name = id, issuer = issuer, issuer_thus_oidc = FALSE,
      auth_url = paste0(issuer, "/authorize"), token_url = paste0(issuer, "/token"),
      par_url = if (par) paste0(issuer, "/par") else NA_character_,
      token_auth_style = "public", use_nonce = FALSE,
      authorization_response_iss_parameter_supported = TRUE)
    client <- oauth_client(provider, client_id = id, client_secret = strrep(id, 64),
      redirect_uri = "https://app.example/callback", state_key = strrep(id, 64),
      scopes = "read", authorization_server_mode = "multi_issuer",
      response_mode = paste0(if (post) "form_post" else "query", if (jarm) ".jwt" else ""),
      jarm_signed_response_alg = if (jarm) "HS256" else NULL,
      jarm_encrypted_response_alg = if (encrypted) "RSA-OAEP" else NULL,
      jarm_encrypted_response_enc = if (encrypted) "A128CBC-HS256" else NULL,
      jarm_decryption_private_key = if (encrypted) openssl::rsa_keygen(2048) else NULL)
    oauth_target(client, c(api = paste0("https://api.example/", id)), "read", id)
  })
  names(targets) <- c("a", "b")
  if (same_registration) {
    targets$b <- oauth_target(targets$a$client, c(api = "https://api.example/b"), "read", "b")
  }
  manager <- oauth_connections(targets, "https://app.example", callback_policy = policy,
    retention = "browser", owner = oauth_browser_owner(),
    store = oauth_connection_store_memory(),
    keys = list(credentials = openssl::rand_bytes(32), owner = openssl::rand_bytes(32)))
  ui <- oauth_connections_ui(shiny::fluidPage("Shared callback"), "health", manager)
  f <- list(manager = manager, ui = ui)
  f$cookie <- manager_test_cookie(f)
  f$controller <- router_controller(manager, f$cookie)
  f$clients <- stats::setNames(lapply(targets, function(target) target$client), c("health-a", "health-b"))
  f
}

router_prepare <- function(f, id = "a", browser = valid_browser_token()) {
  hooks <- f$controller$hooks(id)
  context <- hooks$prepare()
  prepared <- prepare_call(f$manager$targets[[id]]$client, browser,
    .transaction_context = context, .defer_build = TRUE)
  if (is.function(hooks$prepared)) hooks$prepared(prepared, context)
  list(context = context, prepared = prepared, state = prepared$build_args$payload, browser = browser)
}

router_request <- function(f, auth, id = auth$context$target, post = FALSE,
                           jarm = FALSE, error = FALSE, overrides = list()) {
  client <- f$manager$targets[[id]]$client
  fields <- c(list(state = auth$state, iss = client@provider@issuer),
    if (error) list(error = "access_denied") else list(code = "synthetic-code"))
  if (jarm) {
    fields <- list(response = jose::jwt_encode_hmac(do.call(jose::jwt_claim,
      c(fields, list(aud = client@client_id, exp = as.numeric(Sys.time()) + 60))), client@client_secret))
  }
  fields <- utils::modifyList(fields, overrides)
  encoded <- httr2::url_query_build(fields)
  req <- manager_test_request(method = if (post) "POST" else "GET", path = "/callback",
    query = if (post) "" else encoded)
  if (post) {
    req$CONTENT_TYPE <- "application/x-www-form-urlencoded"
    req$rook.input <- list(read = function(n) charToRaw(encoded))
  }
  req
}

test_that("shared issuer routing is explicit and leaves the legacy registry strict", {
  f <- router_fixture()
  expect_error(oauth_connections(f$manager$targets, "https://app.example"), "multi_redirect_uri")
  expect_error(router_fixture(policy = "issuer"), "distinct issuers")
  expect_error(oauth_callback_registry(f$clients), "distinct issuers")
  expect_error(oauth_ui(shiny::fluidPage(), clients = f$clients), "distinct issuers")
  expect_error(oauth_connections(list(a = oauth_target(make_test_client(), c(api = "https://api.example"))),
    "https://app.example", callback_policy = "shared_routes"), "multi_issuer")
  issuer <- router_fixture(policy = "issuer", distinct_issuers = TRUE)
  expect_null(issuer$controller$hooks("a")$prepared)
  for (id in c("a", "b")) {
    auth <- router_prepare(issuer, id)
    expect_identical(issuer$ui(router_request(issuer, auth))$status, 303L)
  }
})

for (post in c(FALSE, TRUE)) for (jarm in c(FALSE, TRUE)) for (failure in c(FALSE, TRUE)) {
  test_that(paste("same-issuer bridge selects original registration", post, jarm, failure), {
    f <- router_fixture(post, jarm)
    authorizations <- lapply(c("a", "b"), function(id) router_prepare(f, id))
    names(authorizations) <- c("a", "b")
    exchanges <- character()
    local_mocked_bindings(swap_code_for_token_set = function(client, ...) {
      exchanges <<- c(exchanges, client@client_id)
      list(access_token = "synthetic-access", token_type = "Bearer", expires_in = 3600, scope = "read")
    })
    for (id in c("b", "a")) {
      auth <- authorizations[[id]]
      client <- f$manager$targets[[id]]$client
      payload <- state_payload_decrypt_validate(client, auth$state)
      before <- state_store_get(client, payload$state)
      response <- f$ui(router_request(f, auth, post = post, jarm = jarm, error = failure))
      expect_identical(response$status, 303L, info = response$content)
      expect_identical(state_store_get(client, payload$state), before)
      expect_length(f$manager$state$routes, if (id == "b") 2L else 1L)
      expect_false(grepl("code=|state=|response=", response$headers$Location))
      shiny::testServer(oauth_module_server_impl,
        args = list(id = paste0("health-", id), client = client, auto_redirect = FALSE,
          async = FALSE, .managed = f$controller$hooks(id)), {
          values$browser_token <- auth$browser
          values$.process_query(response$headers$Location,
            current_uri = paste0(client@redirect_uri, response$headers$Location))
          session$flushReact()
          expect_null(values$token)
          if (!failure) expect_null(values$error)
        })
      expect_null(f$manager$state$pending[[auth$context$transaction]])
    }
    expect_length(f$manager$state$routes, 0L)
    expect_identical(exchanges, if (failure) character() else c("b", "a"))
    rows <- f$controller$records()
    expect_length(rows, if (failure) 0L else 2L)
    if (!failure) expect_setequal(vapply(rows, function(row) row$stored$target, character(1)), c("a", "b"))
  })
}

test_that("routing cannot replace issuer, state, signature or registration verification", {
  for (jarm in c(FALSE, TRUE)) {
    f <- router_fixture(jarm = jarm)
    auth <- router_prepare(f)
    req <- router_request(f, auth, jarm = jarm)
    index <- as.list(f$manager$state$routes)
    logical_state <- state_payload_decrypt_validate(f$manager$targets$a$client, auth$state)$state
    before <- state_store_get(f$manager$targets$a$client, logical_state)
    bad <- list(
      router_request(f, auth, jarm = jarm, overrides = list(iss = "https://wrong.example")),
      router_request(f, auth, id = "b", jarm = jarm),
      router_request(f, auth, jarm = jarm, overrides = if (jarm) list(response = "invalid.jwt.value") else list(state = "unknown"))
    )
    wrong_route <- req
    wrong_route$PATH_INFO <- "/unregistered"
    bad <- c(bad, list(wrong_route))
    for (request in bad) {
      # Direct response has no client selector: changing id alone leaves its
      # exact same issuer/state pair valid, so only JARM tests registration here.
      if (!jarm && identical(request, bad[[2L]])) next
      expect_identical(f$ui(request)$status, 400L)
      expect_identical(as.list(f$manager$state$routes), index)
      expect_identical(state_store_get(f$manager$targets$a$client, logical_state), before)
    }
    expect_identical(f$ui(req)$status, 303L)
  }
})

test_that("routing records bind manager, target, exact state and live pending context", {
  f <- router_fixture()
  auth <- router_prepare(f)
  key <- connection_router_digest(auth$state)
  sealed <- f$manager$state$routes[[key]]
  expect_false(grepl(auth$state, sealed, fixed = TRUE))
  select <- function() connection_router_select(f$manager, f$clients, list(state = auth$state))
  expect_identical(names(select()), "health-a")
  expect_error(connection_router_register(f$manager, "a", auth$context, auth$prepared), "unavailable")
  expect_error(connection_router_select(f$manager, f$clients["health-b"], list(state = auth$state)), "route")
  route <- state_decrypt_gcm(sealed, connection_router_key(f$manager))
  manager_state <- f$manager$state
  for (field in c("manager", "target", "fingerprint", "digest", "context_digest", "purpose", "expires_at")) {
    changed <- route
    changed[[field]] <- if (field == "expires_at") 1 else "invalid"
    manager_state$routes[[key]] <- state_encrypt_gcm(changed, connection_router_key(f$manager))
    expect_error(select())
  }
  manager_state$routes[[key]] <- sealed
  foreign <- router_controller(f$manager, manager_test_cookie(f))
  expect_error(oauth_module_managed_context(foreign$hooks("a"), f$manager$targets$a$client,
    auth$state, auth$browser), "owner")
  expect_error(oauth_module_managed_context(f$controller$hooks("a"), f$manager$targets$a$client,
    auth$state, strrep("f", 128)), "Browser token mismatch")
  expect_identical(names(select()), "health-a")
  f$controller$logout(revoke = FALSE)
  expect_length(f$manager$state$routes, 0L)
  expect_error(select(), "unavailable")
})

test_that("expired routing entries are rejected read-only and pruned on preparation", {
  f <- router_fixture()
  auth <- router_prepare(f)
  pending <- f$manager$state$pending[[auth$context$transaction]]
  pending$context$expires_at <- 1
  manager_state <- f$manager$state
  manager_state$pending[[auth$context$transaction]] <- pending
  expect_error(connection_router_select(f$manager, f$clients, list(state = auth$state)), "unavailable")
  expect_length(f$manager$state$routes, 1L)
  f$controller$hooks("b")$prepare()
  expect_length(f$manager$state$routes, 0L)
  expect_null(f$manager$state$pending[[auth$context$transaction]])
})

test_that("same-issuer encrypted JARM requires distinct routes", {
  expect_error(router_fixture(jarm = TRUE, encrypted = TRUE), "encrypted JARM")
  expect_no_error(router_fixture(jarm = TRUE, encrypted = TRUE, distinct_issuers = TRUE, policy = "issuer"))
})

test_that("module registers structured state before provider work and cancels failed preparation", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- router_fixture()
  client <- f$manager$targets$a$client
  called <- FALSE
  local_mocked_bindings(build_prepared_authorization = function(client, prepared) {
    called <<- TRUE
    expect_identical(names(connection_router_select(f$manager, f$clients,
      list(state = prepared$build_args$payload))), "health-a")
    stop("synthetic provider failure")
  })
  shiny::testServer(oauth_module_server_impl,
    args = list(id = "health-a", client = client, auto_redirect = FALSE, async = FALSE,
      .managed = f$controller$hooks("a")), {
      values$browser_token <- "__SKIPPED__"
      expect_true(is.na(values$build_auth_url()))
      expect_length(f$manager$state$routes, 0L)
      expect_length(f$manager$state$pending, 0L)
    })
  expect_true(called)
})

test_that("async PAR registers state on the parent before dispatch and cleans up failure", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- router_fixture(par = TRUE)
  client <- f$manager$targets$a$client
  dispatched <- NULL
  local_mocked_bindings(async_dispatch = function(expr, args, ...) {
    dispatched <<- args$prepared
    expect_identical(names(connection_router_select(f$manager, f$clients,
      list(state = dispatched$build_args$payload))), "health-a")
    promises::promise(function(resolve, reject) reject(simpleError("synthetic PAR failure")))
  })
  shiny::testServer(oauth_module_server_impl,
    args = list(id = "health-a", client = client, auto_redirect = FALSE, async = TRUE,
      .managed = f$controller$hooks("a")), {
      values$browser_token <- "__SKIPPED__"
      result <- NULL
      promises::then(values$build_auth_url(), function(value) result <<- value)
      poll_for_async(function() !is.null(result), session)
      expect_true(is.na(result))
      expect_length(f$manager$state$routes, 0L)
      expect_length(f$manager$state$pending, 0L)
    })
  expect_false(is.null(dispatched))
  expect_null(client@state_store$get(dispatched$state_key, missing = NULL))
})

test_that("route, transport, parsing bounds and issuer checks precede index lookup", {
  f <- router_fixture()
  auth <- router_prepare(f)
  lookups <- 0L
  local_mocked_bindings(connection_router_select = function(...) {
    lookups <<- lookups + 1L
    stop("unexpected routing lookup")
  })
  req <- router_request(f, auth)
  duplicate <- req
  duplicate$QUERY_STRING <- paste0(req$QUERY_STRING, "&state=duplicate")
  wrong_route <- req
  wrong_route$PATH_INFO <- "/unregistered"
  for (request in list(duplicate, wrong_route,
    router_request(f, auth, post = TRUE),
    router_request(f, auth, overrides = list(iss = "https://unrecognized.example")),
    router_request(f, auth, overrides = list(state = strrep("x", oauth_callback_limits()$state + 1L))))) {
    expect_identical(f$ui(request)$status, 400L)
  }
  expect_identical(lookups, 0L)
})

test_that("selected signed JARM still requires signature, audience and expiry", {
  f <- router_fixture(jarm = TRUE)
  auth <- router_prepare(f)
  client <- f$manager$targets$a$client
  claims <- list(iss = client@provider@issuer, aud = client@client_id,
    exp = as.numeric(Sys.time()) + 60, state = auth$state, code = "synthetic-code")
  for (change in list(list(aud = "another-registration"), list(exp = 1), list(iss = "https://other.example"))) {
    response <- jose::jwt_encode_hmac(do.call(jose::jwt_claim, utils::modifyList(claims, change)), client@client_secret)
    expect_identical(f$ui(router_request(f, auth, jarm = TRUE, overrides = list(response = response)))$status, 400L)
    expect_length(f$manager$state$routes, 1L)
  }
  response <- jose::jwt_encode_hmac(do.call(jose::jwt_claim, claims), strrep("c", 64))
  expect_identical(f$ui(router_request(f, auth, jarm = TRUE, overrides = list(response = response)))$status, 400L)
  expect_identical(f$ui(router_request(f, auth, jarm = TRUE))$status, 303L)
})

test_that("one registration can retain distinct resource targets on its shared route", {
  f <- router_fixture(same_registration = TRUE)
  expect_identical(f$manager$targets$a$client, f$manager$targets$b$client)
  expect_false(identical(f$manager$targets$a$fingerprint, f$manager$targets$b$fingerprint))
  authorizations <- lapply(c("a", "b"), function(id) router_prepare(f, id))
  for (auth in rev(authorizations)) {
    expect_identical(names(connection_router_select(f$manager, f$clients, list(state = auth$state))),
      paste0("health-", auth$context$target))
    expect_identical(f$ui(router_request(f, auth))$status, 303L)
  }
  f$controller$disconnect_all(revoke = FALSE)
  expect_length(f$manager$state$routes, 0L)
  expect_length(f$manager$state$pending, 0L)
})
