make_form_post_req <- function(
  path = "/",
  query = "",
  body = "",
  content_type = "application/x-www-form-urlencoded"
) {
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "POST"
  req$PATH_INFO <- path
  req$QUERY_STRING <- query
  req$CONTENT_TYPE <- content_type
  req$CONTENT_LENGTH <- as.character(nchar(body, type = "bytes"))
  req$rook.input <- list(read = function(n) charToRaw(body))
  req
}

form_post_query <- function(handle, id = "auth") {
  paste0(
    "?",
    httr2::url_query_build(stats::setNames(
      list(handle, id),
      c("shinyOAuth_form_post", "shinyOAuth_form_post_id")
    ))
  )
}

count_referrer_meta <- function(html) {
  matches <- gregexpr(
    '<meta[^>]+name="referrer"[^>]+content="no-referrer"',
    html,
    perl = TRUE
  )[[1]]

  if (length(matches) == 1L && identical(matches[[1]], -1L)) {
    return(0L)
  }

  length(matches)
}

get_ui_dependency_names <- function(ui) {
  vapply(
    htmltools::resolveDependencies(htmltools::findDependencies(ui)),
    `[[`,
    "",
    "name"
  )
}

test_that("oauth_form_post_ui stores POST callback and redirects with handle", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  decoded_state <- shiny::parseQueryString(paste0("?state=", enc_state))$state

  req <- make_form_post_req(
    body = paste0("code=ok&state=", enc_state, "&iss=https%3A%2F%2Fissuer")
  )
  resp <- ui(req)

  expect_identical(resp$status, 303L)
  expect_match(resp$headers$Location, "shinyOAuth_form_post=")
  expect_match(resp$headers$Location, "shinyOAuth_form_post_id=auth")
  expect_false(grepl("code=ok", resp$headers$Location, fixed = TRUE))
  expect_false(grepl(
    "state=",
    sub("shinyOAuth_form_post=[^&]+", "", resp$headers$Location)
  ))

  handle <- parse_query_param(
    resp$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )
  payload <- shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle)
  expect_identical(payload$type, "code")
  expect_identical(payload$code, "ok")
  expect_identical(payload$state, decoded_state)
  expect_identical(payload$iss, "https://issuer")
})

test_that("oauth_form_post_ui rejects scheme-relative callback paths", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  expect_error(
    oauth_form_post_ui(
      shiny::fluidPage(),
      id = "auth",
      client = cli,
      callback_path = "//evil.example/callback"
    ),
    class = "shinyOAuth_input_error",
    regexp = "must not start"
  )

  expect_error(
    shinyOAuth:::normalize_oauth_form_post_callback_path(
      "//evil.example/callback"
    ),
    class = "shinyOAuth_input_error",
    regexp = "must not start"
  )
})

test_that("oauth_form_post_ui consumes state before issuing a callback handle", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  body <- paste0("code=ok&state=", enc_state)

  first <- ui(make_form_post_req(body = body))
  expect_identical(first$status, 303L)

  second <- ui(make_form_post_req(body = body))
  expect_identical(second$status, 400L)
  expect_identical(
    second$content,
    "OAuth form_post callback could not be processed."
  )

  keys <- cli@state_store$keys()
  expect_length(keys, 1L)
  expect_true(startsWith(keys[[1]], "formpost"))

  handle <- parse_query_param(
    first$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )
  payload <- shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle)
  expect_identical(payload$type, "code")
  expect_identical(payload$code, "ok")
  expect_true(is.list(payload$state_payload))
  expect_true(is.list(payload$state_store_values))
  expect_length(cli@state_store$keys(), 0L)
})

test_that("oauth_form_post_store_take verifies fallback handle removal", {
  withr::local_options(list(shinyOAuth.allow_non_atomic_state_store = TRUE))

  backing <- new.env(parent = emptyenv())
  store <- custom_cache(
    get = function(key, missing = NULL) {
      if (exists(key, envir = backing, inherits = FALSE)) {
        return(get(key, envir = backing, inherits = FALSE))
      }
      missing
    },
    set = function(key, value) assign(key, value, envir = backing),
    remove = function(key) TRUE
  )
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@state_store <- store

  handle <- shinyOAuth:::oauth_form_post_store_set(
    cli,
    "auth",
    list(code = "ok", state = "state")
  )

  expect_error(
    shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle),
    class = "shinyOAuth_state_error",
    regexp = "Failed to remove form_post callback handle"
  )
})

test_that("oauth_form_post_store_take rejects expired handles", {
  backing <- new.env(parent = emptyenv())
  store <- custom_cache(
    get = function(key, missing = NULL) {
      if (exists(key, envir = backing, inherits = FALSE)) {
        return(get(key, envir = backing, inherits = FALSE))
      }
      missing
    },
    set = function(key, value) assign(key, value, envir = backing),
    remove = function(key) {
      if (exists(key, envir = backing, inherits = FALSE)) {
        rm(list = key, envir = backing)
      }
      TRUE
    },
    take = function(key, missing = NULL) {
      if (!exists(key, envir = backing, inherits = FALSE)) {
        return(missing)
      }
      value <- get(key, envir = backing, inherits = FALSE)
      rm(list = key, envir = backing)
      value
    },
    info = function() list(max_age = 3600)
  )
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@state_store <- store
  cli@state_payload_max_age <- 1

  handle <- shinyOAuth:::oauth_form_post_store_set(
    cli,
    "auth",
    list(code = "ok", state = "state")
  )
  key <- ls(backing)[[1]]
  payload <- get(key, envir = backing, inherits = FALSE)
  payload$stored_at <- as.numeric(Sys.time()) - 10
  assign(key, payload, envir = backing)

  expect_error(
    shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle),
    class = "shinyOAuth_state_error",
    regexp = "form_post callback handle expired"
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(cli, "auth", handle),
    class = "shinyOAuth_state_error",
    regexp = "missing or already consumed"
  )
})

test_that("oauth_form_post_ui rejects invalid callback POST bodies", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")

  bad_type <- ui(make_form_post_req(
    body = paste0("code=ok&state=", enc_state),
    content_type = "application/json"
  ))
  expect_identical(bad_type$status, 415L)
  expect_match(bad_type$content, "application/x-www-form-urlencoded")
  form_post_reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_validation_failed") &&
        identical(e$phase, "form_post_request_validation")
    },
    events
  )
  expect_length(form_post_reject_events, 1L)

  duplicate <- ui(make_form_post_req(
    body = paste0("code=ok&code=again&state=", enc_state)
  ))
  expect_identical(duplicate$status, 400L)

  missing_state <- ui(make_form_post_req(body = "code=ok"))
  expect_identical(missing_state$status, 400L)

  invalid_state <- ui(make_form_post_req(
    body = "code=ok&state=definitely-not-a-valid-state"
  ))
  expect_identical(invalid_state$status, 400L)
  expect_identical(
    invalid_state$content,
    "OAuth form_post callback could not be processed."
  )
  expect_false(grepl(
    "definitely-not-a-valid-state",
    invalid_state$content,
    fixed = TRUE
  ))
})

test_that("oauth_form_post_ui audits issuer failures at the POST boundary", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  cli@enforce_callback_issuer <- TRUE
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  keys_before <- sort(cli@state_store$keys())

  resp <- ui(make_form_post_req(
    body = paste0(
      "code=ok&state=",
      enc_state,
      "&iss=https%3A%2F%2Fattacker.example"
    )
  ))

  expect_identical(resp$status, 400L)
  expect_identical(sort(cli@state_store$keys()), keys_before)

  event_types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true("audit_callback_iss_mismatch" %in% event_types)
})

test_that("oauth_form_post_ui rejects oversized callback query before storing", {
  withr::local_options(list(shinyOAuth.callback_max_query_bytes = 64))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  keys_before <- sort(cli@state_store$keys())

  resp <- ui(make_form_post_req(
    query = paste0("pad=", strrep("x", 80)),
    body = paste0("code=ok&state=", enc_state)
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    "OAuth form_post callback could not be processed."
  )
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(cli@state_store$keys()), keys_before)
})

test_that("oauth_form_post_ui rejects oversized callback bodies before storing", {
  withr::local_options(list(shinyOAuth.callback_max_form_post_body_bytes = 64))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  keys_before <- sort(cli@state_store$keys())

  resp <- ui(make_form_post_req(
    body = paste0("code=ok&state=", enc_state, "&pad=", strrep("x", 80))
  ))

  expect_identical(resp$status, 413L)
  expect_match(resp$content, "body exceeded maximum length", fixed = TRUE)
  expect_false("Location" %in% names(resp$headers))
  expect_identical(sort(cli@state_store$keys()), keys_before)
})

test_that("oauth_form_post_ui rejects unsafe body read limits", {
  withr::local_options(list(
    shinyOAuth.callback_max_form_post_body_bytes = .Machine$integer.max
  ))

  limits <- shinyOAuth:::oauth_callback_limits()
  expect_lt(limits$form_post_body, .Machine$integer.max - 1L)

  expect_error(
    shinyOAuth:::oauth_form_post_read_body(
      make_form_post_req(body = "code=ok"),
      .Machine$integer.max
    ),
    class = "shinyOAuth_form_post_http_error",
    regexp = "body limit is invalid"
  )
})

test_that("oauth_form_post_ui hides internal callback POST failures", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  url <- prepare_call(cli, browser_token = valid_browser_token())
  enc_state <- parse_query_param(url, "state")
  stored_keys <- cli@state_store$keys()
  backing <- new.env(parent = emptyenv())
  for (key in stored_keys) {
    assign(
      key,
      cli@state_store$get(key, missing = NULL),
      envir = backing
    )
  }

  cli@state_store <- custom_cache(
    get = function(key, missing = NULL) {
      if (exists(key, envir = backing, inherits = FALSE)) {
        return(get(key, envir = backing, inherits = FALSE))
      }
      missing
    },
    set = function(key, value) stop("backend-secret-detail", call. = FALSE),
    remove = function(key) {
      if (exists(key, envir = backing, inherits = FALSE)) {
        rm(list = key, envir = backing)
      }
      TRUE
    },
    take = function(key, missing = NULL) {
      if (!exists(key, envir = backing, inherits = FALSE)) {
        return(missing)
      }
      value <- get(key, envir = backing, inherits = FALSE)
      rm(list = key, envir = backing)
      value
    }
  )
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)

  resp <- ui(make_form_post_req(
    body = paste0("code=ok&state=", enc_state)
  ))

  expect_identical(resp$status, 400L)
  expect_identical(
    resp$content,
    "OAuth form_post callback could not be processed."
  )
  expect_false(grepl("backend-secret-detail", resp$content, fixed = TRUE))
})

test_that("oauth_form_post_ui injects shinyOAuth dependency for GET UIs", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "GET"

  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)
  rendered_ui <- ui(req)
  rt <- htmltools::renderTags(rendered_ui)
  deps <- get_ui_dependency_names(rendered_ui)

  expect_identical(sum(deps == "shinyOAuth"), 1L)
  expect_identical(count_referrer_meta(rt$head), 1L)
})

test_that("oauth_form_post_ui does not duplicate existing helper output", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  req <- new.env(parent = emptyenv())
  req$REQUEST_METHOD <- "GET"

  ui <- oauth_form_post_ui(
    function(req) {
      shiny::fluidPage(
        use_shinyOAuth(),
        shiny::uiOutput("login")
      )
    },
    id = "auth",
    client = cli
  )
  rendered_ui <- ui(req)
  rt <- htmltools::renderTags(rendered_ui)
  deps <- get_ui_dependency_names(rendered_ui)

  expect_identical(sum(deps == "shinyOAuth"), 1L)
  expect_identical(count_referrer_meta(rt$head), 1L)
})

test_that("oauth_module_server consumes form_post callback handles", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(code = "ok", state = decoded_state)
      )

      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          testthat::expect_identical(code, "ok")
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(form_post_query(handle, "auth"))
          session$flushReact()
          values$token
        }
      )

      expect_false(is.null(token))
      expect_true(isTRUE(values$authenticated))
      expect_null(values$error)
    }
  )
})

test_that("oauth_module_server consumes form_post error callbacks", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(
          error = "access_denied",
          error_description = "Denied",
          state = decoded_state
        )
      )

      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()

      expect_identical(values$error, "access_denied")
      expect_identical(values$error_description, "Denied")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("oauth_module_server audits preconsumed form_post error state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  url <- prepare_call(cli, browser_token = NULL)
  enc_state <- parse_query_param(url, "state")
  resp <- ui(make_form_post_req(
    body = paste0("error=access_denied&state=", enc_state)
  ))
  handle <- parse_query_param(
    resp$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()

      expect_identical(values$error, "access_denied")
    }
  )

  event_types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true("audit_error_state_consumed" %in% event_types)
})

test_that("oauth_module_server audits form_post handles missing module ids", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query("?shinyOAuth_form_post=handle")
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "missing module id")
      expect_false(isTRUE(values$authenticated))
    }
  )

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_query_rejected") &&
        identical(e$reason, "missing_form_post_id")
    },
    events
  )
  expect_length(reject_events, 1L)
})

test_that("oauth_module_server rejects unknown form_post module ids", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  seen <- character(0)
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    seen <<- c(seen, type)
    orig(type, message)
  }

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    session = sess,
    expr = {
      session$flushReact()
      seen <<- character(0)

      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(code = "ok", state = decoded_state)
      )

      values$.process_query(form_post_query(handle, "wrong"))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "unknown module id")
      expect_true(any(seen == "shinyOAuth:clearQueryAndFixTitle"))
      expect_false(isTRUE(values$authenticated))
    }
  )

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_query_rejected") &&
        identical(e$reason, "unknown_form_post_id")
    },
    events
  )
  expect_length(reject_events, 1L)
})

test_that("oauth_module_server rejects form_post handles mixed with direct callback params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(code = "ok", state = decoded_state)
      )

      values$.process_query(paste0(
        form_post_query(handle, "auth"),
        "&code=ok&state=",
        utils::URLencode(enc_state, reserved = TRUE)
      ))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "must not be combined")
      expect_false(isTRUE(values$authenticated))
    }
  )

  reject_events <- Filter(
    function(e) {
      identical(e$type, "audit_callback_query_rejected") &&
        identical(e$reason, "mixed_form_post_and_direct_callback_params")
    },
    events
  )
  expect_length(reject_events, 1L)
})

test_that("oauth_module_server rejects duplicate form_post handle query params", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(
          error = "access_denied",
          error_description = "Denied",
          state = decoded_state
        )
      )

      values$.process_query(paste0(
        "?shinyOAuth_form_post=bad",
        "&shinyOAuth_form_post=",
        utils::URLencode(handle, reserved = TRUE),
        "&shinyOAuth_form_post_id=auth"
      ))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "duplicate OAuth parameter")
      expect_false(isTRUE(values$authenticated))

      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()

      expect_identical(values$error, "access_denied")
      expect_identical(values$error_description, "Denied")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("callback query duplicate rejection covers direct OAuth params", {
  expect_error(
    shinyOAuth:::reject_duplicate_oauth_module_callback_query("?code=a&code=b"),
    class = "shinyOAuth_state_error",
    regexp = "duplicate OAuth parameter: code"
  )
  expect_error(
    shinyOAuth:::reject_duplicate_oauth_module_callback_query(
      "?state=a&foo=1&state=b"
    ),
    class = "shinyOAuth_state_error",
    regexp = "duplicate OAuth parameter: state"
  )
  expect_silent(
    shinyOAuth:::reject_duplicate_oauth_module_callback_query("?foo=1&foo=2")
  )
})

test_that("oauth_module_server rejects oversized form_post handle query params", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.callback_max_form_post_handle_bytes = 8
  ))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query(form_post_query(strrep("h", 9), "auth"))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "shinyOAuth_form_post")
      expect_match(values$error_description, "exceeded maximum length")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("oauth_module_server rejects oversized form_post module id query params", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.callback_max_form_post_id_bytes = 8
  ))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query(form_post_query("handle", strrep("m", 9)))
      session$flushReact()

      expect_identical(values$error, "invalid_callback_query")
      expect_match(values$error_description, "shinyOAuth_form_post_id")
      expect_match(values$error_description, "exceeded maximum length")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("oauth_module_server rejects missing form_post handles", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query(form_post_query("missing-handle", "auth"))
      session$flushReact()

      expect_identical(values$error, "invalid_state")
      expect_match(values$error_description, "missing or already consumed")
      expect_false(isTRUE(values$authenticated))
    }
  )
})

test_that("oauth_module_server rejects replayed form_post handles", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc_state <- parse_query_param(url, "state")
      decoded_state <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state
      ))$state
      handle <- shinyOAuth:::oauth_form_post_store_set(
        cli,
        "auth",
        list(
          error = "access_denied",
          error_description = "Denied",
          state = decoded_state
        )
      )

      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()
      expect_identical(values$error, "access_denied")

      values$.process_query(form_post_query(handle, "auth"))
      session$flushReact()

      expect_identical(values$error, "invalid_state")
      expect_match(values$error_description, "missing or already consumed")
      expect_false(isTRUE(values$authenticated))

      lookup_events <- Filter(
        function(e) {
          identical(e$type, "audit_callback_validation_failed") &&
            identical(e$phase, "form_post_callback_lookup")
        },
        events
      )
      expect_length(lookup_events, 1L)
      expect_true(is.character(lookup_events[[1L]]$handle_digest))
    }
  )
})

test_that("form_post handles are ignored until the owning module claims them", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli_a <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli_b <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  seen <- character(0)
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    seen <<- c(seen, type)
    orig(type, message)
  }

  wrapper_server <- function(input, output, session) {
    auth_a <- oauth_module_server(
      "auth_a",
      cli_a,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
    auth_b <- oauth_module_server(
      "auth_b",
      cli_b,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    )
  }

  shiny::testServer(
    app = wrapper_server,
    session = sess,
    expr = {
      session$flushReact()
      seen <<- character(0)

      url_b <- auth_b$build_auth_url()
      enc_state_b <- parse_query_param(url_b, "state")
      decoded_state_b <- shiny::parseQueryString(paste0(
        "?state=",
        enc_state_b
      ))$state
      handle_b <- shinyOAuth:::oauth_form_post_store_set(
        cli_b,
        "auth_b",
        list(
          error = "access_denied",
          error_description = "Denied",
          state = decoded_state_b
        )
      )

      auth_a$.process_query(form_post_query(handle_b, "auth_b"))
      session$flushReact()

      expect_null(auth_a$error)
      expect_false(any(seen == "shinyOAuth:clearQueryAndFixTitle"))

      auth_b$.process_query(form_post_query(handle_b, "auth_b"))
      session$flushReact()

      expect_identical(auth_b$error, "access_denied")
      expect_identical(auth_b$error_description, "Denied")
      expect_true(any(seen == "shinyOAuth:clearQueryAndFixTitle"))
      expect_false(isTRUE(auth_b$authenticated))
    }
  )
})

test_that("form_post bridge does not duplicate callback validation success audits", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1L]] <<- e
  })
  on.exit(options(old), add = TRUE)

  ui <- oauth_form_post_ui(shiny::fluidPage(), id = "auth", client = cli)
  browser_token <- valid_browser_token()
  url <- prepare_call(cli, browser_token = browser_token)
  enc_state <- parse_query_param(url, "state")

  resp <- ui(make_form_post_req(
    body = paste0("code=ok&state=", enc_state)
  ))
  handle <- parse_query_param(
    resp$headers$Location,
    "shinyOAuth_form_post",
    decode = TRUE
  )

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      values$browser_token <- browser_token

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(form_post_query(handle, "auth"))
          session$flushReact()
        }
      )
    }
  )

  event_types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_identical(sum(event_types == "audit_callback_validation_success"), 1L)
})
