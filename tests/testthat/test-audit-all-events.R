testthat::test_that("every audit event fires and serializes to JSON", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Capture all audit events emitted during this test
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  # Helper: extract unique audit types from captured events
  audit_types <- function(ev) {
    unique(vapply(ev, function(x) as.character(x$type), character(1)))
  }

  # Build a baseline client we can reuse across flows
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # 1) prepare_call -> audit_redirect_issued ---------------------------------
  {
    btok <- valid_browser_token()
    url <- prepare_call(cli, browser_token = btok)
    testthat::expect_true(is.character(url) && nzchar(url))
  }

  # 2) handle_callback: browser token mismatch -> audit_callback_validation_failed
  {
    btok <- valid_browser_token()
    enc <- parse_query_param(prepare_call(cli, browser_token = btok), "state")
    bad_btok <- sub("^..", "ff", btok) # keep valid shape; mismatch ensures state error path
    testthat::expect_error(
      handle_callback(
        cli,
        code = "c1",
        payload = enc,
        browser_token = bad_btok
      ),
      class = "shinyOAuth_state_error"
    )
  }

  # 3) handle_callback: success path -> callback_received/validation_success/token_exchange/login_success
  {
    btok <- valid_browser_token()
    enc <- parse_query_param(prepare_call(cli, browser_token = btok), "state")
    tok <- testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(access_token = "t", expires_in = 3600)
      },
      .package = "shinyOAuth",
      {
        handle_callback(cli, code = "ok", payload = enc, browser_token = btok)
      }
    )
    testthat::expect_s3_class(tok, "S7_object")
    testthat::expect_true(S7::S7_inherits(tok, OAuthToken))
  }

  # 4) Module-level failures: token_exchange_error + audit_login_failed -------
  {
    # Seed a fresh state produced with the same client
    btok <- "__SKIPPED__" # honored when shinyOAuth.skip_browser_token = TRUE
    enc <- parse_query_param(prepare_call(cli, browser_token = btok), "state")

    # Call `use_shinyOAuth()` to silence warning
    ui <- shiny::fluidPage(
      use_shinyOAuth()
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
        testthat::with_mocked_bindings(
          swap_code_for_token_set = function(client, code, code_verifier) {
            rlang::abort("boom")
          },
          .package = "shinyOAuth",
          {
            values$.process_query(paste0("?code=bad&state=", enc))
            session$flushReact()
          }
        )
      }
    )
  }

  # 5) Browser cookie observers: invalid_browser_token + browser_cookie_error -
  {
    shiny::testServer(
      app = oauth_module_server,
      args = list(
        id = "auth2",
        client = cli,
        auto_redirect = FALSE,
        indefinite_session = TRUE
      ),
      expr = {
        # Simulate an invalid cookie value -> triggers audit_invalid_browser_token
        session$setInputs(shinyOAuth_sid = "abc")
        session$flushReact()
        # Simulate a browser cookie/webcrypto error -> triggers audit_browser_cookie_error
        session$setInputs(shinyOAuth_cookie_error = "webcrypto_unavailable")
        session$flushReact()
      }
    )
  }

  # 6) Session lifecycle: session_cleared + logout ----------------------------
  {
    shiny::testServer(
      app = oauth_module_server,
      args = list(
        id = "auth3",
        client = cli,
        auto_redirect = FALSE,
        indefinite_session = FALSE
      ),
      expr = {
        # Seed an already-expired token to trigger audit_session_cleared
        t <- OAuthToken(
          access_token = "x",
          refresh_token = NA_character_,
          expires_at = as.numeric(Sys.time()) - 1,
          id_token = NA_character_
        )
        values$token <- t
        session$flushReact()
        # Also call logout to get audit_logout
        values$logout()
      }
    )
  }

  # 7) State failures: audit_state_parse_failure ------------------------------
  {
    key <- paste(rep("k", 40), collapse = "")
    testthat::expect_error(
      state_decrypt_gcm("***", key = key),
      class = "shinyOAuth_state_error"
    )
  }

  # 8) Token/userinfo paths: audit_token_refresh + audit_userinfo -------------
  {
    # Create a provider with a userinfo URL
    prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
    prov@userinfo_url <- "https://example.com/userinfo"
    cli2 <- oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0),
      state_store = cachem::cache_mem(max_age = 600),
      state_entropy = 64,
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    )

    # Stub HTTP to avoid network and drive both code paths deterministically
    testthat::local_mocked_bindings(
      req_with_retry = function(req) {
        # Return success responses; body content depends on URL
        url <- req$url %||% ""
        if (grepl("/token", url, fixed = TRUE)) {
          httr2::response(
            url = url,
            status = 200,
            headers = list("content-type" = "application/json"),
            body = charToRaw('{"access_token":"new","expires_in":3600}')
          )
        } else if (grepl("/userinfo", url, fixed = TRUE)) {
          httr2::response(
            url = url,
            status = 200,
            headers = list("content-type" = "application/json"),
            body = charToRaw('{"sub":"u1"}')
          )
        } else {
          httr2::response(
            url = url,
            status = 200,
            headers = list("content-type" = "application/json"),
            body = charToRaw('{"ok":true}')
          )
        }
      },
      .package = "shinyOAuth"
    )

    # Call get_userinfo() directly -> audit_userinfo
    ui <- get_userinfo(cli2, token = "at")
    testthat::expect_true(is.list(ui))

    # Call refresh_token() -> audit_token_refresh
    t <- OAuthToken(
      access_token = "old",
      refresh_token = "rt",
      expires_at = as.numeric(Sys.time()) + 60,
      id_token = NA_character_
    )
    t2 <- refresh_token(cli2, t, async = FALSE, introspect = FALSE)
    testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  }

  # Validate that every captured event can be serialized to JSON ---------------
  for (ev in events) {
    j <- jsonlite::toJSON(ev, auto_unbox = TRUE, null = "null")
    testthat::expect_true(nchar(as.character(j)) > 0)
  }

  # Compute the set of types we expect to have seen
  # Consider only audit_* events (the audit hook also receives error traces)
  seen <- grep("^audit_", audit_types(events), value = TRUE)

  expected <- c(
    "audit_redirect_issued",
    "audit_callback_received",
    "audit_callback_validation_success",
    "audit_callback_validation_failed",
    "audit_token_exchange",
    "audit_token_exchange_error",
    "audit_login_success",
    "audit_login_failed",
    "audit_logout",
    "audit_session_cleared",
    "audit_refresh_failed_but_kept_session", # may not be seen in this run; don't strictly require
    "audit_browser_cookie_error",
    "audit_session_started",
    "audit_invalid_browser_token",
    "audit_state_parse_failure",
    "audit_token_refresh",
    "audit_userinfo"
  )

  # We may not deterministically hit refresh_failed_but_kept_session in this test,
  # so treat it as optional for presence but ensure all other ones are seen.
  required <- setdiff(expected, "audit_refresh_failed_but_kept_session")
  testthat::expect_true(all(required %in% seen))

  # Ensure documentation lists all events we actually emit ---------------------
  # Locate the audit-logging vignette in source or built locations
  cand <- c(
    file.path("vignettes", "audit-logging.Rmd"),
    file.path("doc", "audit-logging.Rmd"),
    system.file("doc", "audit-logging.Rmd", package = "shinyOAuth"),
    # Also try resolving relative to the tests directory in case wd differs
    testthat::test_path("..", "..", "vignettes", "audit-logging.Rmd")
  )
  cand <- cand[file.exists(cand) & nzchar(cand)]
  testthat::expect_true(
    length(cand) >= 1,
    info = "Could not locate audit-logging.Rmd"
  )
  doc_types <- character()
  for (p in cand) {
    rmd <- try(readLines(p), silent = TRUE)
    if (!inherits(rmd, "try-error")) {
      # Extract any backticked audit event names regardless of surrounding text
      lines <- grep("`audit_[a-z0-9_]+`", rmd, value = TRUE)
      cur <- unique(gsub(
        ".*`(audit_[a-z0-9_]+)`.*",
        "\\1",
        lines
      ))
      doc_types <- unique(c(doc_types, cur))
    }
  }
  # All seen event types must be documented
  missing_in_doc <- setdiff(seen, doc_types)
  testthat::expect(
    length(missing_in_doc) == 0,
    paste(
      "Missing in audit-logging.Rmd:",
      paste(missing_in_doc, collapse = ", ")
    )
  )
})
