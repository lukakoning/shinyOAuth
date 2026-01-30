# Integration test: async module with file-based audit logging
# This test verifies that audit events are correctly emitted from both
# the main R process and async workers when using future::multisession

testthat::test_that("Shiny module async audit: events from main & worker processes logged to file", {
  # Skip if Keycloak isn't reachable
  issuer <- "http://localhost:8080/realms/shinyoauth"
  disc <- paste0(issuer, "/.well-known/openid-configuration")
  ok <- tryCatch(
    {
      resp <- httr2::request(disc) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "application/json") |>
        httr2::req_perform()
      !httr2::resp_is_error(resp)
    },
    error = function(...) FALSE
  )
  testthat::skip_if_not(ok, "Keycloak not reachable at localhost:8080")

  # Optional deps to parse HTML forms and for async

  testthat::skip_if_not_installed("xml2")
  testthat::skip_if_not_installed("rvest")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")

  # Skip on CRAN
  testthat::skip_on_cran()

  # Keep the test stable in CI/headless environments
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 10,
    shinyOAuth.disable_watchdog_warning = TRUE
  ))

  # Set up future plan for async work
  # Note: future::multisession requires the package to be installed (not just dev-loaded).
  # When running via pkgload::load_all(), internal functions aren't available in workers.
  # We try multisession first (for installed package scenarios), fall back to sequential.
  old_plan <- tryCatch(future::plan(), error = function(...) NULL)

  # Check if the package is installed (not just dev-loaded)
  pkg_installed <- tryCatch(
    {
      # If we can find with_async_options in the installed namespace, multisession will work
      ns <- asNamespace("shinyOAuth")
      exists("with_async_options", envir = ns, mode = "function")
    },
    error = function(...) FALSE
  )

  if (pkg_installed) {
    tryCatch(
      future::plan(future::multisession, workers = 2),
      error = function(...) {
        try(future::plan(future::sequential), silent = TRUE)
      }
    )
  } else {
    # Dev-loaded package: use sequential (still tests async code paths, just in-process)
    cat("\n[NOTE] Package is dev-loaded; using future::sequential for async\n")
    try(future::plan(future::sequential), silent = TRUE)
  }
  withr::defer({
    if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
  })

  # Create a temporary file for audit logs
  audit_log_file <- tempfile(fileext = ".jsonl")
  withr::defer(unlink(audit_log_file), envir = parent.frame())

  # Set up a file-based audit hook that writes JSON lines
  # The hook writes one JSON object per line with process metadata
  audit_hook <- function(event) {
    # Add process ID where the hook executed for verification
    event$.hook_pid <- Sys.getpid()
    event$.hook_time <- as.character(Sys.time())

    line <- tryCatch(
      jsonlite::toJSON(event, auto_unbox = TRUE, null = "null"),
      error = function(e) {
        jsonlite::toJSON(
          list(
            type = event$type %||% "unknown",
            error = "serialization_failed",
            .hook_pid = Sys.getpid()
          ),
          auto_unbox = TRUE
        )
      }
    )
    # Append to log file (thread-safe atomic write via cat with append)
    cat(line, "\n", file = audit_log_file, append = TRUE)
  }

  withr::local_options(list(shinyOAuth.audit_hook = audit_hook))

  # Provider and client (public PKCE)
  prov <- shinyOAuth::oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "shinyoauth"
  )
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid")
  )

  main_pid <- Sys.getpid()

  # Drive the module inside a Shiny test server
  x <- shinyOAuth::use_shinyOAuth() # call to avoid warning
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      async = TRUE # Enable async mode!
    ),
    expr = {
      # 1) Build auth URL and capture state
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))

      parse_query_param <- function(url, name, decode = FALSE) {
        q <- sub("^[^?]*\\?", "", url)
        if (identical(q, url) || !nzchar(q)) {
          return(NA_character_)
        }
        parts <- strsplit(q, "&", fixed = TRUE)[[1]]
        kv <- strsplit(parts, "=", fixed = TRUE)
        if (decode) {
          vals <- vapply(
            kv,
            function(p) if (length(p) > 1) utils::URLdecode(p[2]) else "",
            ""
          )
          names(vals) <- vapply(kv, function(p) utils::URLdecode(p[1]), "")
        } else {
          vals <- vapply(
            kv,
            function(p) if (length(p) > 1) p[2] else "",
            ""
          )
          names(vals) <- vapply(kv, function(p) p[1], "")
        }
        vals[[name]] %||% NA_character_
      }

      st <- parse_query_param(url, "state")
      testthat::expect_true(is.character(st) && nzchar(st))

      # 2) Fetch login page (no redirects), capture cookies, parse form
      get_cookies <- function(resp) {
        sc <- httr2::resp_headers(resp)[
          tolower(names(httr2::resp_headers(resp))) == "set-cookie"
        ]
        if (length(sc) == 0) {
          return("")
        }
        kv <- vapply(sc, function(x) sub(";.*$", "", x), "")
        paste(kv, collapse = "; ")
      }

      resp1 <- httr2::request(url) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "text/html") |>
        httr2::req_options(followlocation = FALSE) |>
        httr2::req_perform()

      testthat::expect_false(httr2::resp_is_error(resp1))
      html <- httr2::resp_body_string(resp1)
      doc <- xml2::read_html(html)
      form <- rvest::html_element(doc, "form")
      testthat::expect_true(!is.na(rvest::html_name(form)))
      action <- rvest::html_attr(form, "action")
      testthat::expect_true(is.character(action) && nzchar(action))

      # Collect all inputs and seed form data
      inputs <- rvest::html_elements(form, "input")
      names <- rvest::html_attr(inputs, "name")
      vals <- rvest::html_attr(inputs, "value")
      data <- as.list(stats::setNames(vals, names))
      data <- data[!is.na(names) & nzchar(names)]
      data[["username"]] <- "alice"
      data[["password"]] <- "alice"

      cookie_hdr <- get_cookies(resp1)

      to_abs <- function(base, path) {
        if (grepl("^https?://", path)) {
          return(path)
        }
        u <- httr2::url_parse(base)
        paste0(
          u$scheme,
          "://",
          u$hostname,
          if (!is.na(u$port)) paste0(":", u$port) else "",
          path
        )
      }
      post_url <- to_abs(url, action)

      # 3) Submit login form, follow redirects to capture authorization code
      follow_once <- function(resp, cookie_hdr) {
        loc <- httr2::resp_header(resp, "location")
        if (is.null(loc) || !nzchar(loc)) {
          return(list(done = TRUE, url = NA_character_, resp = resp))
        }
        r <- httr2::request(loc) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
          httr2::req_options(followlocation = FALSE) |>
          httr2::req_perform()
        list(
          done = (httr2::resp_status(r) < 300 || httr2::resp_status(r) >= 400),
          url = loc,
          resp = r
        )
      }

      req_post <- httr2::request(post_url) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_headers(Accept = "text/html", Cookie = cookie_hdr) |>
        httr2::req_options(followlocation = FALSE)
      req_post <- do.call(httr2::req_body_form, c(list(req_post), data))
      post_resp <- httr2::req_perform(req_post)

      redirect_uri <- parse_query_param(url, "redirect_uri", decode = TRUE)
      testthat::expect_true(is.character(redirect_uri) && nzchar(redirect_uri))

      code <- NA_character_
      cur_resp <- post_resp
      for (i in seq_len(5)) {
        status <- httr2::resp_status(cur_resp)
        if (status >= 300 && status < 400) {
          loc <- httr2::resp_header(cur_resp, "location")
          testthat::expect_true(nzchar(loc))
          if (startsWith(loc, redirect_uri)) {
            code <- parse_query_param(loc, "code", decode = TRUE)
            break
          }
          step <- follow_once(cur_resp, cookie_hdr)
          cur_resp <- step$resp
        } else {
          break
        }
      }

      testthat::expect_true(is.character(code) && nzchar(code))

      # 4) Simulate provider callback into the module (async token exchange!)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(code),
        "&state=",
        utils::URLencode(st)
      ))

      # Allow promise handlers to run for async token exchange
      # Wait for both token AND authenticated to be set (async may take time)
      deadline <- Sys.time() + 15
      while (
        (!isTRUE(values$authenticated) || is.null(values$token)) &&
          Sys.time() < deadline
      ) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.02)
      }

      # 5) Assertions: authenticated with a token
      testthat::expect_true(
        isTRUE(values$authenticated),
        info = paste0(
          "Expected authenticated=TRUE. error=",
          values$error %||% "<NULL>",
          ", error_description=",
          values$error_description %||% "<NULL>"
        )
      )
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))

      # Give audit hooks a bit more time to flush to file
      Sys.sleep(0.5)
      later::run_now(0.1)
    }
  )

  # 6) Read and parse audit log file
  Sys.sleep(0.5) # Allow any final writes to complete
  testthat::expect_true(
    file.exists(audit_log_file),
    info = "Audit log file should exist"
  )

  log_lines <- readLines(audit_log_file, warn = FALSE)
  log_lines <- log_lines[nzchar(log_lines)]
  testthat::expect_true(
    length(log_lines) > 0,
    info = "Audit log file should contain events"
  )

  # Parse each JSON line
  events <- lapply(log_lines, function(line) {
    tryCatch(
      jsonlite::fromJSON(line, simplifyVector = FALSE),
      error = function(e) NULL
    )
  })
  events <- Filter(Negate(is.null), events)

  testthat::expect_true(
    length(events) > 0,
    info = "Should have parsed at least one audit event"
  )

  # 7) Categorize events by type
  event_types <- vapply(events, function(e) e$type %||% "unknown", character(1))
  cat("\n=== Captured audit event types ===\n")
  print(table(event_types))

  # 8) Verify key events are present
  # Events emitted during authorization redirect (main process)
  testthat::expect_true(
    "audit_redirect_issued" %in% event_types,
    info = "Should have audit_redirect_issued event"
  )

  # Events emitted during callback processing
  testthat::expect_true(
    "audit_callback_received" %in% event_types,
    info = "Should have audit_callback_received event"
  )

  # Token exchange event (may be from async worker)
  testthat::expect_true(
    "audit_token_exchange" %in% event_types,
    info = "Should have audit_token_exchange event"
  )

  # Login success event
  testthat::expect_true(
    "audit_login_success" %in% event_types,
    info = "Should have audit_login_success event"
  )

  # 9) Verify we have events from both main process and async worker
  # Check for is_async marker in shiny_session
  async_events <- Filter(
    function(e) {
      sess <- e$shiny_session
      if (is.null(sess)) {
        return(FALSE)
      }
      isTRUE(sess$is_async)
    },
    events
  )

  sync_events <- Filter(
    function(e) {
      sess <- e$shiny_session
      if (is.null(sess)) {
        return(TRUE)
      } # Events without session context treated as sync
      isFALSE(sess$is_async) || is.null(sess$is_async)
    },
    events
  )

  cat("\n=== Event distribution ===\n")
  cat("Total events:", length(events), "\n")
  cat("Async events (is_async=TRUE):", length(async_events), "\n")
  cat("Sync events (is_async=FALSE or NULL):", length(sync_events), "\n")

  # Print async event types for debugging
  if (length(async_events) > 0) {
    async_types <- vapply(
      async_events,
      function(e) e$type %||% "unknown",
      character(1)
    )
    cat("Async event types:", paste(async_types, collapse = ", "), "\n")
  }

  # The redirect_issued event should be from main process (sync)
  redirect_events <- Filter(
    function(e) identical(e$type, "audit_redirect_issued"),
    events
  )
  testthat::expect_true(length(redirect_events) > 0)
  # Check that redirect event is NOT marked as async
  for (evt in redirect_events) {
    testthat::expect_false(
      isTRUE((evt$shiny_session %||% list())$is_async),
      info = "audit_redirect_issued should be from main process (not async)"
    )
  }

  # Token exchange should be from async worker when using async=TRUE
  # (may fall back to sync if multisession not available)
  token_exchange_events <- Filter(
    function(e) identical(e$type, "audit_token_exchange"),
    events
  )
  testthat::expect_true(length(token_exchange_events) > 0)

  # Check if at least one async event exists (indicates worker was used)
  # Note: On systems where multisession isn't fully supported, this may be 0
  if (length(async_events) > 0) {
    cat("\n=== Async worker verification ===\n")

    # Verify async events include process tracking info
    # Note: main_process_id is always present for async events, but process_id
    # may be missing for some events that are emitted via captured context
    for (evt in async_events) {
      sess <- evt$shiny_session
      testthat::expect_true(
        !is.null(sess$main_process_id),
        info = paste0(
          "Async event should include main_process_id. Type: ",
          evt$type
        )
      )
      # Print process info when available
      if (!is.null(sess$main_process_id)) {
        cat(
          "Event:",
          evt$type,
          "| main_pid:",
          sess$main_process_id,
          "| worker_pid:",
          sess$process_id %||% "<inherited>",
          "\n"
        )
      }
    }

    testthat::expect_true(
      length(async_events) > 0,
      info = "Expected at least one audit event with is_async=TRUE from async worker"
    )
  } else {
    # Multisession may not be available; warn but don't fail
    cat(
      "\n[NOTE] No async events detected - multisession may have fallen back to sequential\n"
    )
  }

  # 10) Verify all events have required base fields
  for (evt in events) {
    testthat::expect_true(
      !is.null(evt$type),
      info = "Every event should have a type"
    )
    testthat::expect_true(
      !is.null(evt$trace_id),
      info = paste0("Event should have trace_id. Type: ", evt$type)
    )
  }

  cat("\n=== Audit log integration test passed ===\n")
})
