test_that("enumeration batches validation and polls share redacted metadata across sessions", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  open <- connection_credentials_open
  fingerprint <- connection_client_fingerprint
  prune <- connection_credential_prune
  counts <- new.env(parent = emptyenv())
  counts[['opens']] <- counts[['fingerprints']] <- counts[['prunes']] <- 0L
  local_mocked_bindings(
    connection_credentials_open = function(...) {
      counts[['opens']] <- counts[['opens']] + 1L
      open(...)
    },
    connection_client_fingerprint = function(...) {
      counts[['fingerprints']] <- counts[['fingerprints']] + 1L
      fingerprint(...)
    },
    connection_credential_prune = function(...) {
      counts[['prunes']] <- counts[['prunes']] + 1L
      prune(...)
    }
  )
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      hooks <- ctl[["hooks"]]("a")
      for (n in c(10L, 50L)) {
        existing <- length(ctl[["records"]]())
        for (i in seq_len(n - existing)) {
          context <- hooks[["prepare"]]()
          hooks[["accept"]](
            manager_test_token(),
            context,
            as.numeric(Sys.time()) - 100
          )
        }
        counts[['opens']] <- counts[['fingerprints']] <- counts[[
          'prunes'
        ]] <- 0L
        expect_length(ctl[["records"]](), n)
        expect_identical(counts[['opens']], n)
        expect_identical(counts[['fingerprints']], 1L)
        expect_identical(counts[['prunes']], 1L)
        expect_length(ctl[["poll"]](), n)
        counts[['opens']] <- counts[['fingerprints']] <- counts[[
          'prunes'
        ]] <- 0L
        for (i in seq_len(3L)) {
          expect_length(ctl[["poll"]](), n)
        }
        expect_identical(counts[['opens']], 0L)
        expect_identical(counts[['fingerprints']], 3L)
        expect_identical(counts[['prunes']], 3L)
      }
      cached <- unlist(as.list(f[["manager"]][["state"]][[
        "lifecycle_metadata"
      ]]))
      expect_false(any(grepl("synthetic-access|synthetic-refresh", cached)))
      expect_false(any(
        cached ==
          raw_to_hex_lower(connection_credential_key(
            f[["manager"]][["keys"]][["credentials"]]
          ))
      ))
    }
  )
  # Browser retention survives the first session. Another tab reuses metadata,
  # while independently validating its owner and the current client policy.
  counts[['opens']] <- counts[['fingerprints']] <- counts[['prunes']] <- 0L
  shiny::testServer(
    session = manager_test_session(cookie),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      expect_length(ctl[["poll"]](), 50L)
      expect_identical(counts[['opens']], 0L)
      expect_identical(counts[['fingerprints']], 1L)
      expect_identical(counts[['prunes']], 1L)
    }
  )
})

test_that("poll metadata expires at token deadlines and follows store revisions", {
  counts <- new.env(parent = emptyenv())
  counts[['now']] <- as.numeric(Sys.time())
  local_mocked_bindings(
    Sys.time = function() {
      as.POSIXct(counts[['now']], origin = "1970-01-01", tz = "UTC")
    },
    .package = "base"
  )
  f <- manager_test_fixture()
  open <- connection_credentials_open
  counts[['opens']] <- 0L
  local_mocked_bindings(connection_credentials_open = function(...) {
    counts[['opens']] <- counts[['opens']] + 1L
    open(...)
  })
  shiny::testServer(
    session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      token <- manager_test_token()
      token@expires_at <- counts[['now']] + 10
      id <- manager_test_accept(ctl, token = token)
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "active")
      counts[['opens']] <- 0L
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "active")
      expect_identical(counts[['opens']], 0L)
      counts[['now']] <- counts[['now']] + 11
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "expired")
      expect_identical(counts[['opens']], 1L)
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "expired")
      expect_identical(counts[['opens']], 1L)
      row <- ctl[["read"]](id)[["stored"]]
      store <- f[["manager"]][["store"]]
      claim <- store[["begin_refresh"]](row[["owner"]], id, row[["revision"]])
      expect_identical(
        ctl[["poll"]]()[[1L]][["lifecycle_status"]],
        "refreshing"
      )
      store[["fail_refresh"]](
        row[["owner"]],
        id,
        claim[["operation"]],
        claim[["revision"]],
        "possibly_consumed"
      )
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "uncertain")
      ctl[["disconnect"]](id, revoke = FALSE)
      expect_identical(
        ctl[["poll"]]()[[1L]][["lifecycle_status"]],
        "disconnected"
      )
    }
  )
})

test_that("server ticks do not reopen unchanged retained credentials", {
  f <- manager_test_fixture()
  open <- connection_credentials_open
  counts <- new.env(parent = emptyenv())
  counts[['opens']] <- 0L
  local_mocked_bindings(connection_credentials_open = function(...) {
    counts[['opens']] <- counts[['opens']] + 1L
    open(...)
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(
      id = "health",
      manager = f[["manager"]],
      refresh_check_interval_ms = 100
    ),
    session = manager_test_session(manager_test_cookie(f)),
    {
      hooks <- controller[["hooks"]]("a")
      for (i in seq_len(20L)) {
        context <- hooks[["prepare"]]()
        hooks[["accept"]](
          manager_test_token(),
          context,
          as.numeric(Sys.time()) - 100
        )
      }
      session[["flushReact"]]()
      counts[['opens']] <- 0L
      for (i in seq_len(3L)) {
        session[["elapse"]](100)
      }
      expect_identical(counts[['opens']], 0L)
    }
  )
})

test_that("a retirement ledger invalidates cached health before a store revision changes", {
  f <- manager_test_fixture()
  shiny::testServer(
    session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f[["manager"]], session)
    },
    {
      id <- manager_test_accept(ctl)
      before <- ctl[["poll"]]()[[1L]]
      expect_identical(before[["lifecycle_status"]], "active")
      state <- f[["manager"]][["state"]]
      key <- state[["credential_records"]][[id]][["keys"]][["access"]]
      # A failed backend update must not erase independent retirement evidence.
      state[["credential_retirements"]][[paste0("access", key)]] <- list(
        retired = TRUE,
        reservations = 0L,
        expires_at = as.numeric(Sys.time()) + 3600
      )
      expect_identical(ctl[["poll"]]()[[1L]][["lifecycle_status"]], "uncertain")
      expect_null(ctl[["read"]](id)[["token"]])
    }
  )
})
