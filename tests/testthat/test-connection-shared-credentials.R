test_that("rotation disposes of known refresh aliases without merging authorizations", {
  f <- manager_test_fixture()
  seen <- character()
  local_mocked_bindings(refresh_token = function(client, token, ...) {
    seen <<- c(seen, token@refresh_token)
    manager_test_token("new-access", "rotated-refresh")
  })
  shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f$manager, session)
    }, {
      a <- manager_test_accept(ctl, token = manager_test_token("same-access", "shared"))
      b <- manager_test_accept(ctl, token = manager_test_token("same-access", "shared"))
      independent <- manager_test_accept(ctl, token = manager_test_token("other", "separate"))
      other_client <- manager_test_accept(ctl, "b", manager_test_token("different", "shared"))
      expect_true(ctl$refresh(a))
      expect_identical(ctl$read(a)$token@refresh_token, "rotated-refresh")
      expect_identical(ctl$read(b)$status, "uncertain")
      expect_null(ctl$read(b)$stored$sealed)
      expect_error(ctl$refresh(b), "current state")
      expect_identical(seen, "shared")
      expect_identical(ctl$read(independent)$status, "active")
      expect_identical(ctl$read(other_client)$status, "active")
      expect_error(manager_test_accept(ctl, token = manager_test_token("late", "shared")),
        "already retired")
      # The registry contains no access or refresh token bytes.
      registry <- serialize(as.list(f$manager$state$credential_records), NULL)
      expect_false(grepl("rotated-refresh|same-access", rawToChar(registry[registry != as.raw(0)])))
    })
})

for (rotate in c(FALSE, TRUE)) {
  test_that(paste("overlapping aliases await the physical credential outcome; rotation", rotate), {
    f <- manager_test_fixture()
    finish <- NULL
    seen <- character()
    local_mocked_bindings(refresh_token_impl = function(oauth_client, token, ...) {
      seen <<- c(seen, token@refresh_token)
      if (length(seen) == 1L) {
        promises::promise(function(resolve, reject) finish <<- resolve)
      } else {
        manager_test_token("b-refreshed", "shared")
      }
    })
    shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
      function(input, output, session) {
        ctl <- connection_manager_controller(f$manager, session)
      }, {
        a <- manager_test_accept(ctl, token = manager_test_token("a", "shared"))
        b <- manager_test_accept(ctl, token = manager_test_token("b", "shared"))
        done_a <- done_b <- NULL
        promises::then(ctl$refresh(a, async = TRUE), function(value) done_a <<- value)
        promises::then(ctl$refresh(b, async = TRUE),
          function(value) done_b <<- value, function(error) done_b <<- error)
        expect_length(seen, 1L)
        expect_identical(ctl$read(b)$status, "active")
        expect_error(ctl$refresh(b), "Shared credential refresh")
        finish(manager_test_token("a-refreshed", if (rotate) "rotated" else "shared"))
        poll_for_async(function() !is.null(done_a) && !is.null(done_b), session)
        expect_true(done_a)
        if (rotate) {
          expect_s3_class(done_b, "error")
          expect_identical(ctl$read(b)$status, "uncertain")
          expect_length(seen, 1L)
        } else {
          expect_true(done_b)
          expect_identical(ctl$read(b)$token@access_token, "b-refreshed")
          expect_identical(ctl$read(a)$token@access_token, "a-refreshed")
          expect_identical(seen, c("shared", "shared"))
        }
        expect_length(f$manager$state$credential_flights, 0L)
      })
  })
}

for (outcome in c("not_consumed", "possibly_consumed", "consumed")) {
  test_that(paste("shared refresh failures honor credential outcome", outcome), {
    f <- manager_test_fixture()
    local_mocked_bindings(refresh_token = function(...) {
      stop(refresh_outcome_error(simpleError("fixture failure"), outcome))
    })
    shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
      function(input, output, session) {
        ctl <- connection_manager_controller(f$manager, session)
      }, {
        a <- manager_test_accept(ctl)
        b <- manager_test_accept(ctl)
        expect_error(ctl$refresh(a), "refresh failed")
        for (id in c(a, b)) {
          expect_identical(ctl$read(id)$status,
            if (outcome == "not_consumed") "active" else "uncertain")
        }
        expect_length(f$manager$state$credential_flights, 0L)
      })
  })
}

test_that("successful revocation retires byte-identical credentials across owners", {
  f <- manager_test_fixture()
  local_mocked_bindings(revoke_token = function(client, token, which, ...) {
    list(supported = TRUE, revoked = identical(which, "access"))
  })
  peer_session <- manager_test_session(manager_test_cookie(f))
  withr::defer(peer_session$close())
  shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f$manager, session)
    }, {
      a <- manager_test_accept(ctl, token = manager_test_token("same", "refresh-a"))
      peer <- shiny::withReactiveDomain(peer_session,
        connection_manager_controller(f$manager, peer_session))
      b <- shiny::withReactiveDomain(peer_session,
        manager_test_accept(peer, token = manager_test_token("same", "refresh-b")))
      independent <- manager_test_accept(ctl, token = manager_test_token("distinct", "refresh-b"))
      expect_identical(ctl$disconnect(a)$remote$access, "accepted")
      shiny::withReactiveDomain(peer_session, {
        expect_identical(peer$read(b)$status, "uncertain")
        expect_null(peer$read(b)$token)
        expect_null(peer$read(b)$stored$sealed)
        peer$end()
      })
      # Revoking an access token does not retire a distinct refresh credential.
      expect_identical(ctl$read(independent)$status, "active")
    })
})

test_that("abandoned shared refreshes invalidate aliases before another dispatch", {
  f <- manager_test_fixture()
  finish <- NULL
  local_mocked_bindings(refresh_token = function(...) {
    promises::promise(function(resolve, reject) finish <<- resolve)
  })
  shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
    function(input, output, session) {
      ctl <- connection_manager_controller(f$manager, session)
    }, {
      a <- manager_test_accept(ctl)
      b <- manager_test_accept(ctl)
      failed <- NULL
      promises::catch(ctl$refresh(a, async = TRUE), function(e) failed <<- e)
      key <- ls(f$manager$state$credential_flights)[[1L]]
      flight <- f$manager$state$credential_flights[[key]]
      flight$expires_at <- as.numeric(Sys.time()) - 1
      expect_error(ctl$refresh(b), "current state")
      expect_identical(ctl$read(a)$status, "uncertain")
      finish(manager_test_token("late-access", "late-refresh"))
      poll_for_async(function() !is.null(failed), session)
      expect_identical(ctl$read(a)$status, "uncertain")
      expect_identical(ctl$read(b)$status, "uncertain")
    })
})

for (revoke in c(FALSE, TRUE)) {
  test_that(paste("alias removal and pending refresh preserve removal intent", revoke), {
    f <- manager_test_fixture()
    finish <- NULL
    local_mocked_bindings(refresh_token_impl = function(...) {
      promises::promise(function(resolve, reject) finish <<- resolve)
    }, revoke_token = function(...) list(supported = TRUE, revoked = TRUE))
    shiny::testServer(session = manager_test_session(manager_test_cookie(f)),
      function(input, output, session) {
        ctl <- connection_manager_controller(f$manager, session)
      }, {
        a <- manager_test_accept(ctl)
        b <- manager_test_accept(ctl)
        completed <- NULL
        promises::then(ctl$refresh(a, async = TRUE),
          function(value) completed <<- value, function(error) completed <<- error)
        # An authorization accepted while the request is pending is an alias too.
        late <- manager_test_accept(ctl)
        ctl$disconnect(b, revoke = revoke)
        finish(manager_test_token("rotated-access", "rotated-refresh"))
        poll_for_async(function() !is.null(completed), session)
        if (revoke) expect_s3_class(completed, "error") else expect_true(completed)
        expect_identical(ctl$read(a)$status, if (revoke) "uncertain" else "active")
        expect_identical(ctl$read(b)$status, "disconnected")
        expect_identical(ctl$read(late)$status, "uncertain")
        expect_null(ctl$read(late)$stored$sealed)
      })
  })
}
