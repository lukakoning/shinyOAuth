managed_module_fixture <- function() {
  control <- new.env(parent = emptyenv())
  control$valid <- TRUE
  control$accepted <- list()
  control$discarded <- list()
  control$cancelled <- 0L
  control$checks <- 0L
  control$context <- list(
    version = 1L,
    owner = "synthetic-owner",
    generation = "1"
  )
  control$hooks <- list(
    prepare = function() control$context,
    validate = function(context) {
      control$checks <- control$checks + 1L
      isTRUE(control$valid) &&
        identical(context$owner, control$context$owner) &&
        identical(context$generation, control$context$generation)
    },
    accept = function(token, context, authenticated_at) {
      control$accepted[[length(control$accepted) + 1L]] <- list(
        token = token,
        context = context,
        authenticated_at = authenticated_at
      )
      invisible(TRUE)
    },
    cancel = function(context) {
      control$cancelled <- control$cancelled + 1L
    },
    discard = function(token) {
      control$discarded[[length(control$discarded) + 1L]] <- token
    }
  )
  control
}

test_that("managed callback checks browser and live owner without consuming state", {
  client <- make_test_client()
  f <- managed_module_fixture()
  browser <- valid_browser_token()
  auth <- prepare_authorization(client, browser, f$context)
  payload <- state_payload_decrypt_validate(client, auth$state)
  record <- state_store_get(client, payload$state)
  checked <- oauth_module_managed_context(f$hooks, client, auth$state, browser)
  expect_identical(checked$json, record$transaction_context)
  expect_identical(checked$data$owner, f$context$owner)
  expect_identical(state_store_get(client, payload$state), record)
  checks <- f$checks
  expect_error(
    oauth_module_managed_context(
      f$hooks,
      client,
      auth$state,
      paste(rep("b", 128), collapse = "")
    ),
    "Browser token mismatch"
  )
  expect_identical(f$checks, checks)
  f$valid <- FALSE
  expect_error(
    oauth_module_managed_context(
      f$hooks,
      client,
      auth$state,
      browser
    ),
    "owner is unavailable"
  )
  expect_identical(state_store_get(client, payload$state), record)
  unbound <- prepare_authorization(client, browser)
  expect_error(
    oauth_module_managed_context(
      f$hooks,
      client,
      unbound$state,
      browser
    ),
    "requires its authorization context"
  )
})

test_that("managed login commits through its hook and leaves legacy credentials empty", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- managed_module_fixture()
  client <- make_test_client()
  exchanges <- 0L
  local_mocked_bindings(swap_code_for_token_set = function(...) {
    exchanges <<- exchanges + 1L
    list(
      access_token = "synthetic-managed",
      token_type = "Bearer",
      expires_in = 3600
    )
  })
  shiny::testServer(
    oauth_module_server_impl,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      .managed = f$hooks
    ),
    {
      for (i in seq_len(2L)) {
        # This unit fixture does not run the JavaScript cookie acknowledgement.
        values$browser_token <- "__SKIPPED__"
        state <- parse_query_param(values$build_auth_url(), "state")
        values$.process_query(paste0("?code=ok&state=", state))
        session$flushReact()
        expect_null(values$error)
        expect_null(values$token)
        expect_null(values$auth_started_at)
        expect_false(values$authenticated)
        expect_false(values$refresh_in_progress)
      }
      expect_length(f$accepted, 2L)
      expect_identical(exchanges, 2L)
      expect_identical(f$accepted[[1L]]$token@access_token, "synthetic-managed")
      expect_true(is.finite(f$accepted[[1L]]$authenticated_at))
      expect_length(f$discarded, 0L)
    }
  )
})

for (response in c("code=ok", "error=access_denied")) {
  test_that(
    paste("owner expiry prevents consuming a managed", response, "callback"),
    {
      local_options(shinyOAuth.skip_browser_token = TRUE)
      f <- managed_module_fixture()
      client <- make_test_client()
      exchanges <- 0L
      local_mocked_bindings(swap_code_for_token_set = function(...) {
        exchanges <<- exchanges + 1L
        stop("unexpected exchange")
      })
      shiny::testServer(
        oauth_module_server_impl,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          .managed = f$hooks
        ),
        {
          state <- parse_query_param(values$build_auth_url(), "state")
          payload <- state_payload_decrypt_validate(
            client,
            utils::URLdecode(state)
          )
          original <- state_store_get(client, payload$state)
          f$valid <- FALSE
          values$.process_query(paste0("?", response, "&state=", state))
          session$flushReact()
          expect_identical(state_store_get(client, payload$state), original)
          expect_identical(exchanges, 0L)
          expect_length(f$accepted, 0L)
          expect_length(f$discarded, 0L)
          expect_identical(f$cancelled, 0L)
          expect_false(is.null(values$error))
        }
      )
    }
  )
}

test_that("an owner-validated provider error consumes and cancels its managed transaction", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- managed_module_fixture()
  client <- make_test_client()
  shiny::testServer(
    oauth_module_server_impl,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      .managed = f$hooks
    ),
    {
      state <- parse_query_param(values$build_auth_url(), "state")
      payload <- state_payload_decrypt_validate(client, utils::URLdecode(state))
      values$.process_query(paste0("?error=access_denied&state=", state))
      expect_identical(values$error, "access_denied")
      expect_identical(f$cancelled, 1L)
      expect_error(
        state_store_get(client, payload$state),
        class = "shinyOAuth_state_error"
      )
      expect_length(f$accepted, 0L)
    }
  )
})

for (failure in c("owner_change", "commit_failure")) {
  test_that(paste("accepted credentials are discarded after", failure), {
    local_options(shinyOAuth.skip_browser_token = TRUE)
    f <- managed_module_fixture()
    client <- make_test_client()
    if (failure == "commit_failure") {
      f$hooks$accept <- function(...) stop("storage unavailable")
    }
    local_mocked_bindings(swap_code_for_token_set = function(...) {
      if (failure == "owner_change") {
        f$valid <- FALSE
      }
      list(
        access_token = "uncommitted",
        token_type = "Bearer",
        expires_in = 3600
      )
    })
    shiny::testServer(
      oauth_module_server_impl,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        .managed = f$hooks
      ),
      {
        state <- parse_query_param(values$build_auth_url(), "state")
        values$.process_query(paste0("?code=ok&state=", state))
        session$flushReact()
        expect_null(values$token)
        expect_false(is.null(values$error))
        expect_length(f$accepted, 0L)
        expect_length(f$discarded, 1L)
        expect_identical(f$discarded[[1L]]@access_token, "uncommitted")
      }
    )
  })
}

test_that("async managed login carries only context data and rechecks before commit", {
  skip_if_not_installed("promises")
  skip_if_not_installed("later")
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- managed_module_fixture()
  client <- make_test_client()
  finish <- NULL
  dispatched <- NULL
  local_mocked_bindings(
    prepare_client_for_worker = function(client) client,
    async_dispatch = function(expr, args, ...) {
      dispatched <<- args
      promises::promise(function(resolve, reject) {
        finish <<- resolve
      })
    }
  )
  shiny::testServer(
    oauth_module_server_impl,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      async = TRUE,
      .managed = f$hooks
    ),
    {
      state <- parse_query_param(values$build_auth_url(), "state")
      payload <- state_payload_decrypt_validate(client, utils::URLdecode(state))
      values$.process_query(paste0("?code=ok&state=", state))
      expect_type(dispatched$captured_managed_context, "character")
      expect_identical(
        jsonlite::fromJSON(dispatched$captured_managed_context)$owner,
        f$context$owner
      )
      expect_error(
        state_store_get(client, payload$state),
        class = "shinyOAuth_state_error"
      )
      f$valid <- FALSE
      finish(OAuthToken(
        access_token = "late",
        expires_at = as.numeric(Sys.time()) + 3600
      ))
      poll_for_async(function() length(f$discarded) == 1L, session)
      expect_length(f$accepted, 0L)
      expect_null(values$token)
      expect_false(is.null(values$error))
    }
  )
})

test_that("the internal manager rejects conflicting legacy lifecycle controls", {
  f <- managed_module_fixture()
  expect_error(
    oauth_module_server_impl(
      "auth",
      make_test_client(),
      auto_redirect = FALSE,
      refresh_proactively = TRUE,
      .managed = f$hooks
    ),
    "own login, refresh and retention"
  )
  expect_error(oauth_module_validate_managed_hooks(list()), "Invalid internal")
})
