test_that("managed disconnect cycles release cached references and their observers", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  fixture <- manager_test_fixture()
  cookie <- manager_test_cookie(fixture)
  other_session <- manager_test_session(cookie)
  on.exit(other_session[["close"]](), add = TRUE)
  other <- shiny::withReactiveDomain(other_session, {
    connection_manager_controller(fixture[["manager"]], other_session)
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = fixture[["manager"]]),
    session = manager_test_session(cookie),
    {
      session[["flushReact"]]()
      read_ids <- character()
      original_read <- controller[["read"]]
      controller[["read"]] <- function(id, ...) {
        read_ids <<- c(read_ids, id)
        original_read(id, ...)
      }
      assign("controller", controller, envir = environment(connection))
      held <- list()
      for (i in seq_len(20L)) {
        id <- shiny::withReactiveDomain(other_session, {
          manager_test_accept(
            other,
            token = manager_test_token(
              access = paste0("access-", i),
              refresh = paste0("refresh-", i)
            )
          )
        })
        held[[i]] <- connection(id)
        expect_identical(connection(id), held[[i]])
        session[["flushReact"]]()
        shiny::withReactiveDomain(other_session, {
          other[["disconnect"]](id, revoke = FALSE)
        })
        session[["flushReact"]]()
        expect_length(ls(references, all.names = TRUE), 0L)
        expect_false(held[[i]][["has_scopes"]]("read"))
      }
      read_ids <- character()
      id <- manager_test_accept(controller)
      session[["flushReact"]]()
      expect_length(read_ids, 0L)
      current <- connection(id)
      session[["flushReact"]]()
      expect_true(current[["has_scopes"]]("read"))
      expect_identical(connection(id), current)
      expect_identical(ls(references, all.names = TRUE), id)
      read_ids <- character()
      controller[["disconnect"]](id, revoke = FALSE)
      session[["flushReact"]]()
      expect_true(all(read_ids == id))
      expect_length(ls(references, all.names = TRUE), 0L)
      # Retaining a disconnected reference explicitly must not re-register it.
      expect_false(connection(id)[["has_scopes"]]("read"))
      session[["flushReact"]]()
      read_ids <- character()
      manager_test_accept(controller)
      session[["flushReact"]]()
      expect_length(read_ids, 0L)
    }
  )
})

test_that("single-module replacement stops observers belonging to old authorizations", {
  client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
  counts <- integer()
  signal <- connection_integration_signal
  local_mocked_bindings(connection_integration_signal = function(
    resolve,
    is_current = NULL
  ) {
    index <- length(counts) + 1L
    counts[[index]] <<- 0L
    signal(
      function() {
        counts[[index]] <<- counts[[index]] + 1L
        resolve()
      },
      is_current
    )
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      held <- list()
      for (i in seq_len(20L)) {
        .advance_auth_epoch()
        .accept_login_token(
          manager_test_token(access = paste0("access-", i)),
          NULL
        )
        held[[i]] <- values[["connection"]]()
        session[["flushReact"]]()
      }
      previous <- counts
      values[["token"]] <- manager_test_token(access = "rotated")
      session[["flushReact"]]()
      expect_identical(counts[1:19], previous[1:19])
      expect_gt(counts[[20]], previous[[20]])
      expect_false(held[[1]][["has_scopes"]]("read"))
      expect_identical(held[[20]][["access_token"]](), "rotated")
    }
  )
})

test_that("legacy permission observers continue following subsequent logins", {
  client <- connection_test_client(
    make_test_client(use_nonce = FALSE, scopes = c("read", "write")),
    c(api = "https://api.example/")
  )
  shiny::testServer(
    function(input, output, session) {
      source <- shiny::reactiveVal(manager_test_token())
      current <- oauth_connection(client, shiny::reactive(source()))
      observed <- new.env(parent = emptyenv())
      observed[["values"]] <- logical()
      shiny::observe({
        observed[["values"]] <- c(
          observed[["values"]],
          current[["has_scopes"]]("read")
        )
      })
    },
    {
      session[["flushReact"]]()
      source(NULL)
      session[["flushReact"]]()
      source(manager_test_token(access = "new-login"))
      session[["flushReact"]]()
      expect_identical(observed[["values"]], c(TRUE, FALSE, TRUE))
    }
  )
})
