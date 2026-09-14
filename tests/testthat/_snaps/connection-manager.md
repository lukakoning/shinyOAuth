# configured account capacity includes logged-out generations

    Code
      shiny::testServer(oauth_connections_server, args = list(id = "health", manager = f$
        manager), session = manager_test_session(), { })
    Condition
      Error in `err_abort()`:
      ! [shinyOAuth] - Token error
      ! Owner session capacity reached
      i Trace ID: <redacted>

