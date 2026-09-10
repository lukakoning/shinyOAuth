owner_test_sessions <- function(max_entries = 1000L) {
  time <- new.env(parent = emptyenv())
  time$now <- 1000
  policy <- oauth_browser_owner(idle_timeout = 10, absolute_timeout = 30)
  registry <- connection_browser_sessions(
    policy,
    "https://app.example",
    "health",
    openssl::rand_bytes(32L),
    max_entries,
    function() time$now
  )
  list(time = time, policy = policy, registry = registry)
}

test_that("browser owner sessions require server state and bind generations", {
  f <- owner_test_sessions()
  created <- f$registry$create()
  expect_identical(f$registry$resolve(created$cookie), created$owner)
  expect_identical(f$registry$validate(created$owner), created$owner)
  expect_null(f$registry$resolve(random_urlsafe(43L)))
  expect_null(f$registry$resolve(created$owner$id))
  other <- f$registry$create()
  wrong_generation <- created$owner
  wrong_generation$generation <- other$owner$generation
  expect_null(f$registry$validate(wrong_generation))
  rotated <- f$registry$rotate(created$owner)
  expect_identical(rotated$owner$id, created$owner$id)
  expect_identical(rotated$owner$expires_at, created$owner$expires_at)
  expect_false(identical(rotated$owner$generation, created$owner$generation))
  expect_null(f$registry$resolve(created$cookie))
  expect_null(f$registry$validate(created$owner))
  expect_identical(f$registry$resolve(rotated$cookie), rotated$owner)
  expect_false(f$registry$revoke(created$owner))
  expect_true(f$registry$revoke(rotated$owner))
  expect_null(f$registry$resolve(rotated$cookie))
  expect_null(f$registry$validate(rotated$owner))
  expect_identical(f$registry$resolve(other$cookie), other$owner)
})

test_that("idle and absolute expiry remain authoritative after activity and rotation", {
  f <- owner_test_sessions()
  idle <- f$registry$create()
  active <- f$registry$create()
  f$time$now <- 1009
  expect_type(f$registry$resolve(active$cookie, touch = TRUE), "list")
  f$time$now <- 1010
  expect_null(f$registry$resolve(idle$cookie))
  expect_null(f$registry$validate(idle$owner))
  f$time$now <- 1018
  rotated <- f$registry$rotate(active$owner)
  expect_identical(rotated$owner$expires_at, 1030)
  f$time$now <- 1027
  expect_type(f$registry$resolve(rotated$cookie, touch = TRUE), "list")
  f$time$now <- 1030
  expect_null(f$registry$resolve(rotated$cookie))
  expect_error(f$registry$rotate(rotated$owner), "unavailable")
})

test_that("owner cookie attributes are separate from transaction binding cookies", {
  f <- owner_test_sessions()
  created <- f$registry$create()
  name <- f$registry$cookie_name
  expect_match(name, "^__Host-shinyOAuth-owner-")
  header <- connection_owner_cookie_header(
    name,
    created$cookie,
    f$registry$origin,
    f$policy
  )
  expect_match(header, "; Path=/; HttpOnly; SameSite=Lax; Secure", fixed = TRUE)
  expect_false(grepl("Domain=|Max-Age=", header))
  expect_identical(
    connection_owner_cookie_read(
      list(HTTP_COOKIE = paste0("other=value; ", name, "=", created$cookie)),
      name
    ),
    created$cookie
  )
  expect_error(
    connection_owner_cookie_read(
      list(
        HTTP_COOKIE = paste0(
          name,
          "=",
          created$cookie,
          "; ",
          name,
          "=",
          created$cookie
        )
      ),
      name
    ),
    "Ambiguous"
  )
  expect_error(
    connection_owner_cookie_read(list(HTTP_COOKIE = strrep("x", 16385)), name),
    "Invalid"
  )
  expect_null(connection_owner_cookie_read(
    list(HTTP_COOKIE = paste0(name, "=invalid")),
    name
  ))
  expect_match(
    connection_owner_cookie_header(
      name,
      NULL,
      f$registry$origin,
      f$policy,
      clear = TRUE
    ),
    "Max-Age=0"
  )
  expect_false(identical(
    name,
    connection_owner_cookie_name("https://app.example:8443", "health", f$policy)
  ))
  expect_false(identical(
    name,
    connection_owner_cookie_name("https://app.example", "other", f$policy)
  ))
  expect_error(
    connection_owner_cookie_name("http://localhost:8100", "health", f$policy),
    "HTTPS"
  )
  dev <- oauth_browser_owner(allow_http_loopback = TRUE)
  dev_name <- connection_owner_cookie_name(
    "http://localhost:8100",
    "health",
    dev
  )
  expect_false(startsWith(dev_name, "__Host-"))
  expect_false(grepl(
    "Secure",
    connection_owner_cookie_header(
      dev_name,
      created$cookie,
      "http://localhost:8100",
      dev
    )
  ))
  expect_error(connection_owner_cookie_name(
    "http://public.example",
    "health",
    dev
  ))
  expect_error(
    connection_owner_cookie_name(
      "https://app.example/path",
      "health",
      f$policy
    ),
    "without a path"
  )
  expect_error(
    oauth_browser_owner(idle_timeout = 30, absolute_timeout = 10),
    "cannot exceed"
  )
  expect_error(oauth_browser_owner(same_site = "None"))
})

test_that("owner capacity is bounded without invalidating live sessions", {
  f <- owner_test_sessions(1L)
  created <- f$registry$create()
  expect_error(f$registry$create(), "capacity")
  expect_identical(f$registry$resolve(created$cookie), created$owner)
  f$time$now <- 1010
  next_owner <- f$registry$create()
  expect_null(f$registry$resolve(created$cookie))
  expect_identical(f$registry$resolve(next_owner$cookie), next_owner$owner)
})

test_that("account owners revalidate trusted local identity and authentication age", {
  current <- list(
    subject = "local-account-a",
    session_id = "local-session-1",
    generation = "1",
    authenticated_at = 1000,
    expires_at = 1200
  )
  seen_session <- NULL
  policy <- oauth_account_owner(
    function(session) {
      seen_session <<- session
      current
    },
    idle_timeout = 10,
    absolute_timeout = 100,
    reauth_after_seconds = 60
  )
  key <- openssl::rand_bytes(32L)
  session <- new.env()
  resolve <- function(at = 1005) {
    connection_account_identity(
      policy,
      session,
      "https://app.example",
      "health",
      key,
      function() at
    )
  }
  first <- resolve()
  expect_identical(seen_session, session)
  expect_identical(first$expires_at, 1060)
  expect_false(grepl(
    "local-account|local-session",
    paste(unlist(first), collapse = "")
  ))
  current$generation <- "2"
  rotated <- resolve()
  expect_identical(rotated$id, first$id)
  expect_false(identical(rotated$generation, first$generation))
  current$subject <- "local-account-b"
  expect_false(identical(resolve()$id, first$id))
  expect_null(resolve(1060))
  expect_null(resolve(999))
  current <- NULL
  expect_null(resolve())
  policy$resolver <- function(session) stop("sensitive local credential")
  failure <- tryCatch(resolve(), error = identity)
  expect_match(
    conditionMessage(failure),
    "Local account session validation failed"
  )
  expect_false(grepl("sensitive local credential", conditionMessage(failure)))
  expect_error(
    oauth_account_owner(NULL, 10, 100, 60),
    "trusted session resolver"
  )
  expect_error(
    oauth_account_owner(function(session) NULL, 10, Inf, 60),
    "finite"
  )
})

test_that("unverified account values do not satisfy the resolver contract", {
  policy <- oauth_account_owner(
    function(session) list(subject = "unverified"),
    10,
    100,
    60
  )
  key <- openssl::rand_bytes(32L)
  expect_error(
    connection_account_identity(
      policy,
      NULL,
      "https://app.example",
      "health",
      key
    ),
    "Invalid local account"
  )
})

account_owner_test_sessions <- function(max_entries = 1000L) {
  state <- new.env(parent = emptyenv())
  state$now <- 1000
  state$login <- list(
    subject = "local-account-a",
    session_id = "local-session-a",
    generation = "1",
    authenticated_at = 1000,
    expires_at = 1200
  )
  policy <- oauth_account_owner(function(session) state$login, 10, 30, 60)
  registry <- connection_account_sessions(
    policy,
    "https://app.example",
    "health",
    openssl::rand_bytes(32L),
    max_entries,
    function() state$now
  )
  list(state = state, registry = registry)
}

test_that("account owner checks reject a changed login and retire logged-out sessions", {
  f <- account_owner_test_sessions()
  expect_null(f$registry$resolve(NULL))
  first <- f$registry$establish(NULL)
  expect_identical(f$registry$validate(first, NULL), first)
  f$state$login$generation <- "2"
  expect_null(f$registry$validate(first, NULL))
  second <- f$registry$establish(NULL)
  expect_identical(first$id, second$id)
  expect_false(identical(first$generation, second$generation))
  expect_true(f$registry$revoke(first))
  expect_identical(f$registry$resolve(NULL), second)
  expect_true(f$registry$revoke(second))
  expect_false(f$registry$revoke(second))
  expect_null(f$registry$resolve(NULL))
  expect_null(f$registry$establish(NULL))
  # A verified fresh authentication establishes a new generation even when the
  # local application keeps its own session ID across reauthentication.
  f$state$now <- 1001
  f$state$login$authenticated_at <- 1001
  fresh <- f$registry$establish(NULL)
  expect_identical(fresh$id, first$id)
  expect_false(identical(fresh$generation, second$generation))
  f$state$login$subject <- "local-account-b"
  expect_null(f$registry$validate(fresh, NULL))
  other <- f$registry$establish(NULL)
  expect_false(identical(other$id, fresh$id))
  f$state$login <- NULL
  expect_null(f$registry$validate(other, NULL))
})

test_that("expired account generations cannot be re-enrolled", {
  f <- account_owner_test_sessions()
  owner <- f$registry$establish(NULL)
  f$state$now <- 1010
  expect_null(f$registry$validate(owner, NULL, touch = TRUE))
  expect_null(f$registry$establish(NULL))

  f <- account_owner_test_sessions()
  owner <- f$registry$establish(NULL)
  for (at in c(1009, 1018, 1027)) {
    f$state$now <- at
    expect_identical(f$registry$validate(owner, NULL, touch = TRUE), owner)
  }
  f$state$now <- 1030
  expect_null(f$registry$resolve(NULL))
  expect_null(f$registry$establish(NULL))
})

test_that("account expiry can shorten but cannot extend an enrolled lifetime", {
  f <- account_owner_test_sessions()
  f$state$login$expires_at <- 1020
  owner <- f$registry$establish(NULL)
  expect_identical(owner$expires_at, 1020)
  f$state$login$expires_at <- 1200
  expect_identical(f$registry$resolve(NULL)$expires_at, 1020)
  f$state$login$expires_at <- 1005
  expect_identical(f$registry$resolve(NULL)$expires_at, 1005)
  f$state$now <- 1005
  expect_null(f$registry$resolve(NULL))
  f$state$login$expires_at <- 1200
  expect_null(f$registry$establish(NULL))
})

test_that("account capacity preserves retirement until authentication becomes stale", {
  f <- account_owner_test_sessions(1L)
  owner <- f$registry$establish(NULL)
  expect_true(f$registry$revoke(owner))
  f$state$login$generation <- "2"
  expect_error(f$registry$establish(NULL), "capacity")
  f$state$login$generation <- "1"
  expect_null(f$registry$establish(NULL))
  f$state$now <- 1060
  expect_null(f$registry$establish(NULL))
  f$state$login$authenticated_at <- 1060
  expect_type(f$registry$establish(NULL), "list")
})

test_that("failed cookie rotation leaves the existing browser session usable", {
  f <- owner_test_sessions()
  owner <- f$registry$create()
  testthat::local_mocked_bindings(random_urlsafe = function(n) {
    if (n == 43L) {
      stop("randomness unavailable")
    }
    strrep("a", n)
  })
  expect_error(f$registry$rotate(owner$owner), "randomness unavailable")
  expect_identical(f$registry$resolve(owner$cookie), owner$owner)
})

test_that("owner state and identifiers are specific to deployment and namespace", {
  key <- openssl::rand_bytes(32L)
  policy <- oauth_browser_owner()
  first <- connection_browser_sessions(
    policy,
    "https://app.example",
    "one",
    key
  )
  second <- connection_browser_sessions(
    policy,
    "https://app.example",
    "two",
    key
  )
  cookie <- first$create()$cookie
  expect_null(second$resolve(cookie))
  restarted <- connection_browser_sessions(
    policy,
    "https://app.example",
    "one",
    key
  )
  expect_null(restarted$resolve(cookie))

  policy <- oauth_account_owner(
    function(session) {
      list(
        subject = "a",
        session_id = "b",
        generation = "c",
        authenticated_at = 1000,
        expires_at = 2000
      )
    },
    10,
    30,
    60
  )
  resolve <- function(
    origin = "https://app.example",
    namespace = "one",
    secret = key
  ) {
    connection_account_identity(
      policy,
      NULL,
      origin,
      namespace,
      secret,
      function() 1000
    )
  }
  original <- resolve()
  expect_false(identical(original$id, resolve(namespace = "two")$id))
  expect_false(identical(
    original$id,
    resolve(origin = "https://other.example")$id
  ))
  expect_false(identical(
    original$id,
    resolve(secret = openssl::rand_bytes(32L))$id
  ))
  expect_error(resolve(namespace = "bad namespace"), "namespace")
})

test_that("owner registries reject transfer to another R process", {
  skip_if_not_installed("callr")
  registries <- list(
    owner_test_sessions()$registry,
    account_owner_test_sessions()$registry
  )
  errors <- callr::r(
    function(registries, root) {
      pkgload::load_all(root, quiet = TRUE)
      vapply(
        registries,
        function(registry) {
          tryCatch(
            {
              registry$resolve(NULL)
              "accepted"
            },
            error = function(e) conditionMessage(e)
          )
        },
        character(1)
      )
    },
    args = list(registries = registries, root = testthat::test_path("../.."))
  )
  expect_true(all(grepl("process-local", errors, fixed = TRUE)))
})
