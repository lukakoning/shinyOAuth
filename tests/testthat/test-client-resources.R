test_that("client constructors validate optional API and scope configuration", {
  create <- function(...) oauth_client(make_test_provider(), "registration",
    redirect_uri = "https://app.example/callback", scopes = c("read", "write"), ...)
  for (bad in list("https://api.example", c(api = "http://api.example"),
      c(api = "https://api.example/v1?query=1"),
      setNames(c("https://a.example", "https://b.example"), c("api", "api")))) {
    expect_error(create(resource_bases = bad))
  }
  for (bad in list(1, NA_character_, "two words", "admin")) {
    expect_error(create(required_scopes = bad))
  }
  for (bad in list("", NA_character_, "line\nbreak", strrep("x", 129))) {
    expect_error(create(label = bad), "label")
  }
  client <- create(required_scopes = c("write", "read", "read"))
  expect_identical(client@required_scopes, c("read", "write"))
  expect_identical(client@smart, list())
  expect_false(client_uses_smart_scopes(client))
})

test_that("inherited provider names remain compatible with optional labels", {
  for (name in c("Ordinary provider", strrep("a", 200), strrep("\u00e9", 100), "Line\nbreak")) {
    provider <- make_test_provider()
    provider@name <- name
    for (constructor in list(oauth_client, OAuthClient)) {
      client <- constructor(provider = provider, client_id = "example",
        redirect_uri = "https://app.example/callback", scopes = "read")
      expect_identical(client@provider@name, name)
      expect_lte(nchar(client@label, type = "bytes"), 128L)
      expect_identical(validUTF8(client@label), TRUE)
      expect_identical(grepl("[[:cntrl:]]", client@label), FALSE)
      expect_identical(client@smart, list())
      explicit <- constructor(provider = provider, client_id = "example",
        redirect_uri = "https://app.example/callback", scopes = "read", label = "Selected label")
      expect_identical(explicit@label, "Selected label")
    }
  }
})

test_that("managers capture named client configuration and detect changed runtime policy", {
  withr::local_options(shinyOAuth.tls_min_version = NULL)
  client <- oauth_client(make_test_provider(), "external-registration-id",
    redirect_uri = "https://app.example/callback", scopes = "read",
    resource_bases = c(api = "https://api.example/v1"), required_scopes = "read")
  manager <- oauth_connections(clients = list(hospital = client), app_origin = "https://app.example")
  expect_identical(names(manager$clients), "hospital")
  expect_identical(manager$clients$hospital@client_id, "external-registration-id")
  client@resource_bases <- c(api = "https://api.example/v2")
  expect_identical(manager$clients$hospital@resource_bases, c(api = "https://api.example/v1"))
  expect_error(manager$clients <- list(hospital = client), "locked")
  oauth_connections_ui(shiny::fluidPage(), "health", manager)
  session <- manager_test_session()
  withr::defer(session$close())
  shiny::withReactiveDomain(session, shiny::isolate({
    controller <- connection_manager_controller(manager, session)
    hooks <- controller$hooks("hospital")
    context <- hooks$prepare()
    expect_identical(context$client, "hospital")
    expect_true(hooks$validate(context))
    withr::local_options(shinyOAuth.tls_min_version = "1.3")
    expect_error(hooks$prepare(), "configuration changed")
    expect_error(hooks$validate(context), "configuration changed")
  }))
})

test_that("changed runtime policy prevents refresh commits and still permits local disconnect", {
  withr::local_options(shinyOAuth.tls_min_version = NULL)
  client <- oauth_client(make_test_provider(), "registration",
    redirect_uri = "https://app.example/callback", scopes = "read",
    resource_bases = c(api = "https://api.example/v1"))
  manager <- oauth_connections(list(api = client), "https://app.example")
  oauth_connections_ui(shiny::fluidPage(), "health", manager)
  session <- manager_test_session()
  withr::defer(session$close())
  revoked <- 0L
  local_mocked_bindings(
    refresh_token = function(client, token, ...) {
      options(shinyOAuth.tls_min_version = "1.3")
      OAuthToken(access_token = "replacement", refresh_token = "rotated",
        expires_at = as.numeric(Sys.time()) + 60, granted_scopes = "read")
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
      list(revoked = TRUE)
    }, .package = "shinyOAuth")
  shiny::withReactiveDomain(session, shiny::isolate({
    controller <- connection_manager_controller(manager, session)
    hooks <- controller$hooks("api")
    hooks$accept(OAuthToken(access_token = "original", refresh_token = "refresh",
      expires_at = as.numeric(Sys.time()) + 60, granted_scopes = "read"),
      hooks$prepare(), as.numeric(Sys.time()))
    id <- controller$records()[[1L]]$stored$id
    expect_error(controller$refresh(id), "Connection refresh failed")
    expect_identical(controller$read(id)$status, "uncertain")
    expect_null(controller$read(id)$token)
    result <- controller$disconnect(id)
    expect_identical(result$local, "disconnected")
    expect_identical(result$remote, list(refresh = "not_attempted", access = "not_attempted"))
    expect_identical(revoked, 0L)
  }))
})
