test_that("issuer identifiers reject empty query components before discovery", {
  requests <- 0L
  local_mocked_bindings(.discover_fetch_response = function(...) {
    requests <<- requests + 1L
    stop("unexpected discovery request")
  })
  for (issuer in c(
    "https://issuer.example?",
    "https://issuer.example/?",
    "https://issuer.example/tenant?",
    "https://issuer.example/.well-known/openid-configuration?"
  )) {
    for (constructor in list(oauth_provider, OAuthProvider)) {
      expect_error(
        constructor(
          name = "example",
          issuer = issuer,
          auth_url = "https://issuer.example/auth",
          token_url = "https://issuer.example/token"
        ),
        "issuer must not contain query or fragment"
      )
    }
    expect_error(
      .discover_assert_valid_issuer(issuer),
      "issuer must not contain query or fragment"
    )
    expect_error(
      oauth_provider_oidc_discover(issuer),
      "issuer must not contain query or fragment"
    )
  }
  expect_identical(requests, 0L)
  for (issuer in c(
    "https://issuer.example",
    "https://issuer.example/tenant%3F"
  )) {
    expect_no_error(.discover_assert_valid_issuer(issuer))
    expect_identical(
      oauth_provider(
        name = "example",
        issuer = issuer,
        auth_url = "https://issuer.example/auth",
        token_url = "https://issuer.example/token"
      )@issuer,
      issuer
    )
    expect_identical(
      .discover_build_request(issuer)[["url"]],
      paste0(issuer, "/.well-known/openid-configuration")
    )
  }
})
