test_that("Microsoft resource prefixes cannot make permission ownership ambiguous", {
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  make <- function(resources, static = FALSE) {
    targets <- stats::setNames(
      lapply(seq_along(resources), function(i) {
        list(
          resource = resources[[i]],
          scopes = paste0(
            resources[[i]],
            if (static) "/.default" else "/Reports/Read"
          )
        )
      }),
      paste0("api", seq_along(resources))
    )
    oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = unlist(lapply(targets, function(target) target[["scopes"]])),
      token_targets = targets,
      default_token_target = "api1"
    )
  }
  for (static in c(FALSE, TRUE)) {
    for (resources in list(
      c("https://contoso.example", "https://contoso.example/Reports"),
      c("https://contoso.example/Reports", "https://contoso.example"),
      c("api://resource", "api://resource/reports"),
      c("urn:resource", "urn:resource/reports")
    )) {
      expect_error(make(resources, static), "overlapping scope prefixes")
    }
    for (resources in list(
      c("api://resource", "api://resource2"),
      c("api://resource/reports", "api://resource/reporting"),
      c("api://resource", "api://resource")
    )) {
      client <- make(resources, static)
      expect_true(token_target_scopes_allowed(
        client,
        "api1",
        paste0(resources[[1L]], "/REPORTS/READ")
      ))
      if (!identical(resources[[1L]], resources[[2L]])) {
        expect_error(
          validate_token_target_grant(
            client,
            paste0(resources[[2L]], "/Reports/Read"),
            token_target_request(client)
          ),
          "scope limit"
        )
      }
    }
  }
  # RFC 8707 resources are explicit token-request parameters, so they can nest.
  provider@token_target_mode <- "rfc8707"
  expect_s7_class(make(c("urn:resource", "urn:resource/reports")), OAuthClient)
})
