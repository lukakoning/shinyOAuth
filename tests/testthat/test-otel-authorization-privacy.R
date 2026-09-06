test_that("authorization names are omitted from real spans unless explicitly enabled", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  withr::local_options(shinyOAuth.otel_tracing_enabled = TRUE)
  client <- make_test_client(
    use_nonce = TRUE,
    scopes = c("openid", "tenant-health-read"),
    claims = list(id_token = list(email = NULL))
  )
  client@provider@id_token_validation <- TRUE
  client@required_acr_values <- "urn:finance:stepup"
  for (details in list(NULL, FALSE, TRUE)) {
    withr::local_options(
      shinyOAuth.otel_include_authorization_details = details
    )
    record <- otelsdk::with_otel_record({
      prepare_call(client, valid_browser_token())
    })
    attrs <- record$traces[["shinyOAuth.login.request"]]$attributes
    expect_identical(as.integer(attrs[["oauth.scopes.requested_count"]]), 2L)
    expect_identical(as.integer(attrs[["oauth.claims.targets_count"]]), 1L)
    expect_identical(as.integer(attrs[["oauth.required_acr_values_count"]]), 1L)
    if (isTRUE(details)) {
      expect_identical(
        attrs[["oauth.scopes.requested"]],
        "openid tenant-health-read"
      )
      expect_identical(attrs[["oauth.claims.targets"]], "id_token")
      expect_identical(
        attrs[["oauth.required_acr_values"]],
        "urn:finance:stepup"
      )
    } else {
      expect_null(attrs[["oauth.scopes.requested"]])
      expect_null(attrs[["oauth.claims.targets"]])
      expect_null(attrs[["oauth.required_acr_values"]])
      for (span in record$traces) {
        expect_false(any(grepl(
          "tenant-health-read|urn:finance:stepup",
          unlist(span$attributes)
        )))
      }
    }
  }
})

test_that("worker telemetry gates reset stale authorization-detail opt-ins", {
  withr::local_options(shinyOAuth.otel_include_authorization_details = NULL)
  gates <- capture_async_otel_option_gates()
  expect_identical(gates$shinyOAuth.otel_include_authorization_details, FALSE)
  withr::with_options(
    list(shinyOAuth.otel_include_authorization_details = TRUE),
    {
      previous <- apply_async_otel_option_gates(gates)
      expect_null(otel_scope_string("private-scope"))
      expect_null(otel_claim_targets(list(private_target = list())))
      expect_null(otel_required_acr_values("private-acr"))
      expect_identical(
        otel_claim_target_count(list(private_target = list())),
        1L
      )
      restore_async_otel_option_gates(previous$old_options)
      expect_identical(otel_scope_string("private-scope"), "private-scope")
    }
  )
})
