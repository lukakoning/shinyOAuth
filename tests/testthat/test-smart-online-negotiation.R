online_negotiation_client <- function(policy = "online_only", required = "online_access") {
  discovery <- smart_client_fixture()
  discovery$metadata$capabilities <- c(discovery$metadata$capabilities,
    list("permission-online", "permission-offline"))
  smart_client(discovery, "example", "https://app.example/callback",
    scopes = c("user/Patient.r", "online_access"), launch = "ehr",
    required_scopes = c("user/Patient.r", required), online_access_policy = policy)
}

test_that("online negotiation requires an explicit persistence choice", {
  grant <- function(scope) list(access_token = "access", token_type = "Bearer",
    expires_in = 300, scope = scope)
  for (required in list("online_access", character())) {
    client <- online_negotiation_client(required = required)
    expect_error(verify_token_set(client, grant("user/Patient.r offline_access"), NULL),
      "offline negotiation")
    expect_no_error(verify_token_set(client, grant("user/Patient.r online_access"), NULL))
  }
  client <- online_negotiation_client("allow_offline")
  token <- verify_token_set(client, grant("user/Patient.r offline_access"), NULL)
  expect_setequal(token$granted_scopes, c("user/Patient.r", "offline_access"))
  expect_true(token$granted_scopes_verified)
  expect_identical(client_scope_coverage(client, client@scopes,
    c(token$granted_scopes, "launch"))$status, "covered")
  expect_error(verify_token_set(client, grant("user/Observation.r offline_access"), NULL),
    "required permissions")
  expect_identical(smart_scope_coverage("online_access", "offline_access")$status,
    "insufficient")
  expect_error({ client@smart[["online_access_policy"]] <- "automatic" }, "online_access_policy")
})

test_that("negotiated refresh permissions retain directional scope continuity", {
  client <- online_negotiation_client("allow_offline")
  response_scope <- "user/Patient.r offline_access"
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req$url, status = 200,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(list(access_token = "new-access",
        refresh_token = "rotated", token_type = "Bearer", expires_in = 300,
        scope = response_scope), auto_unbox = TRUE)))
  }, .package = "shinyOAuth")
  token <- OAuthToken(access_token = "access", refresh_token = "refresh",
    expires_at = as.numeric(Sys.time()) + 300,
    granted_scopes = c("user/Patient.r", "offline_access"), granted_scopes_verified = TRUE)
  token <- smart_update_token_context(client, token)
  refreshed <- refresh_token(client, token)
  expect_identical(refreshed@refresh_token, "rotated")
  expect_setequal(refreshed@granted_scopes, token@granted_scopes)
  response_scope <- "user/Patient.r online_access"
  online <- refresh_token(client, refreshed)
  expect_setequal(online@granted_scopes, c("user/Patient.r", "online_access"))
  response_scope <- "user/Patient.r offline_access"
  expect_error(refresh_token(client, online), "prior grant")
})
