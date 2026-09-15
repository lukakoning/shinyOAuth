online_negotiation_client <- function(
  policy = "online_only",
  required = "online_access",
  scopes = c("user/Patient.r", "online_access")
) {
  discovery <- smart_client_fixture()
  discovery[["metadata"]][["capabilities"]] <- c(
    discovery[["metadata"]][["capabilities"]],
    list("permission-online", "permission-offline")
  )
  smart_client(
    discovery,
    "example",
    "https://app.example/callback",
    scopes = scopes,
    launch = "ehr",
    required_scopes = c("user/Patient.r", required),
    online_access_policy = policy
  )
}

test_that("online negotiation requires an explicit persistence choice", {
  grant <- function(scope) {
    list(
      access_token = "access",
      token_type = "Bearer",
      expires_in = 300,
      scope = scope
    )
  }
  for (required in list("online_access", character())) {
    client <- online_negotiation_client(required = required)
    expect_error(
      verify_token_set(client, grant("user/Patient.r offline_access"), NULL),
      "offline negotiation"
    )
    expect_no_error(verify_token_set(
      client,
      grant("user/Patient.r online_access"),
      NULL
    ))
  }
  client <- online_negotiation_client("allow_offline")
  token <- verify_token_set(
    client,
    grant("user/Patient.r offline_access"),
    NULL
  )
  expect_setequal(
    token[["granted_scopes"]],
    c("user/Patient.r", "offline_access")
  )
  expect_true(token[["granted_scopes_verified"]])
  expect_identical(
    client_scope_coverage(
      client,
      client@scopes,
      c(token[["granted_scopes"]], "launch")
    )[["status"]],
    "covered"
  )
  expect_error(
    verify_token_set(client, grant("user/Observation.r offline_access"), NULL),
    "required permissions"
  )
  expect_identical(
    smart_scope_coverage("online_access", "offline_access")[["status"]],
    "insufficient"
  )
  expect_error(
    {
      client@smart[["online_access_policy"]] <- "automatic"
    },
    "online_access_policy"
  )
})

test_that("explicit refresh narrowing retains negotiated offline access on the wire", {
  client <- online_negotiation_client(
    "allow_offline",
    scopes = c("user/Patient.rs", "online_access")
  )
  accepted <- verify_token_set(
    client,
    list(
      access_token = "access",
      token_type = "Bearer",
      expires_in = 300,
      scope = "user/Patient.rs offline_access"
    ),
    NULL
  )
  token <- OAuthToken(
    access_token = "access",
    refresh_token = "refresh",
    expires_at = as.numeric(Sys.time()) + 300,
    granted_scopes = accepted[["granted_scopes"]],
    granted_scopes_verified = accepted[["granted_scopes_verified"]]
  )
  token <- smart_update_token_context(client, token)
  scopes <- c("user/Patient.r", "offline_access")
  request <- refresh_scope_request(client, token, scopes)
  expect_setequal(request[["scopes"]], scopes)
  expect_no_error(validate_refresh_scope_request(
    prepare_client_for_worker(client),
    token,
    request
  ))
  seen <- NULL
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      seen <<- req[["body"]][["data"]]
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "new-access",
            refresh_token = "rotated",
            token_type = "Bearer",
            expires_in = 300,
            scope = paste(scopes, collapse = " ")
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  refreshed <- refresh_token_dispatch(client, token, scope_request = request)
  expect_identical(as.character(seen[["grant_type"]]), "refresh_token")
  expect_setequal(
    strsplit(utils::URLdecode(as.character(seen[["scope"]])), " ")[[1L]],
    scopes
  )
  expect_setequal(refreshed@granted_scopes, scopes)
  expect_identical(refreshed@refresh_token, "rotated")
  expect_identical(
    refreshed@original_granted_scopes,
    token@original_granted_scopes
  )
  expect_setequal(
    effective_client_scopes(client),
    c("user/Patient.rs", "online_access", "launch")
  )
  expect_error(
    refresh_scope_request(
      client,
      refreshed,
      c("user/Patient.rs", "offline_access")
    ),
    "covered"
  )
  expect_error(
    refresh_scope_request(client, refreshed, "user/Patient.r"),
    "required"
  )
})

test_that("negotiated refresh ceilings require opt-in and retain other scope limits", {
  scopes <- c("user/Patient.r", "offline_access")
  token <- OAuthToken(
    access_token = "access",
    granted_scopes = scopes,
    granted_scopes_verified = TRUE
  )
  expect_error(
    refresh_scope_request(online_negotiation_client(), token, scopes),
    "configuration"
  )
  client <- online_negotiation_client("allow_offline")
  online <- token
  online@granted_scopes <- c("user/Patient.r", "online_access")
  expect_error(refresh_scope_request(client, online, scopes), "covered")
  unrequested <- online_negotiation_client(
    "allow_offline",
    required = character(),
    scopes = "user/Patient.r"
  )
  expect_error(
    refresh_scope_request(unrequested, token, scopes),
    "configuration"
  )
  token@granted_scopes <- c("user/Patient.rs", "offline_access")
  expect_error(
    refresh_scope_request(client, token, token@granted_scopes),
    "configuration"
  )
  explicit <- online_negotiation_client(
    required = "offline_access",
    scopes = scopes
  )
  expect_setequal(
    refresh_scope_request(explicit, token, scopes)[["scopes"]],
    scopes
  )
})

test_that("negotiated refresh permissions retain directional scope continuity", {
  client <- online_negotiation_client("allow_offline")
  response_scope <- "user/Patient.r offline_access"
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "new-access",
            refresh_token = "rotated",
            token_type = "Bearer",
            expires_in = 300,
            scope = response_scope
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  token <- OAuthToken(
    access_token = "access",
    refresh_token = "refresh",
    expires_at = as.numeric(Sys.time()) + 300,
    granted_scopes = c("user/Patient.r", "offline_access"),
    granted_scopes_verified = TRUE
  )
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
