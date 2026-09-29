default_evidence_client <- function(introspect = FALSE) {
  provider <- make_test_provider()
  S7::props(provider) <- list(
    token_target_mode = "microsoft",
    introspection_url = "https://issuer.example/introspect"
  )
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("api://Primary/.default", "api://Secondary/.default"),
    introspect = introspect,
    introspection_checks = if (introspect) "scope" else character(),
    token_targets = list(
      primary = list(
        resource = "api://Primary",
        scopes = "api://Primary/.default"
      ),
      secondary = list(
        resource = "api://Secondary",
        scopes = "api://Secondary/.default"
      )
    ),
    default_token_target = "primary"
  )
}

test_that("Microsoft consent markers cannot become token or introspection grants", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (introspect in c(FALSE, TRUE)) {
    client <- default_evidence_client(introspect)
    evidence <- "Read"
    local_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(
            list(
              access_token = "access",
              refresh_token = "refresh",
              token_type = "Bearer",
              expires_in = 3600,
              scope = if (introspect) "Read" else evidence
            ),
            auto_unbox = TRUE
          ))
        )
      },
      introspect_token = function(...) {
        list(supported = TRUE, active = TRUE, raw = list(scope = evidence))
      }
    )
    browser <- valid_browser_token()
    exchange <- function() {
      url <- prepare_call(client, browser)
      handle_callback(client, "code", parse_query_param(url, "state"), browser)
    }
    token <- exchange()
    for (marker in c(".default", ".DEFAULT", ".Default", ".dEfAuLt")) {
      for (prefix in c("", "api://Primary/", "api://Primary/child/")) {
        evidence <- paste("Read", paste0(prefix, marker))
        expect_error(exchange(), "actual granted permissions")
        expect_error(refresh_token(client, token), "actual granted permissions")
      }
    }
    evidence <- "rEaD"
    fresh <- refresh_token(client, token)
    expect_identical(fresh@granted_scopes, "api://Primary/rEaD")
    record <- token_target_select(list(
      client = client,
      token = fresh,
      targets = token_target_bundle(client, fresh),
      status = "active"
    ))
    expect_true(connection_record_has_scopes(record, "api://Primary/read"))
    expect_false(connection_record_has_scopes(record, "api://Primary/.default"))
    expect_false(connection_record_has_scopes(record, "api://primary/read"))
  }
})

test_that("restored Microsoft target evidence rejects every consent marker spelling", {
  client <- default_evidence_client()
  primary <- manager_test_token()
  primary@granted_scopes <- "api://Primary/Read"
  secondary <- manager_test_token(access = "secondary", refresh = NA_character_)
  for (marker in c(".default", ".DEFAULT", ".Default", ".dEfAuLt")) {
    bundle <- token_target_bundle(client, primary)
    secondary@granted_scopes <- c(
      "api://Secondary/Read",
      paste0("api://Secondary/", marker)
    )
    bundle[["tokens"]][["secondary"]] <- secondary
    expect_error(
      token_target_bundle_decode(client, token_target_bundle_encode(bundle)),
      class = "shinyOAuth_token_error"
    )
    rejected <- primary
    rejected@granted_scopes <- paste0("api://Primary/", marker)
    expect_error(
      token_target_bundle(client, rejected),
      class = "shinyOAuth_token_error"
    )
  }
})

test_that("Microsoft declarations cannot disguise consent markers as API permissions", {
  for (marker in c(".DEFAULT", ".Default", ".dEfAuLt")) {
    client <- default_evidence_client()
    targets <- client@token_targets
    targets[["primary"]][["required_scopes"]] <- paste0(
      "api://Primary/",
      marker
    )
    expect_error(
      {
        client@token_targets <- targets
      },
      "actual API permissions"
    )
    targets[["primary"]][["required_scopes"]] <- NULL
    targets[["primary"]][["scope_aliases"]] <- paste0("child/", marker)
    expect_error(
      {
        client@token_targets <- targets
      },
      "scope_aliases"
    )
    targets[["primary"]][["scope_aliases"]] <- NULL
    targets[["primary"]][["scopes"]] <- paste0("api://Primary/", marker)
    expect_error(
      {
        S7::props(client) <- list(
          token_targets = targets,
          scopes = c(
            targets[["primary"]][["scopes"]],
            "api://Secondary/.default"
          )
        )
      },
      "exact resource"
    )
  }
})
