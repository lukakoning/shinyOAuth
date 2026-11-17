mtls_logs_fixture <- function(
  module,
  suite_id,
  expectation,
  method = "private_key_jwt",
  oidc = FALSE
) {
  f <- fapi_logs_fixture(module, suite_id, expectation, oauth_only = !oidc)
  f[["plan"]][["spec"]][["plan_variant"]][["client_auth_type"]] <- method
  f[["plan"]][["credentials"]][["mtls"]] <- list(fingerprint = strrep("a", 40L))
  if (
    !expectation[["outcome"]] %in% c("discovery_rejected", "callback_rejected")
  ) {
    f[["logs"]] <- c(
      f[["logs"]],
      list(list(
        testId = suite_id,
        http = "incoming",
        incoming_path = if (oidc) {
          "/test/a/fapi/.well-known/openid-configuration"
        } else {
          "/.well-known/oauth-authorization-server/test/a/fapi"
        },
        incoming_method = "GET",
        incoming_headers = list()
      ))
    )
  }
  fallback <- endsWith(module, "happy-path-no-mtls-endpoint-aliases")
  peers <- list()
  for (i in seq_along(f[["logs"]])) {
    event <- f[["logs"]][[i]]
    if (identical(event[["http"]], "incoming")) {
      path <- event[["incoming_path"]]
      endpoint <- sub("^/test/a/fapi/", "", path)
      mtls <- endpoint %in%
        c("token", "userinfo", "open-banking/v1.1/accounts") ||
        (identical(endpoint, "par") && (!fallback || method == "mtls"))
      if (mtls) {
        event[["incoming_path"]] <- sub("^/test/", "/test-mtls/", path)
      }
      event[["incoming_headers"]][["dpop"]] <- NULL
      if (oidc && identical(endpoint, "par")) {
        event[["incoming_body_form_params"]][["nonce"]] <- "DO_NOT_EXPORT_NONCE"
      }
      if (method == "mtls") {
        event[["incoming_body_form_params"]][["client_assertion"]] <- NULL
        event[["incoming_body_form_params"]][["client_assertion_type"]] <- NULL
      }
      if (endpoint %in% c("userinfo", "open-banking/v1.1/accounts")) {
        event[["incoming_headers"]][[
          "authorization"
        ]] <- "Bearer DO_NOT_EXPORT_ACCESS_TOKEN"
      }
      event[["incoming_headers"]][["x-openid-request-id"]] <- paste0("peer-", i)
      peers[[length(peers) + 1L]] <- list(
        request_id = paste0("peer-", i),
        path = event[["incoming_path"]],
        method = event[["incoming_method"]],
        listener = if (mtls) 8444L else 8443L,
        fingerprint = if (mtls) strrep("a", 40L) else ""
      )
    }
    if (identical(event[["src"]], "CreateTokenEndpointResponse")) {
      event[["Created token endpoint response"]][["token_type"]] <- "Bearer"
    }
    f[["logs"]][[i]] <- event
  }
  # Remove the DPoP fixture's nonce retries from this mTLS exchange.
  for (endpoint in c("/token", "/userinfo", "/open-banking/v1.1/accounts")) {
    retries <- which(vapply(
      f[["logs"]],
      function(e) {
        identical(e[["http"]], "incoming") &&
          endsWith(e[["incoming_path"]], endpoint)
      },
      logical(1)
    ))
    if (length(retries) > 1L) f[["logs"]] <- f[["logs"]][-retries[-1L]]
  }
  if (
    oidc &&
      !expectation[["outcome"]] %in%
        c("discovery_rejected", "callback_rejected")
  ) {
    claims <- list(
      iss = f[["module"]][["issuer"]],
      aud = "DO_NOT_EXPORT_CLIENT",
      iat = 1700000000L,
      exp = 1700000300L,
      nonce = "DO_NOT_EXPORT_NONCE"
    )
    fault <- sub("^fapi2-security-profile-final-client-test-", "", module)
    if (fault == "invalid-iss") {
      claims[["iss"]] <- "https://invalid.example"
    }
    if (fault == "invalid-aud") {
      claims[["aud"]] <- "untrusted-client"
    }
    if (fault == "invalid-secondary-aud") {
      claims[["aud"]] <- list("DO_NOT_EXPORT_CLIENT", "untrusted-client")
    }
    if (fault == "valid-aud-as-array") {
      claims[["aud"]] <- list("DO_NOT_EXPORT_CLIENT")
    }
    if (fault == "invalid-missing-iss") {
      claims[["iss"]] <- NULL
    }
    if (fault == "invalid-missing-aud") {
      claims[["aud"]] <- NULL
    }
    if (fault == "invalid-missing-exp") {
      claims[["exp"]] <- NULL
    }
    if (fault == "invalid-expired-exp") {
      claims[["exp"]] <- claims[["iat"]] - 600L
    }
    if (fault == "invalid-nonce") {
      claims[["nonce"]] <- "different-nonce"
    }
    if (fault == "invalid-missing-nonce") {
      claims[["nonce"]] <- NULL
    }
    alg <- switch(
      fault,
      `invalid-null-alg` = "none",
      `invalid-alternate-alg` = "RS256",
      "ES256"
    )
    id <- f[["jwt"]](list(alg = alg), claims)
    if (alg == "none") {
      id <- sub("signature$", "", id)
    }
    f[["logs"]] <- c(
      f[["logs"]],
      list(list(
        testId = suite_id,
        src = "CreateTokenEndpointResponse",
        result = "SUCCESS",
        `Created token endpoint response` = list(
          access_token = "DO_NOT_EXPORT_ACCESS_TOKEN",
          token_type = "Bearer",
          id_token = id
        )
      ))
    )
  }
  checks <- openid_mtls_checks(
    identical(expectation[["outcome"]], "discovery_rejected"),
    identical(expectation[["outcome"]], "callback_rejected"),
    fallback,
    method,
    oidc,
    oidc && identical(expectation[["outcome"]], "rejected")
  )
  f[["logs"]] <- c(
    f[["logs"]],
    lapply(setdiff(checks, openid_fapi_pre_token_checks(TRUE)), function(src) {
      if (src %in% names(openid_mtls_info_checks())) {
        return(list(
          testId = suite_id,
          src = src,
          msg = unname(openid_mtls_info_checks()[[src]])
        ))
      }
      list(testId = suite_id, src = src, result = "SUCCESS")
    })
  )
  request_ids <- vapply(
    Filter(function(e) identical(e[["http"]], "incoming"), f[["logs"]]),
    function(e) e[["incoming_headers"]][["x-openid-request-id"]],
    character(1)
  )
  f[["peers"]] <- Filter(function(p) p[["request_id"]] %in% request_ids, peers)
  f
}

mtls_evidence_fixture <- function(
  backend = "sync",
  profile = "fapi-oauth-mtls"
) {
  f <- fapi_full_fixture(backend, profile)
  expected <- f[["manifest"]][["profiles"]][[profile]][["modules"]]
  method <- openid_plan_spec(f[["manifest"]], profile)[["plan_variant"]][[
    "client_auth_type"
  ]]
  oidc <- identical(
    openid_plan_spec(f[["manifest"]], profile)[["plan_variant"]][[
      "fapi_client_type"
    ]],
    "oidc"
  )
  for (i in seq_along(expected)) {
    row <- f[["report"]][["results"]][[i]]
    row[["app"]][["mtls_configured"]] <- !identical(
      expected[[i]][["action"]],
      "discovery"
    )
    logs <- mtls_logs_fixture(
      row[["module"]],
      row[["suite_id"]],
      expected[[i]],
      method,
      oidc
    )
    row[["fapi"]] <- openid_mtls_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]],
      logs[["peers"]],
      expected[[i]]
    )
    f[["report"]][["results"]][[i]] <- row
  }
  f[["report"]][["mtls_controls"]] <- lapply(
    c("wrong", "forged_header", "missing"),
    function(kind) {
      row <- f[["report"]][["results"]][[1L]]
      row[["suite_id"]] <- paste0("control", kind)
      row[["app"]][["run_id"]] <- paste0(
        f[["context"]][["run_id"]],
        "-",
        row[["suite_id"]]
      )
      row[["suite_result"]] <- "FAILED"
      row[["suite_status"]] <- if (kind == "missing") {
        "INTERRUPTED"
      } else {
        "FINISHED"
      }
      row[["app"]][["resource"]][["api"]] <- "raw_attacker_request"
      row[["app"]][["resource"]][["control_kind"]] <- kind
      row[["app"]][["resource"]][["http_status"]] <- if (kind == "missing") {
        400L
      } else {
        200L
      }
      row[["app"]][["resource"]][["response_marker_valid"]] <- kind != "missing"
      row[["mtls_control"]] <- list(
        kind = kind,
        actual_peer_verified = TRUE,
        suite_detected = TRUE
      )
      row
    }
  )
  f
}

testthat::test_that("OIDC mTLS evidence binds returned ID tokens, nonces and UserInfo peers", {
  for (profile in c("fapi-mtls", "fapi-mtls-auth")) {
    f <- mtls_evidence_fixture("mirai", profile)
    expected <- f[["manifest"]][["profiles"]][[profile]][["modules"]]
    method <- openid_plan_spec(f[["manifest"]], profile)[["plan_variant"]][[
      "client_auth_type"
    ]]
    for (i in seq_along(expected)) {
      row <- f[["report"]][["results"]][[i]]
      logs <- mtls_logs_fixture(
        row[["module"]],
        row[["suite_id"]],
        expected[[i]],
        method,
        TRUE
      )
      collect <- function(events = logs[["logs"]], peers = logs[["peers"]]) {
        result <- row
        result[["fapi"]] <- openid_mtls_evidence(
          events,
          logs[["module"]],
          logs[["plan"]],
          peers,
          expected[[i]]
        )
        openid_mtls_matches(result, expected[[i]])
      }
      testthat::expect_true(collect(), info = row[["module"]])
      body_index <- which(vapply(
        logs[["logs"]],
        function(e) identical(e[["src"]], "CreateTokenEndpointResponse"),
        logical(1)
      ))
      if (length(body_index)) {
        events <- logs[["logs"]]
        events[[body_index]][["Created token endpoint response"]][[
          "id_token"
        ]] <- NULL
        testthat::expect_false(collect(events))
        events <- logs[["logs"]]
        events[[body_index]][["Created token endpoint response"]][[
          "id_token"
        ]] <- logs[["jwt"]](
          list(alg = "ES256"),
          list(iss = "wrong", nonce = "wrong")
        )
        testthat::expect_false(collect(events))
        testthat::expect_false(collect(c(
          logs[["logs"]],
          logs[["logs"]][body_index]
        )))
        result <- row
        result[["fapi"]][["id_token_nonce_result"]] <- "unrelated"
        testthat::expect_false(openid_mtls_matches(result, expected[[i]]))
      }
      par_index <- which(vapply(
        logs[["logs"]],
        function(e) {
          identical(e[["http"]], "incoming") &&
            endsWith(e[["incoming_path"]], "/par")
        },
        logical(1)
      ))
      if (length(par_index)) {
        events <- logs[["logs"]]
        events[[par_index]][["incoming_body_form_params"]][["nonce"]] <- NULL
        testthat::expect_false(collect(events))
      }
      userinfo_index <- which(vapply(
        logs[["peers"]],
        function(p) endsWith(p[["path"]], "/userinfo"),
        logical(1)
      ))
      for (j in userinfo_index) {
        for (field in c(
          "fingerprint",
          "request_id",
          "listener",
          "path",
          "method"
        )) {
          peers <- logs[["peers"]]
          peers[[j]][[field]] <- if (field == "listener") 8443L else "wrong"
          testthat::expect_false(collect(peers = peers), info = field)
        }
      }
      text <- as.character(jsonlite::toJSON(row[["fapi"]], auto_unbox = TRUE))
      testthat::expect_false(grepl(
        "DO_NOT_EXPORT|BEGIN CERTIFICATE|PRIVATE KEY|fingerprint",
        text
      ))
    }
    report <- f[["report"]]
    report[["mtls_controls"]][[1L]][["variant"]][[
      "fapi_client_type"
    ]] <- "plain_oauth"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("mTLS selection requires all resolved modules and peer evidence in either transport", {
  for (profile in c(
    "fapi-oauth-mtls",
    "fapi-oauth-mtls-auth",
    "fapi-mtls",
    "fapi-mtls-auth"
  )) {
    for (backend in c("sync", "mirai")) {
      f <- mtls_evidence_fixture(backend, profile)
      check <- function(report) {
        openid_check_report(report, f[["context"]], f[["manifest"]])
      }
      result <- check(f[["report"]])
      testthat::expect_true(result[["gate_passed"]], info = result[["reason"]])
      testthat::expect_false(result[["coverage_complete"]])
      expected <- f[["manifest"]][["profiles"]][[profile]][["modules"]]
      oidc <- startsWith(profile, "fapi-mtls")
      jwt <- !endsWith(profile, "-auth")
      testthat::expect_length(f[["report"]][["results"]], length(expected))
      for (i in seq_along(expected)) {
        report <- f[["report"]]
        report[["results"]] <- report[["results"]][-i]
        testthat::expect_false(check(report)[["gate_passed"]])
        required <- c(
          "suite_id",
          "client_authentication",
          "sender_constraint",
          "stage",
          "suite_checks",
          "discovery_request_count",
          "par_request_count",
          "token_request_count",
          "resource_request_count",
          "userinfo_request_count",
          "authorization_request_count"
        )
        if (!identical(expected[[i]][["action"]], "discovery")) {
          required <- c(
            required,
            if (oidc) "oidc_scope_nonce_valid" else "oauth_scope_valid",
            "request_credentials_valid",
            if (jwt) {
              c("assertion_metadata_valid", "assertion_jtis_distinct")
            },
            "authorization_par_only",
            "pkce_s256_verified",
            "endpoint_selection_valid",
            "par_peer_valid",
            "no_dpop",
            "state_characters",
            "state_reference_valid"
          )
          if (!identical(expected[[i]][["outcome"]], "callback_rejected")) {
            required <- c(
              required,
              "token_peer_valid",
              if (oidc) {
                c(
                  "oidc_token_response_observed",
                  "id_token_variant_observed",
                  "id_token_nonce_result"
                )
              } else {
                "token_response_oauth_only"
              },
              if (expected[[i]][["outcome"]] != "rejected") {
                c("resource_peer_valid", "resource_bearer_valid")
              },
              if (oidc && expected[[i]][["outcome"]] != "rejected") {
                c(
                  "userinfo_peer_valid",
                  "userinfo_endpoint_valid",
                  "issued_bearer_tokens_valid"
                )
              }
            )
          }
        }
        for (field in required) {
          report <- f[["report"]]
          report[["results"]][[i]][["fapi"]][[field]] <- NULL
          testthat::expect_false(check(report)[["gate_passed"]], info = field)
        }
        for (verdict in c("FAILED", "WARNING", "SKIPPED", "REVIEW")) {
          report <- f[["report"]]
          report[["results"]][[i]][["suite_result"]] <- verdict
          testthat::expect_false(check(report)[["gate_passed"]])
        }
      }
    }
  }
})

testthat::test_that("mTLS proof binds each suite request to the actual TLS listener and certificate", {
  f <- mtls_evidence_fixture()
  e <- f[["manifest"]][["profiles"]][["fapi-oauth-mtls"]][["modules"]][[1L]]
  row <- f[["report"]][["results"]][[1L]]
  logs <- mtls_logs_fixture(row[["module"]], row[["suite_id"]], e)
  for (i in seq_along(logs[["peers"]])) {
    if (!identical(logs[["peers"]][[i]][["listener"]], 8444L)) {
      next
    }
    for (field in c(
      "request_id",
      "path",
      "method",
      "listener",
      "fingerprint"
    )) {
      peers <- logs[["peers"]]
      peers[[i]][[field]] <- if (field == "listener") 8443L else "wrong"
      result <- row
      result[["fapi"]] <- openid_mtls_evidence(
        logs[["logs"]],
        logs[["module"]],
        logs[["plan"]],
        peers
      )
      testthat::expect_false(openid_mtls_matches(result, e), info = field)
    }
  }
  result <- row
  result[["fapi"]] <- openid_mtls_evidence(
    logs[["logs"]],
    logs[["module"]],
    logs[["plan"]],
    list()
  )
  testthat::expect_false(openid_mtls_matches(result, e))
  testthat::expect_error(
    openid_mtls_evidence(
      list(list(testId = "other")),
      logs[["module"]],
      logs[["plan"]],
      logs[["peers"]]
    ),
    "suite instance"
  )
  text <- as.character(jsonlite::toJSON(row[["fapi"]], auto_unbox = TRUE))
  testthat::expect_false(grepl(
    "DO_NOT_EXPORT|BEGIN CERTIFICATE|PRIVATE KEY|fingerprint",
    text
  ))
})

testthat::test_that("mTLS controls retain separate failed instances and cannot claim resource denial", {
  f <- mtls_evidence_fixture()
  check <- function(report) {
    openid_check_report(report, f[["context"]], f[["manifest"]])
  }
  for (i in seq_len(3L)) {
    report <- f[["report"]]
    report[["mtls_controls"]] <- report[["mtls_controls"]][-i]
    testthat::expect_false(check(report)[["gate_passed"]])
    for (field in c(
      "suite_id",
      "run_id",
      "attempt_id",
      "checkout_revision",
      "source_revision",
      "plan_id",
      "suite_status",
      "suite_result",
      "mtls_control",
      "app",
      "variant"
    )) {
      report <- f[["report"]]
      report[["mtls_controls"]][[i]][[field]] <- NULL
      testthat::expect_false(check(report)[["gate_passed"]], info = field)
    }
    for (field in c("kind", "actual_peer_verified", "suite_detected")) {
      report <- f[["report"]]
      report[["mtls_controls"]][[i]][["mtls_control"]][[field]] <- NULL
      testthat::expect_false(check(report)[["gate_passed"]], info = field)
    }
    for (field in c(
      "api",
      "control_kind",
      "done",
      "http_status",
      "response_marker_valid"
    )) {
      report <- f[["report"]]
      report[["mtls_controls"]][[i]][["app"]][["resource"]][[field]] <- NULL
      testthat::expect_false(check(report)[["gate_passed"]], info = field)
    }
    report <- f[["report"]]
    report[["mtls_controls"]][[i]][["suite_id"]] <- report[["results"]][[1L]][[
      "suite_id"
    ]]
    testthat::expect_false(check(report)[["gate_passed"]])
    report <- f[["report"]]
    report[["mtls_controls"]][[i]][["variant"]][["fapi_client_type"]] <- "oidc"
    testthat::expect_false(check(report)[["gate_passed"]])
  }
  manifest <- f[["manifest"]]
  manifest[["profiles"]][["fapi-oauth-mtls"]][["complete_profile"]] <- TRUE
  manifest[["profiles"]][["fapi-oauth-mtls"]][[
    "coverage_limitations"
  ]] <- list()
  result <- openid_check_report(f[["report"]], f[["context"]], manifest)
  testthat::expect_true(result[["gate_passed"]])
  testthat::expect_false(result[["coverage_complete"]])
  testthat::expect_contains(
    unlist(result[["coverage_limitations"]]),
    "mtls_resource_denial_not_established"
  )
})

testthat::test_that("alias fallback requires the pinned informational setup events", {
  f <- mtls_evidence_fixture()
  e <- f[["manifest"]][["profiles"]][["fapi-oauth-mtls"]][["modules"]][[9L]]
  row <- f[["report"]][["results"]][[9L]]
  fixture <- mtls_logs_fixture(row[["module"]], row[["suite_id"]], e)
  for (src in intersect(
    names(openid_mtls_info_checks()),
    names(row[["fapi"]][["suite_checks"]])
  )) {
    index <- which(vapply(
      fixture[["logs"]],
      function(event) identical(event[["src"]], src),
      logical(1)
    ))
    for (field in c("src", "msg", "result")) {
      logs <- fixture[["logs"]]
      logs[[index]][[field]] <- "wrong"
      result <- row
      result[["fapi"]] <- openid_mtls_evidence(
        logs,
        fixture[["module"]],
        fixture[["plan"]],
        fixture[["peers"]]
      )
      testthat::expect_false(openid_mtls_matches(result, e), info = field)
    }
  }
})

testthat::test_that("mTLS authentication requires certificate peers and client_id without other credentials", {
  f <- mtls_evidence_fixture("sync", "fapi-oauth-mtls-auth")
  expected <- f[["manifest"]][["profiles"]][["fapi-oauth-mtls-auth"]][[
    "modules"
  ]]
  for (i in c(1L, 3L, 9L)) {
    row <- f[["report"]][["results"]][[i]]
    logs <- mtls_logs_fixture(
      row[["module"]],
      row[["suite_id"]],
      expected[[i]],
      "mtls"
    )
    testthat::expect_true(openid_mtls_matches(row, expected[[i]]))
    testthat::expect_identical(
      row[["fapi"]][["client_authentication"]],
      "tls_client_auth"
    )
    testthat::expect_null(row[["fapi"]][["assertion_metadata_valid"]])
    testthat::expect_false(any(grepl(
      "ValidateClientAssertion|ExtractClientAssertion|CheckForClientAssertion",
      names(row[["fapi"]][["suite_checks"]])
    )))
    for (j in seq_along(logs[["logs"]])) {
      event <- logs[["logs"]][[j]]
      if (
        !identical(event[["http"]], "incoming") ||
          !any(endsWith(event[["incoming_path"]], c("/par", "/token")))
      ) {
        next
      }
      for (field in c(
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type"
      )) {
        changed <- logs[["logs"]]
        changed[[j]][["incoming_body_form_params"]][[field]] <- "wrong"
        result <- row
        result[["fapi"]] <- openid_mtls_evidence(
          changed,
          logs[["module"]],
          logs[["plan"]],
          logs[["peers"]]
        )
        testthat::expect_false(
          openid_mtls_matches(result, expected[[i]]),
          info = field
        )
      }
      changed <- logs[["logs"]]
      changed[[j]][["incoming_body_form_params"]][["client_id"]] <- NULL
      result <- row
      result[["fapi"]] <- openid_mtls_evidence(
        changed,
        logs[["module"]],
        logs[["plan"]],
        logs[["peers"]]
      )
      testthat::expect_false(openid_mtls_matches(result, expected[[i]]))
      changed <- logs[["logs"]]
      changed[[j]][["incoming_headers"]][["authorization"]] <- "Basic unwanted"
      result[["fapi"]] <- openid_mtls_evidence(
        changed,
        logs[["module"]],
        logs[["plan"]],
        logs[["peers"]]
      )
      testthat::expect_false(openid_mtls_matches(result, expected[[i]]))
    }
    for (j in seq_along(logs[["peers"]])) {
      peer <- logs[["peers"]][[j]]
      if (!any(endsWith(peer[["path"]], c("/par", "/token")))) {
        next
      }
      for (field in c("fingerprint", "listener")) {
        peers <- logs[["peers"]]
        peers[[j]][[field]] <- if (field == "listener") 8443L else "wrong"
        result <- row
        result[["fapi"]] <- openid_mtls_evidence(
          logs[["logs"]],
          logs[["module"]],
          logs[["plan"]],
          peers
        )
        testthat::expect_false(
          openid_mtls_matches(result, expected[[i]]),
          info = field
        )
      }
    }
    checks <- c(
      "AddTLSClientAuthToServerConfiguration",
      "EnsureClientIdIsPresentOnTokenRequest",
      "EnsureNoClientAssertionSentToTokenEndpoint",
      if (i == 9L) "SetParEndpointToMtlsParEndpoint"
    )
    for (src in checks) {
      changed <- logs[["logs"]]
      for (j in seq_along(changed)) {
        if (identical(changed[[j]][["src"]], src)) {
          changed[[j]][["src"]] <- "wrong"
        }
      }
      result <- row
      result[["fapi"]] <- openid_mtls_evidence(
        changed,
        logs[["module"]],
        logs[["plan"]],
        logs[["peers"]]
      )
      testthat::expect_false(
        openid_mtls_matches(result, expected[[i]]),
        info = src
      )
    }
  }
  report <- f[["report"]]
  report[["mtls_controls"]][[1L]][["variant"]][[
    "client_auth_type"
  ]] <- "private_key_jwt"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  manifest <- f[["manifest"]]
  manifest[["profiles"]][["fapi-oauth-mtls-auth"]][["complete_profile"]] <- TRUE
  manifest[["profiles"]][["fapi-oauth-mtls-auth"]][[
    "coverage_limitations"
  ]] <- list()
  check <- openid_check_report(f[["report"]], f[["context"]], manifest)
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_false(check[["coverage_complete"]])
  testthat::expect_contains(
    unlist(check[["coverage_limitations"]]),
    "suite_exact_certificate_registration_only"
  )
  testthat::expect_contains(
    unlist(check[["coverage_limitations"]]),
    "mtls_client_authentication_denial_not_tested"
  )
})
