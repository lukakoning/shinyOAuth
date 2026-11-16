fapi_logs_fixture <- function(
  module_name,
  suite_id = "instance",
  expectation = NULL
) {
  positive <- if (is.null(expectation)) {
    !endsWith(module_name, "invalid-iss")
  } else {
    identical(expectation[["outcome"]], "authenticated")
  }
  no_nonce <- endsWith(module_name, "no-dpop-nonce")
  issuer <- "https://localhost:41000/test/a/fapi/"
  plan <- list(
    registration = list(client_id = "DO_NOT_EXPORT_CLIENT"),
    credentials = list(key_id = "DO_NOT_EXPORT_KID")
  )
  encode <- function(value) {
    sub(
      "=+$",
      "",
      chartr(
        "+/",
        "-_",
        as.character(openssl::base64_encode(charToRaw(as.character(jsonlite::toJSON(
          value,
          auto_unbox = TRUE
        )))))
      )
    )
  }
  jwt <- function(header, claims) {
    paste(encode(header), encode(claims), "signature", sep = ".")
  }
  number <- 0L
  request <- function(
    endpoint,
    method,
    form = NULL,
    query = NULL,
    dpop = FALSE,
    resource = FALSE,
    nonce = TRUE
  ) {
    number <<- number + 1L
    headers <- list()
    if (dpop) {
      claims <- list(
        htm = method,
        htu = paste0(issuer, endpoint),
        iat = 1700000000L,
        jti = paste0("DO_NOT_EXPORT_PROOF_", number)
      )
      if (!no_nonce && nonce) {
        claims[["nonce"]] <- "DO_NOT_EXPORT_NONCE"
      }
      if (resource) {
        headers[["authorization"]] <- "DPoP DO_NOT_EXPORT_ACCESS_TOKEN"
        claims[["ath"]] <- openid_fapi_hash("DO_NOT_EXPORT_ACCESS_TOKEN")
      }
      headers[["dpop"]] <- jwt(
        list(
          alg = "ES256",
          typ = "dpop+jwt",
          jwk = list(
            kty = "EC",
            crv = "P-256",
            x = "DO_NOT_EXPORT_X",
            y = "DO_NOT_EXPORT_Y"
          )
        ),
        claims
      )
    }
    if (!is.null(form)) {
      form[["client_id"]] <- plan[["registration"]][["client_id"]]
      form[[
        "client_assertion_type"
      ]] <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      form[["client_assertion"]] <- jwt(
        list(alg = "ES256", kid = plan[["credentials"]][["key_id"]]),
        list(
          iss = form[["client_id"]],
          sub = form[["client_id"]],
          aud = issuer,
          iat = 1700000000L,
          exp = 1700000060L,
          jti = paste0("DO_NOT_EXPORT_ASSERTION_", number)
        )
      )
    }
    list(
      testId = suite_id,
      http = "incoming",
      incoming_path = paste0("/test/a/fapi/", endpoint),
      incoming_method = method,
      incoming_body_form_params = form,
      incoming_query_string_params = query,
      incoming_headers = headers
    )
  }
  verifier <- strrep("a", 43L)
  logs <- list(
    request(
      "par",
      "POST",
      form = list(
        response_type = "code",
        code_challenge_method = "S256",
        code_challenge = openid_fapi_hash(verifier)
      )
    ),
    request(
      "authorize",
      "GET",
      query = list(
        client_id = plan[["registration"]][["client_id"]],
        request_uri = "DO_NOT_EXPORT_REQUEST_URI"
      )
    ),
    request(
      "token",
      "POST",
      form = list(grant_type = "authorization_code", code_verifier = verifier),
      dpop = TRUE,
      nonce = FALSE
    )
  )
  if (!no_nonce) {
    logs <- c(
      logs,
      list(request(
        "token",
        "POST",
        form = list(
          grant_type = "authorization_code",
          code_verifier = verifier
        ),
        dpop = TRUE
      ))
    )
  }
  if (positive) {
    logs <- c(
      logs,
      list(request(
        "userinfo",
        "GET",
        dpop = TRUE,
        resource = TRUE,
        nonce = FALSE
      ))
    )
    if (!no_nonce) {
      logs <- c(
        logs,
        list(request("userinfo", "GET", dpop = TRUE, resource = TRUE))
      )
    }
    logs <- c(
      logs,
      list(
        request(
          "open-banking/v1.1/accounts",
          "GET",
          dpop = TRUE,
          resource = TRUE
        )
      )
    )
  }
  checks <- c(
    openid_fapi_checks(positive, !no_nonce),
    if (!no_nonce) "CreateTokenEndpointDpopErrorResponse",
    if (!no_nonce && positive) "CreateResourceEndpointDpopErrorResponse"
  )
  logs <- c(
    logs,
    lapply(checks, function(source) {
      list(testId = suite_id, src = source, result = "SUCCESS")
    })
  )
  if (
    !is.null(expectation) &&
      expectation[["outcome"]] %in% c("discovery_rejected", "callback_rejected")
  ) {
    discovery <- identical(expectation[["outcome"]], "discovery_rejected")
    logs <- Filter(
      function(e) {
        identical(e[["http"]], "incoming") &&
          !discovery &&
          e[["incoming_path"]] %in%
            c("/test/a/fapi/par", "/test/a/fapi/authorize")
      },
      logs
    )
    logs <- c(
      list(request(".well-known/openid-configuration", "GET")),
      logs,
      lapply(openid_fapi_pre_token_checks(discovery), function(source) {
        event <- list(testId = suite_id, src = source)
        if (discovery) {
          event[["msg"]] <- "Added invalid issuer to server configuration"
          event[["issuer"]] <- paste0(issuer, "INVALID")
        } else {
          event[["result"]] <- "SUCCESS"
        }
        event
      })
    )
  }
  list(
    logs = logs,
    module = list(id = suite_id, issuer = issuer, name = module_name),
    plan = plan,
    expectation = if (is.null(expectation)) {
      list(outcome = if (positive) "authenticated" else "rejected")
    } else {
      expectation
    },
    jwt = jwt
  )
}

fapi_evidence_fixture <- function(backend = "sync") {
  f <- evidence_with_transport(evidence_fixture("fapi-dpop"), backend)
  for (i in seq_along(f[["report"]][["results"]])) {
    row <- f[["report"]][["results"]][[i]]
    logs <- fapi_logs_fixture(row[["module"]], row[["suite_id"]])
    row[["fapi"]] <- openid_fapi_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]],
      logs[["expectation"]]
    )
    if (identical(logs[["expectation"]][["outcome"]], "authenticated")) {
      row[["app"]][["resource"]] <- list(
        done = TRUE,
        succeeded = TRUE,
        response_marker_valid = TRUE,
        transport = "main_process",
        pid = 100L
      )
    }
    f[["report"]][["results"]][[i]] <- row
  }
  f
}

testthat::test_that("FAPI selection needs nonce and no-nonce resource flows and issuer rejection", {
  for (backend in c("sync", "mirai")) {
    f <- fapi_evidence_fixture(backend)
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["gate_passed"]])
    testthat::expect_false(check[["coverage_complete"]])
    for (i in 1:3) {
      report <- f[["report"]]
      report[["results"]] <- report[["results"]][-i]
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})

testthat::test_that("FAPI suite verdicts cannot replace protocol and resource proof", {
  f <- fapi_evidence_fixture()
  for (i in 1:3) {
    proof <- f[["report"]][["results"]][[i]][["fapi"]]
    for (name in names(proof)) {
      report <- f[["report"]]
      report[["results"]][[i]][["fapi"]][[name]] <- NULL
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (name in names(proof[["suite_checks"]])) {
      report <- f[["report"]]
      report[["results"]][[i]][["fapi"]][["suite_checks"]][[name]] <- FALSE
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
  for (name in c(
    "done",
    "succeeded",
    "response_marker_valid",
    "transport",
    "pid"
  )) {
    report <- f[["report"]]
    report[["results"]][[1L]][["app"]][["resource"]][[name]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("FAPI raw request checks reject wrong assertions, proofs and PKCE without disclosure", {
  f <- fapi_logs_fixture("fapi2-security-profile-final-client-test-happy-path")
  check <- function(logs) {
    proof <- tryCatch(
      openid_fapi_evidence(
        logs,
        f[["module"]],
        f[["plan"]],
        f[["expectation"]]
      ),
      error = function(...) NULL
    )
    row <- list(
      suite_id = "instance",
      module = f[["module"]][["name"]],
      fapi = proof,
      app = list(
        transport = list(app_pid = 100L),
        resource = list(
          done = TRUE,
          succeeded = TRUE,
          response_marker_valid = TRUE,
          pid = 100L,
          transport = "main_process"
        )
      )
    )
    if (!is.null(proof)) {
      testthat::expect_false(grepl(
        "DO_NOT_EXPORT",
        jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null"),
        fixed = TRUE
      ))
    }
    openid_fapi_matches(row, f[["expectation"]])
  }
  testthat::expect_true(check(f[["logs"]]))
  for (change in list(
    list(index = 1L, field = "client_secret", value = "DO_NOT_EXPORT_SECRET"),
    list(index = 3L, field = "code_verifier", value = strrep("b", 43L)),
    list(
      index = 3L,
      field = "client_assertion",
      value = "DO_NOT_EXPORT_BAD_ASSERTION"
    )
  )) {
    logs <- f[["logs"]]
    logs[[change[["index"]]]][["incoming_body_form_params"]][[change[[
      "field"
    ]]]] <- change[["value"]]
    testthat::expect_false(check(logs))
  }
  logs <- f[["logs"]]
  logs[[2L]][["incoming_query_string_params"]][["scope"]] <- "openid"
  testthat::expect_false(check(logs))
  logs <- f[["logs"]]
  logs[[5L]][["incoming_headers"]][[
    "authorization"
  ]] <- "DPoP DO_NOT_EXPORT_OTHER_TOKEN"
  testthat::expect_false(check(logs))
  logs <- f[["logs"]]
  logs[[1L]][["testId"]] <- "foreign"
  testthat::expect_false(check(logs))
  testthat::expect_false(check(c(f[["logs"]], f[["logs"]][2L])))
})

testthat::test_that("FAPI registration uses only the public ES256 key and freezes plan variants", {
  manifest <- openid_profiles("../..")
  spec <- openid_plan_spec(manifest, "fapi-dpop")
  registration <- NULL
  plan <- openid_suite_plan(
    list(),
    manifest,
    "https://localhost:42000/",
    "fapi-dpop",
    .request = function(stack, path, data, ...) {
      registration <<- data[["client"]]
      list(
        id = "plan",
        name = spec[["plan"]],
        modules = lapply(spec[["available_modules"]], function(module) {
          list(testModule = module, variant = spec[["module_variant"]])
        })
      )
    }
  )
  key <- registration[["jwks"]][["keys"]][[1L]]
  testthat::expect_identical(key[["alg"]], "ES256")
  testthat::expect_identical(key[["crv"]], "P-256")
  testthat::expect_null(key[["d"]])
  testthat::expect_null(registration[["client_secret"]])
  testthat::expect_identical(
    registration[["token_endpoint_auth_signing_alg"]],
    "ES256"
  )
  testthat::expect_match(
    plan[["credentials"]][["private_key"]],
    "PRIVATE KEY",
    fixed = TRUE
  )
  testthat::expect_length(spec[["available_modules"]], 23L)
  testthat::expect_false(grepl(
    "PRIVATE KEY",
    jsonlite::toJSON(registration, auto_unbox = TRUE),
    fixed = TRUE
  ))
})
