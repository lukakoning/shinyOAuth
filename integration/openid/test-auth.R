auth_logs_fixture <- function(method, suite_id = "instance") {
  manifest <- openid_profiles("../..")
  profile <- switch(
    method,
    client_secret_post = "auth-post",
    client_secret_jwt = "auth-secret-jwt",
    private_key_jwt = "auth-private-jwt"
  )
  spec <- openid_plan_spec(manifest, profile)
  module <- list(
    id = suite_id,
    issuer = "https://localhost:41000/test/a/fixture/"
  )
  plan <- list(
    spec = spec,
    registration = list(client_id = "DO_NOT_EXPORT_CLIENT"),
    credentials = list(
      client_secret = "DO_NOT_EXPORT_SECRET",
      key_id = "DO_NOT_EXPORT_KEY_ID"
    )
  )
  verifier <- paste(rep("a", 43L), collapse = "")
  challenge <- sub(
    "=+$",
    "",
    chartr(
      "+/",
      "-_",
      as.character(openssl::base64_encode(
        openssl::sha256(charToRaw(verifier))
      ))
    )
  )
  form <- list(
    grant_type = "authorization_code",
    client_id = plan[["registration"]][["client_id"]],
    code = "DO_NOT_EXPORT_CODE",
    code_verifier = verifier
  )
  claims <- list(
    iss = form[["client_id"]],
    sub = form[["client_id"]],
    aud = paste0(module[["issuer"]], "token"),
    iat = 1700000000L,
    exp = 1700000060L,
    jti = "DO_NOT_EXPORT_JTI"
  )
  header <- list(alg = spec[["client_assertion_alg"]])
  encode <- function(value) {
    sub(
      "=+$",
      "",
      chartr(
        "+/",
        "-_",
        as.character(openssl::base64_encode(
          charToRaw(as.character(jsonlite::toJSON(value, auto_unbox = TRUE)))
        ))
      )
    )
  }
  if (identical(method, "client_secret_post")) {
    form[["client_secret"]] <- plan[["credentials"]][["client_secret"]]
  } else {
    if (identical(method, "private_key_jwt")) {
      header[["kid"]] <- plan[["credentials"]][["key_id"]]
    }
    form[["client_assertion"]] <- paste(
      encode(header),
      encode(claims),
      "signature",
      sep = "."
    )
    form[[
      "client_assertion_type"
    ]] <- "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  }
  logs <- list(
    list(
      testId = suite_id,
      http = "incoming",
      incoming_path = "/test/a/fixture/authorize",
      incoming_method = "GET",
      incoming_query_string_params = list(
        client_id = form[["client_id"]],
        response_type = "code",
        code_challenge = challenge,
        code_challenge_method = "S256"
      )
    ),
    list(
      testId = suite_id,
      http = "incoming",
      incoming_path = "/test/a/fixture/token",
      incoming_method = "POST",
      incoming_headers = list(),
      incoming_body_form_params = form
    )
  )
  for (source in c(
    "EnsureAuthorizationRequestContainsPkceCodeChallenge",
    openid_auth_checks(method)
  )) {
    logs[[length(logs) + 1L]] <- list(
      testId = suite_id,
      src = source,
      result = "SUCCESS",
      message = "DO_NOT_EXPORT_LOG_MESSAGE"
    )
  }
  list(
    logs = logs,
    module = module,
    plan = plan,
    claims = claims,
    header = header,
    encode = encode
  )
}

auth_evidence_fixture <- function(profile) {
  f <- evidence_fixture(profile)
  spec <- openid_plan_spec(f[["manifest"]], profile)
  for (i in seq_along(f[["report"]][["results"]])) {
    row <- f[["report"]][["results"]][[i]]
    logs <- auth_logs_fixture(
      spec[["plan_variant"]][["client_auth_type"]],
      row[["suite_id"]]
    )
    row[["client_auth"]] <- openid_auth_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]]
    )
    f[["report"]][["results"]][[i]] <- row
  }
  public_spec <- f[["manifest"]][["plans"]][["auth-public"]]
  for (name in c("plan_id", "suite_id")) {
    value <- if (name == "plan_id") "publicplan" else "publicinstance"
    f[["context"]][[paste0("public_probe_", name)]] <- f[["report"]][[paste0(
      "public_probe_",
      name
    )]] <- value
  }
  f[["report"]][["public_client_capability"]] <- c(
    f[["context"]][c(
      "run_id",
      "attempt_id",
      "checkout_revision",
      "source_revision",
      "package_version"
    )],
    list(
      plan_id = "publicplan",
      suite_id = "publicinstance",
      module = "oidcc-client-test",
      variant = public_spec[["plan_variant"]],
      suite_status = "INTERRUPTED",
      issuer_exact = TRUE,
      none_advertised = FALSE,
      conformance_credited = FALSE,
      public_client_authentication_tested = FALSE,
      package_matches = TRUE,
      discovery_rejected = TRUE
    )
  )
  f
}

testthat::test_that("auth selections require both cases and stay partial Comprehensive coverage", {
  for (profile in c("auth-post", "auth-secret-jwt", "auth-private-jwt")) {
    for (backend in c("sync", "mirai")) {
      f <- evidence_with_transport(auth_evidence_fixture(profile), backend)
      check <- openid_check_report(
        f[["report"]],
        f[["context"]],
        f[["manifest"]]
      )
      testthat::expect_true(check[["gate_passed"]])
      testthat::expect_true(check[["selection_complete"]])
      testthat::expect_false(check[["coverage_complete"]])
      for (i in 1:2) {
        report <- f[["report"]]
        report[["results"]] <- report[["results"]][-i]
        testthat::expect_false(openid_check_report(
          report,
          f[["context"]],
          f[["manifest"]]
        )[["gate_passed"]])
      }
    }
  }
})

testthat::test_that("suite verdicts cannot substitute for observed authentication and S256 proof", {
  for (profile in c("auth-post", "auth-secret-jwt", "auth-private-jwt")) {
    f <- auth_evidence_fixture(profile)
    proof <- f[["report"]][["results"]][[1L]][["client_auth"]]
    for (name in setdiff(names(proof), "suite_checks")) {
      report <- f[["report"]]
      value <- proof[[name]]
      report[["results"]][[1L]][["client_auth"]][[name]] <- if (
        is.logical(value)
      ) {
        !value
      } else if (is.numeric(value)) {
        2L
      } else if (is.null(value)) {
        "unexpected"
      } else {
        "wrong"
      }
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (source in names(proof[["suite_checks"]])) {
      report <- f[["report"]]
      report[["results"]][[1L]][["client_auth"]][["suite_checks"]][[
        source
      ]] <- FALSE
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})

testthat::test_that("public capability probes never earn client authentication conformance", {
  f <- auth_evidence_fixture("auth-post")
  probe <- f[["report"]][["public_client_capability"]]
  for (name in names(probe)) {
    report <- f[["report"]]
    value <- probe[[name]]
    report[["public_client_capability"]][[name]] <- if (is.logical(value)) {
      !value
    } else {
      "wrong"
    }
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["public_client_capability"]] <- NULL
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  for (name in c("public_probe_plan_id", "public_probe_suite_id")) {
    report <- f[["report"]]
    report[[name]] <- "stale"
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("actual request checks reject mixed credentials and mismatched PKCE", {
  for (method in c(
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  )) {
    f <- auth_logs_fixture(method)
    for (change in list(
      list(field = "client_id", value = "DO_NOT_EXPORT_WRONG_CLIENT"),
      list(field = "client_secret", value = "DO_NOT_EXPORT_WRONG_SECRET"),
      list(field = "code_verifier", value = paste(rep("b", 43L), collapse = ""))
    )) {
      logs <- f[["logs"]]
      logs[[2L]][["incoming_body_form_params"]][[change[["field"]]]] <- change[[
        "value"
      ]]
      proof <- openid_auth_evidence(logs, f[["module"]], f[["plan"]])
      testthat::expect_false(openid_auth_matches(
        list(suite_id = "instance", client_auth = proof),
        f[["plan"]][["spec"]]
      ))
    }
    logs <- f[["logs"]]
    logs[[2L]][["incoming_headers"]][[
      "authorization"
    ]] <- "DO_NOT_EXPORT_HEADER"
    proof <- openid_auth_evidence(logs, f[["module"]], f[["plan"]])
    testthat::expect_false(openid_auth_matches(
      list(suite_id = "instance", client_auth = proof),
      f[["plan"]][["spec"]]
    ))
    logs <- f[["logs"]]
    logs[[1L]][["testId"]] <- "foreign"
    testthat::expect_error(
      openid_auth_evidence(logs, f[["module"]], f[["plan"]]),
      "do not belong"
    )
    testthat::expect_error(
      openid_auth_evidence(
        c(f[["logs"]], f[["logs"]][2L]),
        f[["module"]],
        f[["plan"]]
      ),
      "one actual"
    )
    proof <- openid_auth_evidence(f[["logs"]], f[["module"]], f[["plan"]])
    encoded <- as.character(jsonlite::toJSON(
      proof,
      auto_unbox = TRUE,
      null = "null"
    ))
    testthat::expect_false(grepl("DO_NOT_EXPORT", encoded, fixed = TRUE))
  }
})

testthat::test_that("assertion metadata cannot expose claim values or unsupported algorithms", {
  for (method in c("client_secret_jwt", "private_key_jwt")) {
    f <- auth_logs_fixture(method)
    for (field in c("iss", "sub", "aud", "iat", "exp", "jti")) {
      claims <- f[["claims"]]
      claims[[field]] <- if (field == "jti") {
        NULL
      } else {
        "DO_NOT_EXPORT_WRONG_CLAIM"
      }
      logs <- f[["logs"]]
      logs[[2L]][["incoming_body_form_params"]][["client_assertion"]] <- paste(
        f[["encode"]](f[["header"]]),
        f[["encode"]](claims),
        "signature",
        sep = "."
      )
      proof <- openid_auth_evidence(logs, f[["module"]], f[["plan"]])
      testthat::expect_false(openid_auth_matches(
        list(suite_id = "instance", client_auth = proof),
        f[["plan"]][["spec"]]
      ))
      testthat::expect_false(grepl(
        "DO_NOT_EXPORT",
        as.character(jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null")),
        fixed = TRUE
      ))
    }
    header <- f[["header"]]
    header[["alg"]] <- "DO_NOT_EXPORT_ALGORITHM"
    logs <- f[["logs"]]
    logs[[2L]][["incoming_body_form_params"]][["client_assertion"]] <- paste(
      f[["encode"]](header),
      f[["encode"]](f[["claims"]]),
      "signature",
      sep = "."
    )
    proof <- openid_auth_evidence(logs, f[["module"]], f[["plan"]])
    testthat::expect_identical(proof[["assertion_algorithm"]], "unsupported")
    testthat::expect_false(grepl(
      "DO_NOT_EXPORT",
      as.character(jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null")),
      fixed = TRUE
    ))
  }
})

testthat::test_that("only the public signing key enters the suite registration", {
  manifest <- openid_profiles("../..")
  spec <- openid_plan_spec(manifest, "auth-private-jwt")
  registration <- NULL
  request <- function(stack, path, data, ...) {
    registration <<- data[["client"]]
    list(
      id = "plan",
      name = spec[["plan"]],
      modules = lapply(spec[["available_modules"]], function(module) {
        list(testModule = module, variant = NULL)
      })
    )
  }
  plan <- openid_suite_plan(
    list(),
    manifest,
    "https://localhost:42000/",
    "auth-private-jwt",
    .request = request
  )
  testthat::expect_null(registration[["client_secret"]])
  testthat::expect_identical(
    registration[["token_endpoint_auth_method"]],
    "private_key_jwt"
  )
  testthat::expect_identical(
    registration[["token_endpoint_auth_signing_alg"]],
    "RS256"
  )
  key <- registration[["jwks"]][["keys"]][[1L]]
  testthat::expect_false(any(
    c("d", "p", "q", "dp", "dq", "qi") %in% names(key)
  ))
  testthat::expect_identical(key[["kid"]], plan[["credentials"]][["key_id"]])
  testthat::expect_match(
    plan[["credentials"]][["private_key"]],
    "BEGIN PRIVATE KEY",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "PRIVATE KEY",
    as.character(jsonlite::toJSON(registration, auto_unbox = TRUE)),
    fixed = TRUE
  ))
})
