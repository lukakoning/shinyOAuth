signing_logs_fixture <- function(expectation, suite_id = "instance") {
  f <- fapi_logs_fixture(expectation[["module"]], suite_id, expectation)
  key <- openssl::ec_keygen("P-256")
  public <- jsonlite::fromJSON(
    jose::write_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  public[["kid"]] <- f[["plan"]][["credentials"]][["key_id"]]
  f[["plan"]][["registration"]][["redirect_uri"]] <- "https://localhost:42000/"
  f[["plan"]][["registration"]][["jwks"]] <- list(keys = list(public))
  f[["plan"]][["spec"]][[
    "plan"
  ]] <- "fapi2-message-signing-final-client-test-plan"
  f[["plan"]][["state_transport"]] <- "reference"
  now <- floor(as.numeric(Sys.time()))
  for (i in seq_along(f[["logs"]])) {
    e <- f[["logs"]][[i]]
    if (identical(e[["incoming_path"]], "/test/a/fapi/par")) {
      form <- e[["incoming_body_form_params"]]
      claims <- form[intersect(
        names(form),
        c(
          "client_id",
          "state",
          "response_type",
          "scope",
          "code_challenge",
          "code_challenge_method"
        )
      )]
      claims <- c(
        claims,
        list(
          iss = form[["client_id"]],
          aud = f[["module"]][["issuer"]],
          redirect_uri = "https://localhost:42000/",
          response_mode = "jwt",
          nonce = "DO_NOT_EXPORT_NONCE",
          jti = "DO_NOT_EXPORT_JAR_JTI",
          iat = now,
          nbf = now,
          exp = now + 45
        )
      )
      jwt <- jose::jwt_encode_sig(
        structure(claims, class = c("jwt_claim", "list")),
        key,
        header = list(typ = "oauth-authz-req+jwt", kid = public[["kid"]])
      )
      form <- form[c("client_id", "client_assertion_type", "client_assertion")]
      form[["request"]] <- jwt
      e[["incoming_body_form_params"]] <- form
      f[["logs"]][[i]] <- e
    }
    if (identical(e[["incoming_path"]], "/test/a/fapi/token")) {
      e[["incoming_body_form_params"]][["code"]] <- "DO_NOT_EXPORT_CODE"
      f[["logs"]][[i]] <- e
    }
  }
  if (identical(expectation[["action"]], "discovery")) {
    return(f)
  }
  f[["logs"]] <- c(
    f[["logs"]],
    lapply(openid_signing_checks(), function(source) {
      if (identical(source, "ValidateRequestObjectMaxAge")) {
        list(
          testId = suite_id,
          src = source,
          msg = "Request object does not contain a max_age claim"
        )
      } else {
        list(testId = suite_id, src = source, result = "SUCCESS")
      }
    })
  )
  claims <- list(
    iss = f[["module"]][["issuer"]],
    aud = f[["plan"]][["registration"]][["client_id"]],
    exp = now + 600,
    code = "DO_NOT_EXPORT_CODE",
    state = strrep("s", 64L)
  )
  case <- expectation[["jarm_error"]]
  if (identical(case, "without-iss")) {
    claims[["iss"]] <- NULL
  }
  if (identical(case, "with-invalid-iss")) {
    claims[["iss"]] <- "DO_NOT_EXPORT_INVALID_ISSUER"
  }
  if (identical(case, "without-aud")) {
    claims[["aud"]] <- NULL
  }
  if (identical(case, "with-invalid-aud")) {
    claims[["aud"]] <- "DO_NOT_EXPORT_INVALID_AUDIENCE"
  }
  if (identical(case, "without-exp")) {
    claims[["exp"]] <- NULL
  }
  if (identical(case, "with-expired-exp")) {
    claims[["exp"]] <- now - 600
  }
  if (identical(case, "without-state")) {
    claims[["state"]] <- NULL
  }
  if (identical(case, "with-invalid-state")) {
    claims[["state"]] <- "DO_NOT_EXPORT_INVALID_STATE"
  }
  jwt <- jose::jwt_encode_sig(
    structure(claims, class = c("jwt_claim", "list")),
    key
  )
  f[["logs"]] <- c(
    f[["logs"]],
    list(list(
      testId = suite_id,
      src = "SignJARMResponse",
      result = "SUCCESS",
      jarm_response = list(
        verifiable_jws = jwt,
        public_jwk = jose::write_jwk(key[["pubkey"]])
      )
    ))
  )
  if (identical(case, "with-invalid-sig")) {
    parts <- strsplit(jwt, ".", fixed = TRUE)[[1L]]
    parts[[3L]] <- paste0(
      if (startsWith(parts[[3L]], "A")) "B" else "A",
      substring(parts[[3L]], 2L)
    )
    jwt <- paste(parts, collapse = ".")
  }
  if (identical(case, "signature-is-not-none")) {
    jwt <- sub("\\.[^.]+$", ".", f[["jwt"]](list(alg = "none"), claims))
  }
  f[["logs"]] <- c(
    f[["logs"]],
    list(list(
      testId = suite_id,
      src = "SendJARMResponseWitResponseModeQuery",
      uri = paste0("https://localhost:42000/?response=", jwt)
    ))
  )
  f
}

signing_report_fixture <- function(backend) {
  f <- fapi_full_fixture(backend, "fapi-message-signing")
  expected <- f[["manifest"]][["profiles"]][["fapi-message-signing"]][[
    "modules"
  ]]
  for (i in seq_along(expected)) {
    row <- f[["report"]][["results"]][[i]]
    logs <- signing_logs_fixture(expected[[i]], row[["suite_id"]])
    row[["message_signing"]] <- openid_signing_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]],
      expected[[i]]
    )
    row[["fapi"]] <- openid_fapi_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]],
      expected[[i]]
    )
    if (identical(expected[[i]][["outcome"]], "callback_rejected")) {
      row[["app"]][["jarm_error"]] <- expected[[i]][["jarm_error"]]
      row[["callback_http"]][["jarm_error"]] <- expected[[i]][["jarm_error"]]
    }
    f[["report"]][["results"]][[i]] <- row
  }
  f
}

testthat::test_that("Message Signing requires the pinned 29-module selection and actual signed exchanges", {
  for (backend in c("sync", "mirai")) {
    f <- signing_report_fixture(backend)
    check <- function(report) {
      openid_check_report(report, f[["context"]], f[["manifest"]])[[
        "gate_passed"
      ]]
    }
    testthat::expect_length(f[["report"]][["results"]], 29L)
    testthat::expect_true(check(f[["report"]]))
    for (i in seq_along(f[["report"]][["results"]])) {
      report <- f[["report"]]
      report[["results"]] <- report[["results"]][-i]
      testthat::expect_false(check(report))
      proof <- f[["report"]][["results"]][[i]][["message_signing"]]
      for (name in names(proof)) {
        report <- f[["report"]]
        report[["results"]][[i]][["message_signing"]][[name]] <- NULL
        testthat::expect_false(
          openid_signing_matches(
            report[["results"]][[i]],
            f[["manifest"]][["profiles"]][["fapi-message-signing"]][[
              "modules"
            ]][[i]]
          ),
          info = paste(backend, i, name)
        )
      }
      for (name in c("state_present", "issuer_present", "jarm_error")) {
        if (is.null(f[["report"]][["results"]][[i]][["callback_http"]])) {
          next
        }
        report <- f[["report"]]
        report[["results"]][[i]][["callback_http"]][[name]] <- NULL
        testthat::expect_false(check(report), info = paste(backend, i, name))
      }
    }
    text <- jsonlite::toJSON(
      lapply(f[["report"]][["results"]], function(row) {
        row[["message_signing"]]
      }),
      auto_unbox = TRUE
    )
    testthat::expect_false(grepl("DO_NOT_EXPORT", text, fixed = TRUE))
  }
})

testthat::test_that("signed proof rejects tampered JAR and JARM without trusting suite verdicts", {
  expected <- openid_profiles("../..")[["profiles"]][["fapi-message-signing"]][[
    "modules"
  ]]
  for (e in expected) {
    f <- signing_logs_fixture(e)
    collect <- function(logs) {
      openid_signing_evidence(logs, f[["module"]], f[["plan"]], e)
    }
    proof <- collect(f[["logs"]])
    testthat::expect_true(openid_signing_matches(
      list(suite_id = "instance", message_signing = proof),
      e
    ))
    if (identical(e[["action"]], "discovery")) {
      next
    }
    for (source in openid_signing_checks()) {
      logs <- Filter(
        function(event) !identical(event[["src"]], source),
        f[["logs"]]
      )
      testthat::expect_false(openid_signing_matches(
        list(suite_id = "instance", message_signing = collect(logs)),
        e
      ))
    }
    logs <- f[["logs"]]
    index <- which(vapply(
      logs,
      function(event) identical(event[["incoming_path"]], "/test/a/fapi/par"),
      logical(1)
    ))[[1L]]
    logs[[index]][["incoming_body_form_params"]][["request"]] <- "malformed"
    testthat::expect_false(collect(logs)[["jar_signatures_valid"]])
    logs <- f[["logs"]]
    logs[[index]][["incoming_body_form_params"]][["scope"]] <- "tampered"
    testthat::expect_false(collect(logs)[["jar_metadata_valid"]])
    logs <- f[["logs"]]
    token_indices <- which(vapply(
      logs,
      function(event) identical(event[["incoming_path"]], "/test/a/fapi/token"),
      logical(1)
    ))
    if (length(token_indices)) {
      logs[[token_indices[[1L]]]][["incoming_body_form_params"]][[
        "code"
      ]] <- "OTHER_CODE"
      testthat::expect_false(collect(logs)[["jarm_code_redemption_valid"]])
    }
    if (is.null(e[["jarm_error"]])) {
      logs <- f[["logs"]]
      index <- length(logs)
      uri <- logs[[index]][["uri"]]
      parts <- strsplit(sub("^.*response=", "", uri), ".", fixed = TRUE)[[1L]]
      parts[[3L]] <- paste0(
        if (startsWith(parts[[3L]], "A")) "B" else "A",
        substring(parts[[3L]], 2L)
      )
      logs[[index]][["uri"]] <- paste0(
        "https://localhost:42000/?response=",
        paste(parts, collapse = ".")
      )
      testthat::expect_false(collect(logs)[["jarm_signature_variant"]])
    }
    testthat::expect_error(
      collect(c(logs, list(list(testId = "other")))),
      "suite instance"
    )
  }
})

testthat::test_that("JARM rejection categories come from the real HTTP response text", {
  source("fixture-app.R", local = TRUE)
  testthat::expect_identical(
    openid_fixture_jarm_error(
      "Invalid state\n! JARM payload expired\ni Trace ID: private"
    ),
    "with-expired-exp"
  )
  testthat::expect_null(openid_fixture_jarm_error(
    "Unrelated provider or network error"
  ))
  testthat::expect_null(openid_fixture_jarm_error(
    "JARM payload expired; JARM signature is invalid"
  ))
  testthat::expect_identical(openid_variant_key(list()), "{}")
  testthat::expect_identical(openid_variant_key(NULL), "null")
})
