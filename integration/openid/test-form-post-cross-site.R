cross_site_request_fixture <- function(denied = FALSE) {
  manifest <- openid_profiles("../..")
  expectation <- manifest[["profiles"]][["form-post-cross-site"]][["modules"]][[
    if (denied) 2L else 1L
  ]]
  module <- list(
    id = "cross-site-instance",
    issuer = "https://localhost:41000/test/a/cross-site/"
  )
  plan <- list(
    registration = list(
      client_id = "DO_NOT_EXPORT_CLIENT",
      redirect_uri = "https://127.0.0.1:42000/"
    ),
    credentials = list(client_secret = "DO_NOT_EXPORT_SECRET")
  )
  verifier <- paste(rep("a", 43L), collapse = "")
  challenge <- sub(
    "=+$",
    "",
    chartr(
      "+/",
      "-_",
      as.character(
        openssl::base64_encode(openssl::sha256(charToRaw(verifier)))
      )
    )
  )
  query <- list(
    client_id = plan[["registration"]][["client_id"]],
    redirect_uri = plan[["registration"]][["redirect_uri"]],
    response_type = "code",
    response_mode = "form_post",
    state = "DO_NOT_EXPORT_STATE",
    nonce = "DO_NOT_EXPORT_NONCE",
    code_challenge_method = "S256",
    code_challenge = challenge
  )
  if (denied) {
    query <- c(query, list(prompt = "none", max_age = "0"))
  }
  logs <- list(list(
    testId = module[["id"]],
    http = "incoming",
    incoming_method = "GET",
    incoming_path = "/test/a/cross-site/authorize",
    incoming_query_string_params = query
  ))
  if (!denied) {
    logs <- c(
      logs,
      list(
        list(
          testId = module[["id"]],
          http = "incoming",
          incoming_method = "POST",
          incoming_path = "/test/a/cross-site/token",
          incoming_headers = list(
            authorization = paste0(
              "Basic ",
              as.character(
                openssl::base64_encode(charToRaw(
                  "DO_NOT_EXPORT_CLIENT:DO_NOT_EXPORT_SECRET"
                ))
              )
            )
          ),
          incoming_body_form_params = list(
            grant_type = "authorization_code",
            code = "DO_NOT_EXPORT_CODE",
            code_verifier = verifier
          )
        ),
        list(
          testId = module[["id"]],
          http = "incoming",
          incoming_method = "GET",
          incoming_path = "/test/a/cross-site/userinfo"
        )
      )
    )
  }
  list(logs = logs, module = module, plan = plan, expectation = expectation)
}

cross_site_evidence_fixture <- function(transport = "sync") {
  f <- evidence_fixture("form-post-cross-site")
  f[["context"]][["provider_origin"]] <- f[["report"]][[
    "provider_origin"
  ]] <- "https://localhost:41000"
  f[["context"]][["app_origin"]] <- f[["report"]][[
    "app_origin"
  ]] <- "https://127.0.0.1:42000"
  for (i in seq_along(f[["report"]][["results"]])) {
    row <- f[["report"]][["results"]][[i]]
    denied <- i == 2L
    row[["app"]][["id_token_present"]] <- !denied
    row[["app"]][["pending_state_count"]] <- 0L
    row[["app"]][["operations"]][["audit_callback_validation_success"]] <- 1L
    row[["app"]][["operations"]][["audit_error_state_consumed"]] <- 0L
    row[["app"]][["authorization_error_sanitized"]] <- TRUE
    if (denied) {
      row[["app"]][["error_code"]] <- "login_required"
      row[["app"]][["error_classes"]] <- list()
      row[["app"]][["operations"]][["audit_token_exchange"]] <- 0L
      row[["app"]][["operations"]][["audit_callback_validation_success"]] <- 0L
      row[["app"]][["operations"]][["audit_error_state_consumed"]] <- 1L
      row[["form_post_error"]] <- list(
        visible = TRUE,
        provider_description_absent = TRUE
      )
    }
    row[["form_post"]] <- list(
      provider_origin = f[["context"]][["provider_origin"]],
      app_origin = f[["context"]][["app_origin"]],
      authorization_method = "GET",
      callback_method = "POST",
      bridge_redirect_303 = TRUE,
      secure_context = TRUE,
      cross_origin = TRUE,
      cross_site = TRUE,
      cookie = list(
        binding_cookie_count = 1L,
        secure = TRUE,
        same_site = "Strict",
        http_only = FALSE
      )
    )
    row[["app"]][["form_post"]] <- list(
      method = "POST",
      origin_matched = TRUE,
      sec_fetch_site = "cross-site",
      form_urlencoded = TRUE,
      binding_cookie_absent = TRUE
    )
    row[["form_post_tls"]] <- list(
      app_origin = f[["context"]][["app_origin"]],
      ca_verified = TRUE,
      wrong_pin_rejected = TRUE
    )
    request <- cross_site_request_fixture(denied)
    request[["module"]][["id"]] <- row[["suite_id"]]
    request[["logs"]] <- lapply(request[["logs"]], function(entry) {
      entry[["testId"]] <- row[["suite_id"]]
      entry
    })
    row[["form_post_requests"]] <- do.call(openid_form_post_requests, request)
    f[["report"]][["results"]][[i]] <- row
  }
  f <- evidence_with_transport(f, transport)
  for (i in seq_along(f[["report"]][["results"]])) {
    for (name in c("app", "initial")) {
      f[["report"]][["results"]][[i]][[name]][["transport"]][[
        "worker_operations"
      ]][["audit_error_state_consumed"]] <- 0L
    }
  }
  f
}

testthat::test_that("the cross-site selection pins its separate Comprehensive Form Post variant", {
  f <- cross_site_evidence_fixture()
  spec <- openid_plan_spec(f[["manifest"]], "form-post-cross-site")
  testthat::expect_identical(spec[["plan"]], "oidcc-client-test-plan")
  testthat::expect_identical(
    spec[["plan_variant"]][["response_mode"]],
    "form_post"
  )
  testthat::expect_identical(
    spec[["plan_variant"]][["client_auth_type"]],
    "client_secret_basic"
  )
  testthat::expect_null(spec[["module_variant"]])
  testthat::expect_length(spec[["available_modules"]], 30L)
  testthat::expect_true(
    "oidcc-client-test-form-post-error" %in% unlist(spec[["available_modules"]])
  )
  testthat::expect_false(openid_auth_profile("form-post-cross-site"))
  testthat::expect_true(all(vapply(
    c("auth-post", "auth-secret-jwt", "auth-private-jwt"),
    openid_auth_profile,
    logical(1)
  )))
  for (transport in c("sync", "mirai")) {
    f <- cross_site_evidence_fixture(transport)
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["gate_passed"]])
    testthat::expect_true(check[["selection_complete"]])
    testthat::expect_false(check[["coverage_complete"]])
    testthat::expect_false(check[["upstream_plan_complete"]])
    testthat::expect_identical(
      check[["assessment"]][["certification_status"]],
      "not_assessed"
    )
    roundtrip <- jsonlite::fromJSON(
      as.character(jsonlite::toJSON(
        f[["report"]],
        auto_unbox = TRUE,
        null = "null"
      )),
      simplifyVector = FALSE
    )
    testthat::expect_true(openid_check_report(
      roundtrip,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("observed cross-site navigation and trusted TLS cannot be replaced by labels", {
  f <- cross_site_evidence_fixture()
  changes <- list(
    list("form_post", "cross_site", FALSE),
    list("form_post", "secure_context", FALSE),
    list("form_post", "bridge_redirect_303", FALSE),
    list("form_post_tls", "app_origin", "https://127.0.0.1:43000"),
    list("form_post_tls", "ca_verified", FALSE),
    list("form_post_tls", "wrong_pin_rejected", FALSE)
  )
  for (i in 1:2) {
    for (change in changes) {
      report <- f[["report"]]
      report[["results"]][[i]][[change[[1L]]]][[change[[2L]]]] <- change[[3L]]
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (change in list(
      list("sec_fetch_site", "same-site"),
      list("origin_matched", FALSE),
      list("binding_cookie_absent", FALSE)
    )) {
      report <- f[["report"]]
      report[["results"]][[i]][["app"]][["form_post"]][[change[[
        1L
      ]]]] <- change[[2L]]
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
  f[["context"]][["app_origin"]] <- f[["report"]][[
    "app_origin"
  ]] <- "https://localhost:42000"
  testthat::expect_false(openid_check_report(
    f[["report"]],
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("legitimate authorization denial validates and consumes state without exchange", {
  for (transport in c("sync", "mirai")) {
    f <- cross_site_evidence_fixture(transport)
    for (change in list(
      list("error_code", "invalid_state"),
      list("pending_state_count", 1L),
      list("has_token", TRUE),
      list("id_token_present", TRUE),
      list("authorization_error_sanitized", FALSE),
      list("error_classes", list("shinyOAuth_state_error"))
    )) {
      report <- f[["report"]]
      report[["results"]][[2L]][["app"]][[change[[1L]]]] <- change[[2L]]
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (name in c(
      "audit_error_state_consumed",
      "audit_callback_validation_success",
      "audit_token_exchange",
      "audit_userinfo",
      "audit_login_success"
    )) {
      report <- f[["report"]]
      report[["results"]][[2L]][["app"]][["operations"]][[name]] <- if (
        name == "audit_error_state_consumed"
      ) {
        0L
      } else {
        1L
      }
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (name in c("visible", "provider_description_absent")) {
      report <- f[["report"]]
      report[["results"]][[2L]][["form_post_error"]][[name]] <- FALSE
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    if (transport == "mirai") {
      report <- f[["report"]]
      report[["results"]][[2L]][["app"]][["transport"]][[
        "worker_pids"
      ]] <- list(200L)
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})

testthat::test_that("Form Post request evidence checks actual denial controls and excludes credentials", {
  for (denied in c(FALSE, TRUE)) {
    f <- cross_site_request_fixture(denied)
    proof <- do.call(openid_form_post_requests, f)
    result <- list(suite_id = f[["module"]][["id"]], form_post_requests = proof)
    testthat::expect_true(openid_form_post_requests_match(
      result,
      f[["expectation"]]
    ))
    testthat::expect_no_match(
      as.character(jsonlite::toJSON(proof, auto_unbox = TRUE)),
      "DO_NOT_EXPORT|https://|aaaaaaaa"
    )
    for (name in c(
      "client_id",
      "redirect_uri",
      "state",
      "nonce",
      "response_mode",
      "code_challenge_method"
    )) {
      changed <- f
      changed[["logs"]][[1L]][["incoming_query_string_params"]][[name]] <- if (
        name %in% c("state", "nonce")
      ) {
        ""
      } else {
        "wrong"
      }
      result[["form_post_requests"]] <- do.call(
        openid_form_post_requests,
        changed
      )
      testthat::expect_false(openid_form_post_requests_match(
        result,
        f[["expectation"]]
      ))
    }
    if (denied) {
      for (name in c("prompt", "max_age")) {
        changed <- f
        changed[["logs"]][[1L]][["incoming_query_string_params"]][[
          name
        ]] <- "wrong"
        result[["form_post_requests"]] <- do.call(
          openid_form_post_requests,
          changed
        )
        testthat::expect_false(openid_form_post_requests_match(
          result,
          f[["expectation"]]
        ))
      }
      changed <- f
      changed[["logs"]] <- c(
        changed[["logs"]],
        cross_site_request_fixture()[["logs"]][2:3]
      )
      testthat::expect_error(
        do.call(openid_form_post_requests, changed),
        "request count"
      )
    } else {
      for (name in c("code_verifier", "grant_type")) {
        changed <- f
        changed[["logs"]][[2L]][["incoming_body_form_params"]][[
          name
        ]] <- "wrong"
        result[["form_post_requests"]] <- do.call(
          openid_form_post_requests,
          changed
        )
        testthat::expect_false(openid_form_post_requests_match(
          result,
          f[["expectation"]]
        ))
      }
      changed <- f
      changed[["logs"]][[2L]][["incoming_headers"]][[
        "authorization"
      ]] <- "Basic wrong"
      result[["form_post_requests"]] <- do.call(
        openid_form_post_requests,
        changed
      )
      testthat::expect_false(openid_form_post_requests_match(
        result,
        f[["expectation"]]
      ))
    }
    changed <- f
    changed[["logs"]][[1L]][["testId"]] <- "old-instance"
    testthat::expect_error(
      do.call(openid_form_post_requests, changed),
      "suite instance"
    )
    for (index in 2:3) {
      changed <- f
      changed[["logs"]] <- c(
        changed[["logs"]],
        cross_site_request_fixture()[["logs"]][index]
      )
      testthat::expect_error(
        do.call(openid_form_post_requests, changed),
        "request count"
      )
      if (!denied) {
        changed <- f
        changed[["logs"]] <- changed[["logs"]][-index]
        testthat::expect_error(
          do.call(openid_form_post_requests, changed),
          "request count"
        )
      }
    }
  }
})
