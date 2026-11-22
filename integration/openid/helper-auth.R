openid_form_post_requests <- function(logs, module, plan, expectation) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(entry) {
          identical(entry[["testId"]], module[["id"]])
        },
        logical(1)
      ))
  ) {
    stop("Form Post logs do not belong to this suite instance")
  }
  path <- sub("^https://[^/]+", "", module[["issuer"]])
  requests <- function(endpoint) {
    Filter(
      function(entry) {
        identical(entry[["http"]], "incoming") &&
          identical(entry[["incoming_path"]], paste0(path, endpoint))
      },
      logs
    )
  }
  authorization <- requests("authorize")
  token <- requests("token")
  userinfo <- requests("userinfo")
  denied <- identical(expectation[["outcome"]], "authorization_error")
  expected_count <- if (denied) 0L else 1L
  if (
    length(authorization) != 1L ||
      length(token) != expected_count ||
      length(userinfo) != expected_count
  ) {
    stop("Unexpected authorization, token or UserInfo request count")
  }
  query <- authorization[[1L]][["incoming_query_string_params"]]
  challenge <- query[["code_challenge"]]
  request_valid <- identical(authorization[[1L]][["incoming_method"]], "GET") &&
    identical(query[["response_type"]], "code") &&
    identical(query[["response_mode"]], "form_post") &&
    identical(
      query[["redirect_uri"]],
      plan[["registration"]][["redirect_uri"]]
    ) &&
    identical(query[["client_id"]], plan[["registration"]][["client_id"]]) &&
    openid_string(query[["state"]]) &&
    openid_string(query[["nonce"]]) &&
    identical(query[["code_challenge_method"]], "S256") &&
    openid_string(challenge) &&
    grepl("^[A-Za-z0-9_-]{43}$", challenge)
  controls_valid <- if (denied) {
    identical(query[["prompt"]], "none") &&
      identical(as.character(query[["max_age"]]), "0")
  } else {
    is.null(query[["prompt"]]) && is.null(query[["max_age"]])
  }
  pair <- basic <- NULL
  if (!denied) {
    request <- token[[1L]]
    form <- request[["incoming_body_form_params"]]
    verifier <- form[["code_verifier"]]
    pair <- openid_string(verifier) &&
      grepl("^[A-Za-z0-9._~-]{43,128}$", verifier) &&
      identical(
        challenge,
        sub(
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
      )
    header <- request[["incoming_headers"]][["authorization"]]
    expected <- paste0(
      "Basic ",
      as.character(openssl::base64_encode(charToRaw(
        paste0(
          plan[["registration"]][["client_id"]],
          ":",
          plan[["credentials"]][["client_secret"]]
        )
      )))
    )
    basic <- identical(header, expected) &&
      identical(request[["incoming_method"]], "POST") &&
      identical(form[["grant_type"]], "authorization_code") &&
      openid_string(form[["code"]]) &&
      is.null(form[["client_secret"]]) &&
      is.null(form[["client_assertion"]])
  }
  list(
    schema_version = 1L,
    suite_id = module[["id"]],
    authorization_request_count = length(authorization),
    token_request_count = length(token),
    userinfo_request_count = length(userinfo),
    authorization_request_valid = request_valid,
    authorization_controls_valid = controls_valid,
    pkce_pair_verified = pair,
    basic_auth_verified = basic
  )
}

openid_form_post_requests_match <- function(result, expectation) {
  proof <- result[["form_post_requests"]]
  denied <- identical(expectation[["outcome"]], "authorization_error")
  identical(proof[["schema_version"]], 1L) &&
    identical(proof[["suite_id"]], result[["suite_id"]]) &&
    identical(proof[["authorization_request_count"]], 1L) &&
    identical(proof[["token_request_count"]], if (denied) 0L else 1L) &&
    identical(proof[["userinfo_request_count"]], if (denied) 0L else 1L) &&
    isTRUE(proof[["authorization_request_valid"]]) &&
    isTRUE(proof[["authorization_controls_valid"]]) &&
    if (denied) {
      is.null(proof[["pkce_pair_verified"]]) &&
        is.null(proof[["basic_auth_verified"]])
    } else {
      isTRUE(proof[["pkce_pair_verified"]]) &&
        isTRUE(proof[["basic_auth_verified"]])
    }
}

openid_userinfo_request_evidence <- function(logs, module) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(entry) identical(entry[["testId"]], module[["id"]]),
        logical(1)
      ))
  ) {
    stop("UserInfo logs do not belong to this suite instance")
  }
  path <- sub("^https://[^/]+", "", module[["issuer"]])
  requests <- function(endpoint) {
    Filter(
      function(entry) {
        identical(entry[["http"]], "incoming") &&
          identical(entry[["incoming_path"]], paste0(path, endpoint))
      },
      logs
    )
  }
  userinfo <- requests("userinfo")
  one_userinfo_request <- length(userinfo) == 1L
  suite_passed <- function(check) {
    any(vapply(
      logs,
      function(entry) {
        identical(entry[["src"]], check) &&
          identical(entry[["result"]], "SUCCESS")
      },
      logical(1)
    ))
  }
  list(
    suite_id = module[["id"]],
    token_request_count = length(requests("token")),
    userinfo_request_count = length(userinfo),
    userinfo_bearer_get = one_userinfo_request &&
      {
        request <- userinfo[[1L]]
        authorization <- request[["incoming_headers"]][["authorization"]]
        identical(request[["incoming_method"]], "GET") &&
          openid_string(authorization) &&
          grepl("^Bearer [^[:space:]]+$", authorization) &&
          !"access_token" %in%
            names(request[["incoming_query_string_params"]]) &&
          !"access_token" %in% names(request[["incoming_body_form_params"]])
      },
    suite_accepted_bearer_token = suite_passed("RequireBearerAccessToken"),
    suite_signed_userinfo = suite_passed("SignUserInfoResponse"),
    suite_omitted_id_token_audience = suite_passed("RemoveAudFromIdToken")
  )
}

openid_userinfo_requests_match <- function(result, expectation) {
  proof <- result[["userinfo_requests"]]
  authenticated <- identical(expectation[["outcome"]], "authenticated")
  identical(proof[["suite_id"]], result[["suite_id"]]) &&
    identical(proof[["token_request_count"]], 1L) &&
    identical(proof[["userinfo_request_count"]], as.integer(authenticated)) &&
    identical(proof[["userinfo_bearer_get"]], authenticated) &&
    identical(proof[["suite_accepted_bearer_token"]], authenticated) &&
    identical(proof[["suite_omitted_id_token_audience"]], !authenticated) &&
    (!isTRUE(expectation[["require_signed_userinfo"]]) ||
      (isTRUE(proof[["suite_signed_userinfo"]]) &&
        isTRUE(result[["app"]][["signed_userinfo_validated"]])))
}

openid_auth_checks <- function(method) {
  if (identical(method, "client_secret_post")) {
    return(c(
      "ExtractClientCredentialsFromFormPost",
      "ValidateClientIdAndSecret"
    ))
  }
  c(
    "ExtractClientAssertion",
    "EnsureClientAssertionSignatureAlgorithmMatchesRegistered",
    if (identical(method, "client_secret_jwt")) {
      "ValidateClientAssertionSignatureWithHMACAlgorithm"
    } else {
      "ValidateClientAssertionSignature"
    },
    "EnsureClientAssertionTypeIsJwt",
    "ValidateClientAssertionClaims",
    if (identical(method, "private_key_jwt")) "CheckForClientAssertionJtiReuse"
  )
}

openid_auth_evidence <- function(logs, module, plan) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(entry) identical(entry[["testId"]], module[["id"]]),
        logical(1)
      ))
  ) {
    stop("Authentication logs do not belong to this suite instance")
  }
  method <- plan[["spec"]][["plan_variant"]][["client_auth_type"]]
  path <- sub("^https://[^/]+", "", module[["issuer"]])
  request <- function(endpoint) {
    Filter(
      function(entry) {
        identical(entry[["http"]], "incoming") &&
          identical(entry[["incoming_path"]], paste0(path, endpoint))
      },
      logs
    )
  }
  token <- request("token")
  authorization <- request("authorize")
  if (length(token) != 1L || length(authorization) != 1L) {
    stop("Expected one actual authorization and token request")
  }
  token <- token[[1L]]
  authorization <- authorization[[1L]]
  form <- token[["incoming_body_form_params"]]
  query <- authorization[["incoming_query_string_params"]]
  verifier <- form[["code_verifier"]]
  pkce <- openid_string(verifier) &&
    grepl("^[A-Za-z0-9._~-]{43,128}$", verifier) &&
    identical(query[["code_challenge_method"]], "S256") &&
    identical(
      query[["code_challenge"]],
      sub(
        "=+$",
        "",
        chartr(
          "+/",
          "-_",
          as.character(openssl::base64_encode(openssl::sha256(charToRaw(
            verifier
          ))))
        )
      )
    )
  checks <- c(
    "EnsureAuthorizationRequestContainsPkceCodeChallenge",
    openid_auth_checks(method)
  )
  checked <- setNames(
    lapply(checks, function(source) {
      any(vapply(
        logs,
        function(entry) {
          identical(entry[["src"]], source) &&
            identical(entry[["result"]], "SUCCESS")
        },
        logical(1)
      ))
    }),
    checks
  )
  assertion <- form[["client_assertion"]]
  decoded <- if (openid_string(assertion)) {
    tryCatch(
      {
        parts <- strsplit(assertion, ".", fixed = TRUE)[[1L]]
        if (length(parts) != 3L) {
          stop("Malformed assertion")
        }
        lapply(parts[1:2], function(part) {
          jsonlite::fromJSON(
            rawToChar(openssl::base64_decode(
              paste0(
                chartr("-_", "+/", part),
                strrep("=", (4L - nchar(part) %% 4L) %% 4L)
              )
            )),
            simplifyVector = FALSE
          )
        })
      },
      error = function(...) NULL
    )
  } else {
    NULL
  }
  jwt <- !identical(method, "client_secret_post")
  claims <- if (jwt) decoded[[2L]] else NULL
  client_id <- plan[["registration"]][["client_id"]]
  list(
    suite_id = module[["id"]],
    method = method,
    authorization_request_count = 1L,
    token_request_count = 1L,
    authorization_get = identical(authorization[["incoming_method"]], "GET"),
    token_post = identical(token[["incoming_method"]], "POST"),
    authorization_code = identical(query[["response_type"]], "code") &&
      identical(form[["grant_type"]], "authorization_code"),
    pkce_s256_verified = pkce,
    suite_pkce_verifier_checked = any(vapply(
      logs,
      function(entry) {
        identical(entry[["src"]], "ValidateCodeVerifierWithS256") &&
          identical(entry[["result"]], "SUCCESS")
      },
      logical(1)
    )),
    no_authorization_header = !"authorization" %in%
      names(token[["incoming_headers"]]),
    client_id_matches = identical(form[["client_id"]], client_id) &&
      identical(query[["client_id"]], client_id),
    body_secret_present = "client_secret" %in% names(form),
    body_secret_matches = if (jwt) {
      NULL
    } else {
      identical(
        form[["client_secret"]],
        plan[["credentials"]][["client_secret"]]
      )
    },
    assertion_present = "client_assertion" %in% names(form),
    assertion_type_valid = if (jwt) {
      identical(
        form[["client_assertion_type"]],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      )
    } else {
      NULL
    },
    assertion_algorithm = if (!jwt) {
      NULL
    } else if (decoded[[1L]][["alg"]] %in% c("HS256", "RS256")) {
      decoded[[1L]][["alg"]]
    } else {
      "unsupported"
    },
    assertion_key_id_matches = if (identical(method, "private_key_jwt")) {
      identical(decoded[[1L]][["kid"]], plan[["credentials"]][["key_id"]])
    } else {
      NULL
    },
    assertion_identity_matches = if (jwt) {
      identical(claims[["iss"]], client_id) &&
        identical(claims[["sub"]], client_id)
    } else {
      NULL
    },
    assertion_audience_matches = if (jwt) {
      identical(claims[["aud"]], paste0(module[["issuer"]], "token"))
    } else {
      NULL
    },
    assertion_jti_present = if (jwt) openid_string(claims[["jti"]]) else NULL,
    assertion_times_valid = if (jwt) {
      is.numeric(claims[["iat"]]) &&
        length(claims[["iat"]]) == 1L &&
        is.finite(claims[["iat"]]) &&
        is.numeric(claims[["exp"]]) &&
        length(claims[["exp"]]) == 1L &&
        is.finite(claims[["exp"]]) &&
        claims[["exp"]] > claims[["iat"]] &&
        claims[["exp"]] - claims[["iat"]] <= 300
    } else {
      NULL
    },
    suite_checks = checked
  )
}

openid_auth_matches <- function(result, spec) {
  evidence <- result[["client_auth"]]
  method <- spec[["plan_variant"]][["client_auth_type"]]
  jwt <- method %in% c("client_secret_jwt", "private_key_jwt")
  if (
    !method %in%
      c("client_secret_post", "client_secret_jwt", "private_key_jwt") ||
      !identical(evidence[["suite_id"]], result[["suite_id"]]) ||
      !identical(evidence[["method"]], method)
  ) {
    return(FALSE)
  }
  if (!identical(evidence[["suite_pkce_verifier_checked"]], FALSE)) {
    return(FALSE)
  }
  for (name in c("authorization_request_count", "token_request_count")) {
    if (!openid_count(evidence[[name]]) || evidence[[name]] != 1L) return(FALSE)
  }
  for (name in c(
    "authorization_get",
    "token_post",
    "authorization_code",
    "pkce_s256_verified",
    "no_authorization_header",
    "client_id_matches"
  )) {
    if (!isTRUE(evidence[[name]])) return(FALSE)
  }
  if (
    !identical(evidence[["body_secret_present"]], !jwt) ||
      !identical(evidence[["assertion_present"]], jwt)
  ) {
    return(FALSE)
  }
  if (jwt) {
    if (
      !is.null(evidence[["body_secret_matches"]]) ||
        !identical(
          evidence[["assertion_algorithm"]],
          spec[["client_assertion_alg"]]
        )
    ) {
      return(FALSE)
    }
    for (name in c(
      "assertion_type_valid",
      "assertion_identity_matches",
      "assertion_audience_matches",
      "assertion_jti_present",
      "assertion_times_valid"
    )) {
      if (!isTRUE(evidence[[name]])) return(FALSE)
    }
  } else {
    if (!isTRUE(evidence[["body_secret_matches"]])) {
      return(FALSE)
    }
    for (name in c(
      "assertion_type_valid",
      "assertion_algorithm",
      "assertion_identity_matches",
      "assertion_audience_matches",
      "assertion_jti_present",
      "assertion_times_valid"
    )) {
      if (!is.null(evidence[[name]])) return(FALSE)
    }
  }
  if (identical(method, "private_key_jwt")) {
    if (!isTRUE(evidence[["assertion_key_id_matches"]])) return(FALSE)
  } else if (!is.null(evidence[["assertion_key_id_matches"]])) {
    return(FALSE)
  }
  checks <- evidence[["suite_checks"]]
  setequal(
    names(checks),
    c(
      "EnsureAuthorizationRequestContainsPkceCodeChallenge",
      openid_auth_checks(method)
    )
  ) &&
    !anyDuplicated(names(checks)) &&
    all(vapply(checks, isTRUE, logical(1)))
}

openid_public_capability_matches <- function(probe, context, manifest) {
  for (name in c("plan_id", "suite_id")) {
    if (
      !openid_string(context[[paste0("public_probe_", name)]]) ||
        !identical(probe[[name]], context[[paste0("public_probe_", name)]])
    ) {
      return(FALSE)
    }
  }
  for (name in c(
    "run_id",
    "attempt_id",
    "checkout_revision",
    "source_revision",
    "package_version"
  )) {
    if (!identical(probe[[name]], context[[name]])) return(FALSE)
  }
  spec <- manifest[["plans"]][[manifest[["capability_probes"]][[
    "public_client"
  ]][["plan"]]]]
  identical(probe[["module"]], "oidcc-client-test") &&
    openid_string(probe[["suite_id"]]) &&
    openid_string(probe[["plan_id"]]) &&
    !identical(probe[["plan_id"]], context[["plan_id"]]) &&
    identical(
      openid_variant_key(probe[["variant"]]),
      openid_variant_key(spec[["plan_variant"]])
    ) &&
    identical(probe[["suite_status"]], "INTERRUPTED") &&
    isTRUE(probe[["issuer_exact"]]) &&
    isTRUE(probe[["discovery_rejected"]]) &&
    isTRUE(probe[["package_matches"]]) &&
    identical(probe[["none_advertised"]], FALSE) &&
    identical(probe[["conformance_credited"]], FALSE) &&
    identical(probe[["public_client_authentication_tested"]], FALSE)
}

openid_public_capability <- function(
  stack,
  manifest,
  context,
  redirect_uri,
  library
) {
  probe <- manifest[["capability_probes"]][["public_client"]]
  spec <- manifest[["plans"]][[probe[["plan"]]]]
  plan <- openid_suite_plan(stack, manifest, redirect_uri, .spec = spec)
  module <- openid_suite_module(stack, plan, probe[["module"]])
  metadata <- httr2::request(paste0(
    module[["issuer"]],
    ".well-known/openid-configuration"
  )) |>
    httr2::req_options(cainfo = stack[["ca"]], followlocation = FALSE) |>
    httr2::req_timeout(10) |>
    httr2::req_perform() |>
    httr2::resp_body_json(simplifyVector = FALSE)
  if (
    !identical(metadata[["issuer"]], module[["issuer"]]) ||
      "none" %in% unlist(metadata[["token_endpoint_auth_methods_supported"]])
  ) {
    stop(
      "Pinned public-client capability changed; review the manifest and coverage gap"
    )
  }
  result <- callr::r(
    function(issuer, ca, expected_package) {
      Sys.setenv(CURL_SSL_BACKEND = "openssl", CURL_CA_BUNDLE = ca)
      actual <- normalizePath(
        getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
        winslash = "/"
      )
      failure <- tryCatch(
        shinyOAuth::oauth_provider_oidc_discover(
          issuer,
          token_auth_style = "public"
        ),
        error = identity
      )
      list(
        package_matches = identical(actual, expected_package),
        package_version = as.character(utils::packageVersion("shinyOAuth")),
        discovery_rejected = inherits(failure, "shinyOAuth_config_error") &&
          identical(
            failure[["context"]][["requested_token_auth_style"]],
            "public"
          ) &&
          !"none" %in% unlist(failure[["context"]][["methods"]])
      )
    },
    args = list(
      module[["issuer"]],
      stack[["ca"]],
      normalizePath(file.path(library, "shinyOAuth"), winslash = "/")
    ),
    libpath = c(library, .libPaths())
  )
  if (
    !isTRUE(result[["package_matches"]]) ||
      !isTRUE(result[["discovery_rejected"]])
  ) {
    stop("Public-client discovery gap was not reproduced")
  }
  openid_suite_cancel(stack, module)
  c(
    context[c("run_id", "attempt_id", "checkout_revision", "source_revision")],
    list(
      plan_id = plan[["id"]],
      suite_id = module[["id"]],
      module = module[["name"]],
      variant = module[["variant"]],
      suite_status = "INTERRUPTED",
      issuer_exact = TRUE,
      none_advertised = FALSE,
      conformance_credited = FALSE,
      public_client_authentication_tested = FALSE
    ),
    result
  )
}
