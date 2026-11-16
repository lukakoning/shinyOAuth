openid_fapi_decode <- function(value) {
  tryCatch(
    {
      if (!openid_string(value)) {
        return(NULL)
      }
      parts <- strsplit(value, ".", fixed = TRUE)[[1L]]
      if (length(parts) != 3L || !all(nzchar(parts))) {
        return(NULL)
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
}

openid_fapi_hash <- function(value) {
  sub(
    "=+$",
    "",
    chartr(
      "+/",
      "-_",
      as.character(openssl::base64_encode(openssl::sha256(charToRaw(value))))
    )
  )
}

openid_fapi_oauth_scope <- function(par) {
  length(par) > 0L &&
    all(vapply(
      par,
      function(event) {
        form <- event[["incoming_body_form_params"]]
        identical(form[["scope"]], "accounts") && !"nonce" %in% names(form)
      },
      logical(1)
    ))
}

openid_fapi_checks <- function(positive, nonce = TRUE) {
  c(
    openid_auth_checks("private_key_jwt"),
    "ValidateClientAssertionClaimsForPAREndpoint",
    "ValidateClientAssertionAudClaimIsIssuerAsString",
    "EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR",
    "ValidateCodeVerifierWithS256",
    "ValidateDpopProofTokenRequest",
    "ValidateDpopProofSignature",
    "EnsureDpopProofJtiNotAlreadyUsed",
    if (nonce) "ValidateTokenEndpointDpopProofNonce",
    if (nonce && positive) "ValidateResourceEndpointDpopProofNonce",
    if (positive) {
      c("ValidateDpopProofResourceRequest", "ExtractDpopAccessTokenFromHeader")
    }
  )
}

openid_fapi_reference_evidence <- function(logs, module) {
  par <- Filter(
    function(event) {
      identical(event[["http"]], "incoming") &&
        identical(
          event[["incoming_path"]],
          paste0(
            sub("^https://[^/]+", "", module[["issuer"]]),
            "par"
          )
        )
    },
    logs
  )
  states <- lapply(par, function(event) {
    event[["incoming_body_form_params"]][["state"]]
  })
  state <- if (length(states)) states[[1L]] else NULL
  list(
    state_characters = if (openid_string(state)) nchar(state) else 0L,
    state_reference_valid = openid_string(state) &&
      grepl("^[A-Za-z0-9_-]{22,128}$", state) &&
      all(vapply(states, identical, logical(1), state))
  )
}

openid_fapi_evidence <- function(logs, module, plan, expectation) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(e) identical(e[["testId"]], module[["id"]]),
        logical(1)
      ))
  ) {
    stop("FAPI logs do not belong to this suite instance")
  }
  if (
    expectation[["outcome"]] %in% c("discovery_rejected", "callback_rejected")
  ) {
    proof <- openid_fapi_pre_token_evidence(logs, module, plan, expectation)
    if (
      identical(plan[["state_transport"]], "reference") &&
        !identical(expectation[["outcome"]], "discovery_rejected")
    ) {
      proof <- c(proof, openid_fapi_reference_evidence(logs, module))
    }
    return(proof)
  }
  requests <- function(endpoint) {
    Filter(
      function(e) {
        identical(e[["http"]], "incoming") &&
          identical(
            e[["incoming_path"]],
            paste0(sub("^https://[^/]+", "", module[["issuer"]]), endpoint)
          )
      },
      logs
    )
  }
  par <- requests("par")
  authorization <- requests("authorize")
  token <- requests("token")
  userinfo <- requests("userinfo")
  resource <- requests("open-banking/v1.1/accounts")
  if (!length(par) || length(authorization) != 1L || !length(token)) {
    stop("Missing actual FAPI requests")
  }
  positive <- expectation[["outcome"]] %in% c("authenticated", "authorized")
  oauth_only <- identical(
    plan[["spec"]][["plan_variant"]][["fapi_client_type"]],
    "plain_oauth"
  )
  no_nonce <- identical(
    module[["name"]],
    "fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce"
  )
  client_id <- plan[["registration"]][["client_id"]]
  success <- function(source) {
    any(vapply(
      logs,
      function(e) {
        identical(e[["src"]], source) && identical(e[["result"]], "SUCCESS")
      },
      logical(1)
    ))
  }
  forms <- c(par, token)
  assertions <- lapply(forms, function(e) {
    openid_fapi_decode(e[["incoming_body_form_params"]][["client_assertion"]])
  })
  par_query <- tail(par, 1L)[[1L]][["incoming_body_form_params"]]
  auth_query <- authorization[[1L]][["incoming_query_string_params"]]
  proof_requests <- Filter(
    function(e) openid_string(e[["incoming_headers"]][["dpop"]]),
    c(par, token, userinfo, resource)
  )
  proofs <- lapply(proof_requests, function(e) {
    openid_fapi_decode(e[["incoming_headers"]][["dpop"]])
  })
  all_true <- function(values, predicate) {
    length(values) > 0L && all(vapply(values, predicate, logical(1)))
  }
  jwt_valid <- function(jwt) {
    header <- jwt[[1L]]
    claims <- jwt[[2L]]
    identical(header[["alg"]], "ES256") &&
      identical(header[["kid"]], plan[["credentials"]][["key_id"]]) &&
      identical(claims[["iss"]], client_id) &&
      identical(claims[["sub"]], client_id) &&
      identical(claims[["aud"]], module[["issuer"]]) &&
      openid_string(claims[["jti"]]) &&
      is.numeric(claims[["iat"]]) &&
      length(claims[["iat"]]) == 1L &&
      is.finite(claims[["iat"]]) &&
      is.numeric(claims[["exp"]]) &&
      length(claims[["exp"]]) == 1L &&
      is.finite(claims[["exp"]]) &&
      claims[["exp"]] > claims[["iat"]] &&
      claims[["exp"]] - claims[["iat"]] <= 300
  }
  keys <- lapply(proofs, function(jwt) jwt[[1L]][["jwk"]])
  key_strings <- vapply(
    keys,
    function(key) {
      as.character(jsonlite::toJSON(
        key[c("crv", "kty", "x", "y")],
        auto_unbox = TRUE
      ))
    },
    character(1)
  )
  proofs_valid <- all(vapply(
    seq_along(proofs),
    function(i) {
      jwt <- proofs[[i]]
      request <- proof_requests[[i]]
      header <- jwt[[1L]]
      claims <- jwt[[2L]]
      identical(header[["alg"]], "ES256") &&
        identical(header[["typ"]], "dpop+jwt") &&
        identical(keys[[i]][["kty"]], "EC") &&
        identical(keys[[i]][["crv"]], "P-256") &&
        all(vapply(keys[[i]][c("x", "y")], openid_string, logical(1))) &&
        !"d" %in% names(keys[[i]]) &&
        identical(claims[["htm"]], request[["incoming_method"]]) &&
        identical(
          claims[["htu"]],
          paste0(
            sub("^(https://[^/]+).*$", "\\1", module[["issuer"]]),
            request[["incoming_path"]]
          )
        ) &&
        openid_string(claims[["jti"]]) &&
        is.numeric(claims[["iat"]]) &&
        length(claims[["iat"]]) == 1L &&
        is.finite(claims[["iat"]])
    },
    logical(1)
  ))
  resource_proofs <- lapply(c(userinfo, resource), function(e) {
    jwt <- openid_fapi_decode(e[["incoming_headers"]][["dpop"]])
    authorization <- e[["incoming_headers"]][["authorization"]]
    openid_string(authorization) &&
      startsWith(authorization, "DPoP ") &&
      identical(
        jwt[[2L]][["ath"]],
        openid_fapi_hash(substring(authorization, 6L))
      )
  })
  nonce_retry <- function(requests) {
    if (length(requests) != 2L) {
      return(FALSE)
    }
    nonces <- lapply(requests, function(e) {
      openid_fapi_decode(e[["incoming_headers"]][["dpop"]])[[2L]][["nonce"]]
    })
    openid_string(nonces[[2L]]) && !identical(nonces[[1L]], nonces[[2L]])
  }
  proof <- list(
    suite_id = module[["id"]],
    par_request_count = length(par),
    token_request_count = length(token),
    authorization_request_count = length(authorization),
    userinfo_request_count = length(userinfo),
    resource_request_count = length(resource),
    par_authenticated = all_true(forms, function(e) {
      identical(e[["incoming_method"]], "POST") &&
        identical(e[["incoming_body_form_params"]][["client_id"]], client_id) &&
        identical(
          e[["incoming_body_form_params"]][["client_assertion_type"]],
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) &&
        !"client_secret" %in% names(e[["incoming_body_form_params"]]) &&
        !"authorization" %in% names(e[["incoming_headers"]])
    }),
    assertion_metadata_valid = all_true(assertions, jwt_valid),
    assertion_jtis_distinct = !anyDuplicated(vapply(
      assertions,
      function(jwt) jwt[[2L]][["jti"]],
      character(1)
    )),
    authorization_par_only = identical(
      authorization[[1L]][["incoming_method"]],
      "GET"
    ) &&
      setequal(names(auth_query), c("client_id", "request_uri")) &&
      identical(auth_query[["client_id"]], client_id) &&
      openid_string(auth_query[["request_uri"]]),
    code_flow = identical(par_query[["response_type"]], "code") &&
      all_true(token, function(e) {
        identical(
          e[["incoming_body_form_params"]][["grant_type"]],
          "authorization_code"
        )
      }),
    pkce_s256_verified = identical(
      par_query[["code_challenge_method"]],
      "S256"
    ) &&
      all_true(token, function(e) {
        verifier <- e[["incoming_body_form_params"]][["code_verifier"]]
        openid_string(verifier) &&
          grepl("^[A-Za-z0-9._~-]{43,128}$", verifier) &&
          identical(openid_fapi_hash(verifier), par_query[["code_challenge"]])
      }),
    dpop_proofs_valid = length(proofs) >=
      length(token) + length(userinfo) + length(resource) &&
      proofs_valid,
    dpop_key_consistent = length(unique(key_strings)) == 1L,
    dpop_jtis_distinct = !anyDuplicated(vapply(
      proofs,
      function(jwt) jwt[[2L]][["jti"]],
      character(1)
    )),
    resource_ath_valid = if (positive) {
      length(resource_proofs) > 0L && all(unlist(resource_proofs))
    } else {
      length(resource_proofs) == 0L
    },
    nonce_handshake_valid = if (no_nonce) {
      length(par) == 1L &&
        length(token) == 1L &&
        length(resource) == 1L &&
        length(userinfo) == (if (oauth_only) 0L else 1L) &&
        all(vapply(
          proofs,
          function(jwt) is.null(jwt[[2L]][["nonce"]]),
          logical(1)
        ))
    } else {
      (nonce_retry(par) || nonce_retry(token)) &&
        (!positive || (nonce_retry(userinfo) || nonce_retry(resource)))
    },
    resource_get = if (positive) {
      all_true(c(userinfo, resource), function(e) {
        identical(e[["incoming_method"]], "GET")
      })
    } else {
      !length(userinfo) && !length(resource)
    },
    suite_checks = setNames(
      lapply(openid_fapi_checks(positive, !no_nonce), success),
      openid_fapi_checks(positive, !no_nonce)
    )
  )
  if (oauth_only) {
    responses <- Filter(
      function(event) {
        identical(event[["src"]], "CreateTokenEndpointResponse") &&
          identical(event[["result"]], "SUCCESS")
      },
      logs
    )
    proof[["oauth_scope_valid"]] <- openid_fapi_oauth_scope(par)
    proof[["token_response_oauth_only"]] <- length(responses) == 1L &&
      {
        body <- responses[[1L]][["Created token endpoint response"]]
        is.list(body) &&
          openid_string(body[["access_token"]]) &&
          !"id_token" %in% names(body)
      }
    if (identical(expectation[["advisory_policy"]], "state_length_over_128")) {
      states <- lapply(par, function(event) {
        event[["incoming_body_form_params"]][["state"]]
      })
      state <- states[[1L]]
      findings <- Filter(
        function(event) {
          isTRUE(
            event[["result"]] %in% c("WARNING", "FAILURE", "ERROR", "REVIEW")
          )
        },
        logs
      )
      proof[["state_characters"]] <- if (openid_string(state)) {
        nchar(state)
      } else {
        0L
      }
      proof[["state_length_advisory_verified"]] <- length(findings) == 1L &&
        identical(findings[[1L]][["src"]], "CheckStateLength") &&
        identical(findings[[1L]][["result"]], "WARNING") &&
        identical(
          findings[[1L]][["msg"]],
          "State contains in excess of 128 characters. This may introduce interoperability issues."
        ) &&
        openid_string(state) &&
        all(vapply(states, identical, logical(1), state))
    }
  }
  if (identical(plan[["state_transport"]], "reference")) {
    proof <- c(proof, openid_fapi_reference_evidence(logs, module))
  }
  proof
}

openid_fapi_matches <- function(result, expectation) {
  if (
    expectation[["outcome"]] %in% c("discovery_rejected", "callback_rejected")
  ) {
    return(openid_fapi_pre_token_matches(result, expectation))
  }
  proof <- result[["fapi"]]
  positive <- expectation[["outcome"]] %in% c("authenticated", "authorized")
  oauth_only <- identical(
    result[["variant"]][["fapi_client_type"]],
    "plain_oauth"
  )
  if (
    positive &&
      !identical(
        expectation[["outcome"]],
        if (oauth_only) "authorized" else "authenticated"
      )
  ) {
    return(FALSE)
  }
  if (
    oauth_only &&
      (!isTRUE(proof[["oauth_scope_valid"]]) ||
        !isTRUE(proof[["token_response_oauth_only"]]))
  ) {
    return(FALSE)
  }
  if (
    !is.null(expectation[["advisory_policy"]]) &&
      !openid_fapi_state_advisory_matches(result, expectation)
  ) {
    return(FALSE)
  }
  if (!identical(proof[["suite_id"]], result[["suite_id"]])) {
    return(FALSE)
  }
  for (name in c("par_request_count", "token_request_count")) {
    if (!openid_count(proof[[name]], 1L) || proof[[name]] > 2L) return(FALSE)
  }
  if (!identical(proof[["authorization_request_count"]], 1L)) {
    return(FALSE)
  }
  for (name in c("userinfo_request_count", "resource_request_count")) {
    required <- positive &&
      !(oauth_only && identical(name, "userinfo_request_count"))
    if (
      !openid_count(proof[[name]], if (required) 1L else 0L) ||
        proof[[name]] > if (required) 2L else 0L
    ) {
      return(FALSE)
    }
  }
  for (name in c(
    "par_authenticated",
    "assertion_metadata_valid",
    "assertion_jtis_distinct",
    "authorization_par_only",
    "code_flow",
    "pkce_s256_verified",
    "dpop_proofs_valid",
    "dpop_key_consistent",
    "dpop_jtis_distinct",
    "resource_ath_valid",
    "nonce_handshake_valid",
    "resource_get"
  )) {
    if (!isTRUE(proof[[name]])) return(FALSE)
  }
  resource <- result[["app"]][["resource"]]
  if (positive) {
    if (!is.null(expectation[["resource_api"]])) {
      if (
        !identical(resource[["api"]], expectation[["resource_api"]]) ||
          !identical(resource[["expiry_unknown"]], FALSE) ||
          !identical(resource[["connection_unusable"]], FALSE)
      ) {
        return(FALSE)
      }
    }
    if (
      !all(vapply(
        c("done", "succeeded", "response_marker_valid"),
        function(name) isTRUE(resource[[name]]),
        logical(1)
      )) ||
        !identical(resource[["transport"]], "main_process") ||
        !identical(
          resource[["pid"]],
          result[["app"]][["transport"]][["app_pid"]]
        )
    ) {
      return(FALSE)
    }
  } else if (!is.null(resource)) {
    return(FALSE)
  }
  checks <- proof[["suite_checks"]]
  setequal(
    names(checks),
    openid_fapi_checks(
      positive,
      !endsWith(result[["module"]], "happy-path-no-dpop-nonce")
    )
  ) &&
    !anyDuplicated(names(checks)) &&
    all(vapply(checks, isTRUE, logical(1)))
}

openid_fapi_state_advisory_matches <- function(result, expectation) {
  identical(expectation[["advisory_policy"]], "state_length_over_128") &&
    identical(expectation[["outcome"]], "authorized") &&
    identical(result[["variant"]][["fapi_client_type"]], "plain_oauth") &&
    result[["module"]] %in%
      c(
        "fapi2-security-profile-final-client-test-happy-path",
        "fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce",
        "fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases"
      ) &&
    identical(result[["suite_result"]], "WARNING") &&
    openid_count(result[["fapi"]][["state_characters"]], 129L) &&
    isTRUE(result[["fapi"]][["state_length_advisory_verified"]])
}

openid_fapi_pre_token_checks <- function(discovery) {
  if (discovery) {
    return("ChangeIssuerInServerConfigurationToBeInvalid")
  }
  c(
    setdiff(
      openid_auth_checks("private_key_jwt"),
      "ValidateClientAssertionClaims"
    ),
    "ValidateClientAssertionClaimsForPAREndpoint",
    "ValidateClientAssertionAudClaimIsIssuerAsString",
    "EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR"
  )
}

openid_fapi_pre_token_evidence <- function(logs, module, plan, expectation) {
  discovery <- identical(expectation[["outcome"]], "discovery_rejected")
  requests <- function(endpoint) {
    Filter(
      function(e) {
        identical(e[["http"]], "incoming") &&
          identical(
            e[["incoming_path"]],
            paste0(sub("^https://[^/]+", "", module[["issuer"]]), endpoint)
          )
      },
      logs
    )
  }
  par <- requests("par")
  authorization <- requests("authorize")
  client_id <- plan[["registration"]][["client_id"]]
  checks <- openid_fapi_pre_token_checks(discovery)
  metadata_path <- if (
    identical(
      plan[["spec"]][["plan_variant"]][["fapi_client_type"]],
      "plain_oauth"
    )
  ) {
    paste0(
      "/.well-known/oauth-authorization-server",
      sub("/+$", "", sub("^https://[^/]+", "", module[["issuer"]]))
    )
  } else {
    paste0(
      sub("^https://[^/]+", "", module[["issuer"]]),
      ".well-known/openid-configuration"
    )
  }
  proof <- list(
    suite_id = module[["id"]],
    stage = if (discovery) "discovery" else "callback",
    discovery_request_count = sum(vapply(
      logs,
      function(event) {
        identical(event[["http"]], "incoming") &&
          identical(event[["incoming_path"]], metadata_path)
      },
      logical(1)
    )),
    par_request_count = length(par),
    authorization_request_count = length(authorization),
    token_request_count = length(requests("token")),
    userinfo_request_count = length(requests("userinfo")),
    resource_request_count = length(requests("open-banking/v1.1/accounts")),
    suite_checks = setNames(
      lapply(checks, function(source) {
        any(vapply(
          logs,
          function(e) {
            identical(e[["src"]], source) &&
              if (discovery) {
                is.null(e[["result"]]) &&
                  identical(
                    e[["msg"]],
                    "Added invalid issuer to server configuration"
                  ) &&
                  identical(
                    e[["issuer"]],
                    paste0(module[["issuer"]], "INVALID")
                  )
              } else {
                identical(e[["result"]], "SUCCESS")
              }
          },
          logical(1)
        ))
      }),
      checks
    )
  )
  if (discovery) {
    return(proof)
  }
  proof[["par_authenticated"]] <- length(par) > 0L &&
    all(vapply(
      par,
      function(e) {
        form <- e[["incoming_body_form_params"]]
        jwt <- openid_fapi_decode(form[["client_assertion"]])
        claims <- jwt[[2L]]
        identical(e[["incoming_method"]], "POST") &&
          identical(form[["client_id"]], client_id) &&
          identical(
            form[["client_assertion_type"]],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
          ) &&
          !"client_secret" %in% names(form) &&
          !"authorization" %in% names(e[["incoming_headers"]]) &&
          identical(jwt[[1L]][["alg"]], "ES256") &&
          identical(jwt[[1L]][["kid"]], plan[["credentials"]][["key_id"]]) &&
          identical(claims[["iss"]], client_id) &&
          identical(claims[["sub"]], client_id) &&
          identical(claims[["aud"]], module[["issuer"]]) &&
          openid_string(claims[["jti"]])
      },
      logical(1)
    ))
  proof[["assertion_jtis_distinct"]] <- !anyDuplicated(vapply(
    par,
    function(e) {
      openid_fapi_decode(e[["incoming_body_form_params"]][[
        "client_assertion"
      ]])[[2L]][["jti"]]
    },
    character(1)
  ))
  proof[["pkce_s256_present"]] <- length(par) > 0L &&
    all(vapply(
      par,
      function(e) {
        form <- e[["incoming_body_form_params"]]
        identical(form[["response_type"]], "code") &&
          identical(form[["code_challenge_method"]], "S256") &&
          openid_string(form[["code_challenge"]]) &&
          grepl("^[A-Za-z0-9_-]{43}$", form[["code_challenge"]])
      },
      logical(1)
    ))
  proof[["authorization_par_only"]] <- length(authorization) == 1L &&
    {
      e <- authorization[[1L]]
      query <- e[["incoming_query_string_params"]]
      identical(e[["incoming_method"]], "GET") &&
        setequal(names(query), c("client_id", "request_uri")) &&
        identical(query[["client_id"]], client_id) &&
        openid_string(query[["request_uri"]])
    }
  if (
    identical(
      plan[["spec"]][["plan_variant"]][["fapi_client_type"]],
      "plain_oauth"
    )
  ) {
    proof[["oauth_scope_valid"]] <- openid_fapi_oauth_scope(par)
  }
  proof
}

openid_fapi_pre_token_matches <- function(result, expectation) {
  proof <- result[["fapi"]]
  discovery <- identical(expectation[["outcome"]], "discovery_rejected")
  if (
    !identical(proof[["suite_id"]], result[["suite_id"]]) ||
      !identical(
        proof[["stage"]],
        if (discovery) "discovery" else "callback"
      ) ||
      !is.null(result[["app"]][["resource"]])
  ) {
    return(FALSE)
  }
  for (name in c(
    "token_request_count",
    "userinfo_request_count",
    "resource_request_count"
  )) {
    if (!identical(proof[[name]], 0L)) return(FALSE)
  }
  if (discovery) {
    if (
      !identical(proof[["discovery_request_count"]], 1L) ||
        !identical(proof[["par_request_count"]], 0L) ||
        !identical(proof[["authorization_request_count"]], 0L)
    ) {
      return(FALSE)
    }
  } else {
    if (
      identical(result[["variant"]][["fapi_client_type"]], "plain_oauth") &&
        (!isTRUE(proof[["oauth_scope_valid"]]) ||
          !isTRUE(result[["app"]][["oauth_only_configured"]]))
    ) {
      return(FALSE)
    }
    if (!openid_http_callback_matches(result, expectation)) {
      return(FALSE)
    }
    if (
      !openid_count(proof[["discovery_request_count"]], 1L) ||
        !openid_count(proof[["par_request_count"]], 1L) ||
        proof[["par_request_count"]] > 2L ||
        !identical(proof[["authorization_request_count"]], 1L) ||
        !all(vapply(
          c(
            "par_authenticated",
            "assertion_jtis_distinct",
            "pkce_s256_present",
            "authorization_par_only"
          ),
          function(name) isTRUE(proof[[name]]),
          logical(1)
        ))
    ) {
      return(FALSE)
    }
  }
  checks <- proof[["suite_checks"]]
  setequal(names(checks), openid_fapi_pre_token_checks(discovery)) &&
    !anyDuplicated(names(checks)) &&
    all(vapply(checks, isTRUE, logical(1)))
}

openid_observe_http_callback <- function(tab, origin) {
  observation <- new.env(parent = emptyenv())
  tab[["Network"]][["enable"]]()
  tab[["Network"]][["responseReceived"]](function(params) {
    response <- params[["response"]]
    if (
      identical(params[["type"]], "Document") &&
        startsWith(response[["url"]], paste0(origin, "/"))
    ) {
      observation[["request_id"]] <- params[["requestId"]]
      observation[["status"]] <- response[["status"]]
      observation[["headers"]] <- response[["headers"]]
    }
    invisible(NULL)
  })
  observation
}

openid_wait_http_callback <- function(app, browser, tab, initial, observation) {
  path <- file.path(app[["config"]][["audit_directory"]], "callback-http.json")
  openid_wait(
    function() {
      if (
        !app[["process"]][["is_alive"]]() ||
          !browser[["get_browser"]]()[["get_process"]]()[["is_alive"]]()
      ) {
        stop("App or browser stopped before the HTTP rejection")
      }
      # A CDP call also services Chromote's event loop and delivers response events.
      content <- openid_browser_value(
        tab,
        "document.body && document.body.textContent"
      )
      if (!file.exists(path) || is.null(observation[["request_id"]])) {
        return(NULL)
      }
      snapshot <- jsonlite::read_json(path)
      if (!identical(snapshot[["run_id"]], app[["config"]][["run_id"]])) {
        stop("Stale HTTP rejection snapshot")
      }
      if (!openid_string(content)) {
        return(NULL)
      }
      http <- snapshot[["http_rejection"]]
      http[["body_matches"]] <- identical(
        http[["content_digest"]],
        paste(openssl::sha256(charToRaw(trimws(content))), collapse = "")
      )
      http[["content_digest"]] <- NULL
      headers <- observation[["headers"]]
      names(headers) <- tolower(names(headers))
      http[["browser_status_400"]] <- identical(
        as.integer(observation[["status"]]),
        400L
      )
      http[["headers_verified"]] <- identical(
        headers[["cache-control"]],
        "no-store"
      ) &&
        identical(headers[["referrer-policy"]], "no-referrer") &&
        startsWith(headers[["content-type"]], "text/plain")
      http[["no_callback_module"]] <- is.null(openid_app_snapshot(
        tab,
        app[["config"]][["run_id"]]
      )) &&
        identical(snapshot[["session_number"]], initial[["session_number"]]) &&
        identical(snapshot[["app_instance"]], initial[["app_instance"]]) &&
        identical(snapshot[["cache_instance"]], initial[["cache_instance"]])
      snapshot[["http_rejection"]] <- NULL
      list(app = snapshot, http = http)
    },
    "Real-browser HTTP callback rejection",
    30
  )
}

openid_http_callback_matches <- function(result, expectation) {
  http <- result[["callback_http"]]
  identical(result[["callback_cleaned"]], FALSE) &&
    identical(http[["status"]], 400L) &&
    identical(http[["state_present"]], expectation[["state_present"]]) &&
    identical(http[["issuer_present"]], expectation[["issuer_present"]]) &&
    all(vapply(
      c(
        "no_store",
        "no_referrer",
        "plain_text",
        "credentials_absent",
        "body_matches",
        "browser_status_400",
        "headers_verified",
        "no_callback_module"
      ),
      function(name) isTRUE(http[[name]]),
      logical(1)
    ))
}
