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
  positive <- identical(expectation[["outcome"]], "authenticated")
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
  list(
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
      all(lengths(list(par, token, userinfo, resource)) == 1L) &&
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
}

openid_fapi_matches <- function(result, expectation) {
  proof <- result[["fapi"]]
  positive <- identical(expectation[["outcome"]], "authenticated")
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
    if (
      !openid_count(proof[[name]], if (positive) 1L else 0L) ||
        proof[[name]] > if (positive) 2L else 0L
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
