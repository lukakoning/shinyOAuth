openid_signing_plan <- function(plan) {
  identical(
    plan[["spec"]][["plan"]],
    "fapi2-message-signing-final-client-test-plan"
  )
}

openid_signing_parameters <- function(logs, module) {
  # Existing FAPI collectors inspect effective PAR parameters. Keep the raw
  # log intact for the separate JAR checks; never replace authentication fields.
  lapply(logs, function(event) {
    if (
      identical(event[["http"]], "incoming") &&
        identical(
          event[["incoming_path"]],
          paste0(sub("^https://[^/]+", "", module[["issuer"]]), "par")
        )
    ) {
      form <- event[["incoming_body_form_params"]]
      claims <- openid_fapi_decode(form[["request"]])[[2L]]
      for (name in c(
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method"
      )) {
        form[[name]] <- claims[[name]]
      }
      event[["incoming_body_form_params"]] <- form
    }
    event
  })
}

openid_signing_checks <- function() {
  c(
    "ExtractRequestObjectFromPAREndpointRequest",
    "FAPI2ValidateRequestObjectSigningAlg",
    "FAPIValidateRequestObjectMediaType",
    "ValidateRequestObjectClaims",
    "ValidateRequestObjectMaxAge",
    "EnsureRequestObjectDoesNotContainRequestOrRequestUri",
    "EnsureRequestObjectDoesNotContainSubWithClientId",
    "ValidateRequestObjectSignature",
    "EnsureMatchingRedirectUriInRequestObject",
    "EnsureRequestObjectContainsCodeChallengeWhenUsingPAR"
  )
}

openid_signing_signature <- function(jwt, jwk) {
  # Verify the ES256 signature without the time checks in jose::jwt_decode_sig,
  # so the intentionally expired response can still prove a valid signature.
  tryCatch(
    {
      parts <- strsplit(jwt, ".", fixed = TRUE)[[1L]]
      if (length(parts) != 3L) {
        return(FALSE)
      }
      signature <- openssl::base64_decode(paste0(
        chartr("-_", "+/", parts[[3L]]),
        strrep("=", (4L - nchar(parts[[3L]]) %% 4L) %% 4L)
      ))
      if (length(signature) != 64L) {
        return(FALSE)
      }
      key <- jose::read_jwk(as.character(jsonlite::toJSON(
        jwk,
        auto_unbox = TRUE
      )))
      isTRUE(openssl::signature_verify(
        charToRaw(paste(parts[1:2], collapse = ".")),
        openssl::ecdsa_write(signature[1:32], signature[33:64]),
        hash = openssl::sha256,
        pubkey = key
      ))
    },
    error = function(...) FALSE
  )
}

openid_signing_evidence <- function(logs, module, plan, expectation) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(e) identical(e[["testId"]], module[["id"]]),
        logical(1)
      ))
  ) {
    stop("Message Signing logs do not belong to this suite instance")
  }
  discovery <- identical(expectation[["outcome"]], "discovery_rejected")
  proof <- list(
    suite_id = module[["id"]],
    stage = if (discovery) "discovery" else "signed_exchange"
  )
  if (discovery) {
    return(proof)
  }
  par <- Filter(
    function(e) {
      identical(e[["http"]], "incoming") &&
        identical(
          e[["incoming_path"]],
          paste0(sub("^https://[^/]+", "", module[["issuer"]]), "par")
        )
    },
    logs
  )
  jars <- lapply(par, function(e) {
    openid_fapi_decode(e[["incoming_body_form_params"]][["request"]])
  })
  client <- plan[["registration"]]
  finite <- function(x) is.numeric(x) && length(x) == 1L && is.finite(x)
  proof[["jar_count"]] <- length(jars)
  proof[["jar_metadata_valid"]] <- length(jars) > 0L &&
    all(vapply(
      seq_along(jars),
      function(i) {
        jwt <- jars[[i]]
        header <- jwt[[1L]]
        claims <- jwt[[2L]]
        form <- par[[i]][["incoming_body_form_params"]]
        identical(header[["alg"]], "ES256") &&
          identical(header[["typ"]], "oauth-authz-req+jwt") &&
          identical(header[["kid"]], plan[["credentials"]][["key_id"]]) &&
          identical(claims[["iss"]], client[["client_id"]]) &&
          identical(claims[["client_id"]], client[["client_id"]]) &&
          identical(claims[["aud"]], module[["issuer"]]) &&
          identical(claims[["redirect_uri"]], client[["redirect_uri"]]) &&
          identical(claims[["response_type"]], "code") &&
          identical(claims[["response_mode"]], "jwt") &&
          identical(claims[["scope"]], client[["scope"]]) &&
          openid_string(claims[["nonce"]]) &&
          nchar(claims[["nonce"]]) >= 16L &&
          openid_string(claims[["jti"]]) &&
          finite(claims[["iat"]]) &&
          finite(claims[["exp"]]) &&
          finite(claims[["nbf"]]) &&
          claims[["exp"]] > claims[["iat"]] &&
          claims[["exp"]] - claims[["iat"]] <= 60 &&
          claims[["nbf"]] <= claims[["iat"]] &&
          !any(
            c("sub", "request", "request_uri", "max_age") %in% names(claims)
          ) &&
          setequal(
            names(form),
            c(
              "client_id",
              "request",
              "client_assertion_type",
              "client_assertion"
            )
          )
      },
      logical(1)
    ))
  proof[["jar_signatures_valid"]] <- length(jars) > 0L &&
    all(vapply(
      par,
      function(e) {
        openid_signing_signature(
          e[["incoming_body_form_params"]][["request"]],
          client[["jwks"]][["keys"]][[1L]]
        )
      },
      logical(1)
    ))
  checks <- openid_signing_checks()
  proof[["suite_checks"]] <- setNames(
    lapply(checks, function(source) {
      any(vapply(
        logs,
        function(e) {
          identical(e[["src"]], source) &&
            if (identical(source, "ValidateRequestObjectMaxAge")) {
              is.null(e[["result"]]) &&
                identical(
                  e[["msg"]],
                  "Request object does not contain a max_age claim"
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
  redirects <- Filter(
    function(e) {
      identical(e[["src"]], "SendJARMResponseWitResponseModeQuery") &&
        openid_string(e[["uri"]])
    },
    logs
  )
  proof[["jarm_response_count"]] <- length(redirects)
  uri <- if (length(redirects) == 1L) redirects[[1L]][["uri"]] else ""
  params <- shiny::parseQueryString(sub("^[^?]*\\??", "", uri))
  value <- params[["response"]]
  parts <- if (openid_string(value)) {
    strsplit(value, ".", fixed = TRUE)[[1L]]
  } else {
    character()
  }
  jwt <- if (length(parts) >= 2L) {
    openid_fapi_decode(paste(parts[[1L]], parts[[2L]], "inspection", sep = "."))
  } else {
    NULL
  }
  header <- jwt[[1L]]
  claims <- jwt[[2L]]
  case <- expectation[["jarm_error"]]
  proof[["jarm_query_only"]] <- identical(
    sub("\\?.*$", "", uri),
    client[["redirect_uri"]]
  ) &&
    identical(names(params), "response") &&
    !is.null(jwt)
  proof[["jarm_issuer_variant"]] <- if (identical(case, "without-iss")) {
    is.null(claims[["iss"]])
  } else if (identical(case, "with-invalid-iss")) {
    openid_string(claims[["iss"]]) &&
      !identical(claims[["iss"]], module[["issuer"]])
  } else {
    identical(claims[["iss"]], module[["issuer"]])
  }
  proof[["jarm_audience_variant"]] <- if (identical(case, "without-aud")) {
    is.null(claims[["aud"]])
  } else if (identical(case, "with-invalid-aud")) {
    openid_string(claims[["aud"]]) &&
      !identical(claims[["aud"]], client[["client_id"]])
  } else {
    identical(claims[["aud"]], client[["client_id"]])
  }
  now <- floor(as.numeric(Sys.time()))
  proof[["jarm_expiry_variant"]] <- if (identical(case, "without-exp")) {
    is.null(claims[["exp"]])
  } else if (identical(case, "with-expired-exp")) {
    finite(claims[["exp"]]) && claims[["exp"]] < now - 60
  } else {
    finite(claims[["exp"]]) &&
      claims[["exp"]] > now &&
      claims[["exp"]] <= now + 610
  }
  states <- lapply(jars, function(jwt) jwt[[2L]][["state"]])
  proof[["jarm_state_variant"]] <- if (identical(case, "without-state")) {
    is.null(claims[["state"]])
  } else if (identical(case, "with-invalid-state")) {
    openid_string(claims[["state"]]) &&
      !identical(claims[["state"]], states[[1L]])
  } else {
    openid_string(claims[["state"]]) &&
      all(vapply(states, identical, logical(1), claims[["state"]]))
  }
  signed <- Filter(
    function(e) {
      identical(e[["src"]], "SignJARMResponse") &&
        identical(e[["result"]], "SUCCESS")
    },
    logs
  )
  key <- if (length(signed) == 1L) {
    tryCatch(
      jsonlite::fromJSON(
        signed[[1L]][["jarm_response"]][["public_jwk"]],
        simplifyVector = FALSE
      ),
      error = function(...) NULL
    )
  } else {
    NULL
  }
  proof[["jarm_signature_variant"]] <- if (
    identical(case, "signature-is-not-none")
  ) {
    identical(header[["alg"]], "none") && endsWith(value, ".")
  } else {
    verified <- openid_signing_signature(value, key)
    identical(header[["alg"]], "ES256") &&
      length(signed) == 1L &&
      if (identical(case, "with-invalid-sig")) {
        !verified &&
          openid_signing_signature(
            signed[[1L]][["jarm_response"]][["verifiable_jws"]],
            key
          )
      } else {
        verified
      }
  }
  proof[["jarm_code_present"]] <- openid_string(claims[["code"]]) &&
    !"error" %in% names(claims)
  token <- Filter(
    function(e) {
      identical(e[["http"]], "incoming") &&
        identical(
          e[["incoming_path"]],
          paste0(sub("^https://[^/]+", "", module[["issuer"]]), "token")
        )
    },
    logs
  )
  proof[["jarm_code_redemption_valid"]] <- if (
    identical(expectation[["outcome"]], "callback_rejected")
  ) {
    length(token) == 0L
  } else {
    length(token) > 0L &&
      all(vapply(
        token,
        function(e) {
          identical(
            e[["incoming_body_form_params"]][["code"]],
            claims[["code"]]
          )
        },
        logical(1)
      ))
  }
  proof
}

openid_signing_matches <- function(result, expectation) {
  proof <- result[["message_signing"]]
  if (!identical(proof[["suite_id"]], result[["suite_id"]])) {
    return(FALSE)
  }
  if (identical(expectation[["outcome"]], "discovery_rejected")) {
    return(identical(
      proof,
      list(suite_id = result[["suite_id"]], stage = "discovery")
    ))
  }
  identical(proof[["stage"]], "signed_exchange") &&
    openid_count(proof[["jar_count"]], 1L) &&
    proof[["jar_count"]] <= 2L &&
    identical(proof[["jarm_response_count"]], 1L) &&
    all(vapply(
      c(
        "jar_metadata_valid",
        "jar_signatures_valid",
        "jarm_query_only",
        "jarm_issuer_variant",
        "jarm_audience_variant",
        "jarm_expiry_variant",
        "jarm_state_variant",
        "jarm_signature_variant",
        "jarm_code_present",
        "jarm_code_redemption_valid"
      ),
      function(name) isTRUE(proof[[name]]),
      logical(1)
    )) &&
    setequal(names(proof[["suite_checks"]]), openid_signing_checks()) &&
    !anyDuplicated(names(proof[["suite_checks"]])) &&
    all(vapply(proof[["suite_checks"]], isTRUE, logical(1)))
}
