openid_mtls_credentials <- function(stack) {
  directory <- tempfile("client-tls-", tmpdir = stack[["output"]])
  dir.create(directory)
  directory <- normalizePath(directory, winslash = "/")
  user <- if (.Platform[["OS.type"]] == "windows") {
    character()
  } else {
    identity <- vapply(
      c("-u", "-g"),
      function(arg) {
        trimws(processx::run("id", arg)[["stdout"]])
      },
      character(1)
    )
    if (!all(grepl("^[0-9]+$", identity))) {
      stop("Invalid TLS file owner")
    }
    c("--user", paste(identity, collapse = ":"))
  }
  openid_docker(
    c(
      "run",
      "--rm",
      user,
      "--network",
      "none",
      "--entrypoint",
      "openssl",
      "--mount",
      paste0("type=bind,source=", directory, ",target=/output"),
      stack[["lock"]][["images"]][["proxy"]],
      "req",
      "-x509",
      "-nodes",
      "-days",
      "2",
      "-newkey",
      "rsa:2048",
      "-keyout",
      "/output/key.pem",
      "-out",
      "/output/cert.pem",
      "-subj",
      "/CN=shinyOAuth-local-client",
      "-addext",
      "extendedKeyUsage=clientAuth"
    ),
    file.path(directory, "generate.log")
  )
  certificate <- file.path(directory, "cert.pem")
  list(
    cert_file = certificate,
    key_file = file.path(directory, "key.pem"),
    certificate = paste(readLines(certificate), collapse = "\n"),
    fingerprint = paste(
      openssl::sha1(openssl::write_der(openssl::read_cert(certificate))),
      collapse = ""
    )
  )
}

openid_mtls_peers <- function(stack) {
  lines <- strsplit(
    openid_compose(stack, c("logs", "--no-color", "proxy")),
    "\n",
    fixed = TRUE
  )[[1L]]
  lines <- lines[grepl('\\{"tls_peer":', lines)]
  lapply(lines, function(line) {
    jsonlite::fromJSON(
      sub('^.*?(\\{"tls_peer":.*)$', "\\1", line),
      simplifyVector = FALSE
    )[["tls_peer"]]
  })
}

openid_mtls_controls <- function(
  root,
  stack,
  plan,
  expectation,
  context,
  transport,
  library
) {
  alternate <- openid_mtls_credentials(stack)
  lapply(c("wrong", "forged_header", "missing"), function(kind) {
    row <- openid_run_case(
      root,
      stack,
      plan,
      expectation,
      context,
      transport,
      library,
      .resource_control = c(
        list(kind = kind),
        alternate[c("cert_file", "key_file")]
      )
    )
    logs <- openid_api(stack, paste0("/api/log/", row[["suite_id"]]))
    incoming <- Filter(
      function(e) {
        identical(e[["http"]], "incoming") &&
          endsWith(e[["incoming_path"]], "/open-banking/v1.1/accounts")
      },
      logs
    )
    peers <- openid_mtls_peers(stack)
    matched <- if (length(incoming) == 1L) {
      Filter(
        function(p) {
          identical(
            p[["request_id"]],
            incoming[[1L]][["incoming_headers"]][["x-openid-request-id"]]
          ) &&
            identical(p[["path"]], incoming[[1L]][["incoming_path"]]) &&
            identical(p[["method"]], "GET") &&
            identical(p[["listener"]], 8444L)
        },
        peers
      )
    } else {
      list()
    }
    observed <- if (length(matched) == 1L) {
      matched[[1L]][["fingerprint"]]
    } else {
      NULL
    }
    row[["mtls_control"]] <- list(
      kind = kind,
      actual_peer_verified = identical(
        observed,
        if (kind == "missing") "" else alternate[["fingerprint"]]
      ) &&
        !identical(observed, plan[["credentials"]][["mtls"]][["fingerprint"]]),
      suite_detected = any(vapply(
        logs,
        function(e) {
          identical(
            e[["src"]],
            if (kind == "missing") {
              "CheckForClientCertificate"
            } else {
              "EnsureClientCertificateMatches"
            }
          ) &&
            identical(e[["result"]], "FAILURE")
        },
        logical(1)
      ))
    )
    row
  })
}

openid_mtls_controls_match <- function(rows, context, regular_ids) {
  if (length(rows) != 3L) {
    return(FALSE)
  }
  kinds <- vapply(
    rows,
    function(row) row[["mtls_control"]][["kind"]],
    character(1)
  )
  ids <- vapply(rows, function(row) row[["suite_id"]], character(1))
  if (
    anyDuplicated(ids) ||
      any(ids %in% regular_ids) ||
      anyDuplicated(kinds) ||
      !setequal(kinds, c("wrong", "forged_header", "missing"))
  ) {
    return(FALSE)
  }
  all(vapply(
    rows,
    function(row) {
      kind <- row[["mtls_control"]][["kind"]]
      resource <- row[["app"]][["resource"]]
      identity <- c(
        "run_id",
        "attempt_id",
        "checkout_revision",
        "source_revision",
        "plan_id"
      )
      all(vapply(
        identity,
        function(name) identical(row[[name]], context[[name]]),
        logical(1)
      )) &&
        identical(
          row[["module"]],
          "fapi2-security-profile-final-client-test-happy-path"
        ) &&
        row[["variant"]][["client_auth_type"]] %in%
          c("private_key_jwt", "mtls") &&
        identical(row[["variant"]][["sender_constrain"]], "mtls") &&
        identical(row[["suite_result"]], "FAILED") &&
        identical(
          row[["suite_status"]],
          if (kind == "missing") "INTERRUPTED" else "FINISHED"
        ) &&
        isTRUE(row[["mtls_control"]][["actual_peer_verified"]]) &&
        isTRUE(row[["mtls_control"]][["suite_detected"]]) &&
        isTRUE(row[["app"]][["mtls_configured"]]) &&
        openid_app_matches(
          row[["app"]],
          list(
            outcome = if (
              identical(row[["variant"]][["fapi_client_type"]], "oidc")
            ) {
              "authenticated"
            } else {
              "authorized"
            }
          ),
          paste0(context[["run_id"]], "-", row[["suite_id"]]),
          context[["package_version"]]
        ) &&
        openid_transport_matches(
          row,
          list(
            outcome = if (
              identical(row[["variant"]][["fapi_client_type"]], "oidc")
            ) {
              "authenticated"
            } else {
              "authorized"
            }
          ),
          context
        ) &&
        identical(resource[["api"]], "raw_attacker_request") &&
        identical(resource[["control_kind"]], kind) &&
        isTRUE(resource[["done"]]) &&
        identical(
          resource[["http_status"]],
          if (kind == "missing") 400L else 200L
        ) &&
        identical(resource[["response_marker_valid"]], kind != "missing")
    },
    logical(1)
  ))
}

openid_mtls_info_checks <- function() {
  c(
    RemoveMtlsEndpointAliasesFromServerConfiguration = "Removed mtls_endpoint_aliases from server configuration",
    SetTokenEndpointToMtlsTokenEndpoint = "Set token endpoint to be the MTLS token endpoint",
    SetParEndpointToMtlsParEndpoint = "Set PAR endpoint to be the MTLS PAR endpoint",
    SetUserinfoEndpointToMtlsUserinfoEndpoint = "Set userinfo endpoint to be the MTLS userinfo endpoint"
  )
}

openid_mtls_checks <- function(
  discovery = FALSE,
  callback = FALSE,
  fallback = FALSE,
  method = "private_key_jwt",
  oidc = FALSE,
  token_rejected = FALSE
) {
  authentication <- if (method == "mtls") {
    c(
      "AddTLSClientAuthToServerConfiguration",
      "EnsureClientIdIsPresentOnTokenRequest",
      "EnsureNoClientAssertionSentToTokenEndpoint"
    )
  }
  if (discovery) {
    return(c(
      openid_fapi_pre_token_checks(TRUE),
      if (method == "mtls") "AddTLSClientAuthToServerConfiguration"
    ))
  }
  c(
    authentication,
    if (callback) {
      if (method == "mtls") {
        "EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR"
      } else {
        openid_fapi_pre_token_checks(FALSE)
      }
    } else {
      c(
        if (method == "private_key_jwt") {
          c(
            openid_auth_checks("private_key_jwt"),
            "ValidateClientAssertionClaimsForPAREndpoint",
            "ValidateClientAssertionAudClaimIsIssuerAsString"
          )
        },
        "EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR",
        "ValidateCodeVerifierWithS256"
      )
    },
    "CheckForClientCertificate",
    "EnsureClientCertificateMatches",
    if (fallback) {
      c(
        "RemoveMtlsEndpointAliasesFromServerConfiguration",
        "SetTokenEndpointToMtlsTokenEndpoint",
        if (method == "mtls") "SetParEndpointToMtlsParEndpoint",
        if (oidc) "SetUserinfoEndpointToMtlsUserinfoEndpoint"
      )
    },
    if (!callback && !token_rejected) {
      c(
        "EnsureBearerAccessTokenNotInParams",
        "ExtractBearerAccessTokenFromHeader",
        "RequireBearerAccessToken"
      )
    }
  )
}

openid_mtls_evidence <- function(
  logs,
  module,
  plan,
  peers,
  expectation = NULL
) {
  if (
    !length(logs) ||
      !all(vapply(
        logs,
        function(e) identical(e[["testId"]], module[["id"]]),
        logical(1)
      ))
  ) {
    stop("mTLS logs do not belong to this suite instance")
  }
  discovery <- endsWith(module[["name"]], "discovery-issuer-mismatch")
  callback <- grepl(
    "authorization-response|invalid-state|missing-state",
    module[["name"]]
  )
  method <- plan[["spec"]][["plan_variant"]][["client_auth_type"]]
  oidc <- identical(
    plan[["spec"]][["plan_variant"]][["fapi_client_type"]],
    "oidc"
  )
  if (oidc && is.null(expectation)) {
    stop("OIDC mTLS evidence requires this module's expectation")
  }
  token_rejected <- oidc && identical(expectation[["outcome"]], "rejected")
  fallback <- endsWith(module[["name"]], "happy-path-no-mtls-endpoint-aliases")
  path <- sub("^https://[^/]+", "", module[["issuer"]])
  mtls_path <- sub("^/test/", "/test-mtls/", path)
  requests <- function(endpoint) {
    Filter(
      function(e) {
        identical(e[["http"]], "incoming") &&
          e[["incoming_path"]] %in% paste0(c(path, mtls_path), endpoint)
      },
      logs
    )
  }
  par <- requests("par")
  token <- requests("token")
  resource <- requests("open-banking/v1.1/accounts")
  userinfo <- requests("userinfo")
  authorization <- requests("authorize")
  forms <- c(par, token)
  client_id <- plan[["registration"]][["client_id"]]
  assertions <- if (method == "private_key_jwt") {
    lapply(forms, function(e) {
      openid_fapi_decode(e[["incoming_body_form_params"]][["client_assertion"]])
    })
  } else {
    list()
  }
  checks <- openid_mtls_checks(
    discovery,
    callback,
    fallback,
    method,
    oidc,
    token_rejected
  )
  peer_valid <- function(
    requests,
    listener = 8444L,
    fingerprint = plan[["credentials"]][["mtls"]][["fingerprint"]]
  ) {
    length(requests) > 0L &&
      all(vapply(
        requests,
        function(e) {
          matches <- Filter(
            function(p) {
              identical(
                p[["request_id"]],
                e[["incoming_headers"]][["x-openid-request-id"]]
              )
            },
            peers
          )
          length(matches) == 1L &&
            identical(matches[[1L]][["path"]], e[["incoming_path"]]) &&
            identical(matches[[1L]][["method"]], e[["incoming_method"]]) &&
            identical(matches[[1L]][["listener"]], listener) &&
            identical(
              matches[[1L]][["fingerprint"]],
              fingerprint
            )
        },
        logical(1)
      ))
  }
  same <- function(values, f) {
    length(values) > 0L && all(vapply(values, f, logical(1)))
  }
  par_form <- if (length(par)) {
    par[[1L]][["incoming_body_form_params"]]
  } else {
    list()
  }
  scope <- openid_fapi_oauth_scope(par)
  proof <- list(
    suite_id = module[["id"]],
    client_authentication = if (method == "mtls") "tls_client_auth" else method,
    sender_constraint = "mtls",
    stage = if (discovery) {
      "discovery"
    } else if (callback) {
      "callback"
    } else if (token_rejected) {
      "id_token"
    } else {
      "resource"
    },
    discovery_request_count = sum(vapply(
      logs,
      function(e) {
        identical(e[["http"]], "incoming") &&
          identical(
            e[["incoming_path"]],
            if (oidc) {
              paste0(path, ".well-known/openid-configuration")
            } else {
              paste0(
                "/.well-known/oauth-authorization-server",
                sub("/+$", "", path)
              )
            }
          )
      },
      logical(1)
    )),
    par_request_count = length(par),
    token_request_count = length(token),
    authorization_request_count = length(authorization),
    userinfo_request_count = length(requests("userinfo")),
    resource_request_count = length(resource),
    oauth_scope_valid = scope,
    request_credentials_valid = same(forms, function(e) {
      form <- e[["incoming_body_form_params"]]
      identical(e[["incoming_method"]], "POST") &&
        identical(form[["client_id"]], client_id) &&
        (if (method == "mtls") {
          !any(c("client_assertion", "client_assertion_type") %in% names(form))
        } else {
          identical(
            form[["client_assertion_type"]],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
          )
        }) &&
        !"client_secret" %in% names(form) &&
        !"authorization" %in% names(e[["incoming_headers"]])
    }),
    assertion_metadata_valid = same(assertions, function(jwt) {
      h <- jwt[[1L]]
      c <- jwt[[2L]]
      identical(h[["alg"]], "ES256") &&
        identical(h[["kid"]], plan[["credentials"]][["key_id"]]) &&
        identical(c[["iss"]], client_id) &&
        identical(c[["sub"]], client_id) &&
        identical(c[["aud"]], module[["issuer"]]) &&
        openid_string(c[["jti"]]) &&
        is.numeric(c[["iat"]]) &&
        is.numeric(c[["exp"]]) &&
        length(c[["iat"]]) == 1L &&
        length(c[["exp"]]) == 1L &&
        is.finite(c[["iat"]]) &&
        is.finite(c[["exp"]]) &&
        c[["exp"]] > c[["iat"]] &&
        c[["exp"]] - c[["iat"]] <= 300
    }),
    assertion_jtis_distinct = !anyDuplicated(vapply(
      assertions,
      function(jwt) jwt[[2L]][["jti"]],
      character(1)
    )),
    authorization_par_only = length(authorization) == 1L &&
      {
        query <- authorization[[1L]][["incoming_query_string_params"]]
        identical(authorization[[1L]][["incoming_method"]], "GET") &&
          setequal(names(query), c("client_id", "request_uri")) &&
          identical(query[["client_id"]], client_id) &&
          openid_string(query[["request_uri"]])
      },
    pkce_s256_verified = identical(
      par_form[["code_challenge_method"]],
      "S256"
    ) &&
      identical(par_form[["response_type"]], "code") &&
      openid_string(par_form[["code_challenge"]]) &&
      (callback ||
        same(token, function(e) {
          identical(
            openid_fapi_hash(e[["incoming_body_form_params"]][[
              "code_verifier"
            ]]),
            par_form[["code_challenge"]]
          )
        })),
    endpoint_selection_valid = same(par, function(e) {
      identical(
        e[["incoming_path"]],
        paste0(if (fallback && method != "mtls") path else mtls_path, "par")
      )
    }) &&
      (callback ||
        same(token, function(e) {
          identical(e[["incoming_path"]], paste0(mtls_path, "token"))
        })),
    par_peer_valid = if (fallback && method != "mtls") {
      peer_valid(par, 8443L, "")
    } else {
      peer_valid(par)
    },
    token_peer_valid = peer_valid(token),
    resource_peer_valid = peer_valid(resource),
    no_dpop = all(vapply(
      c(par, token, userinfo, resource),
      function(e) !"dpop" %in% names(e[["incoming_headers"]]),
      logical(1)
    )),
    token_response_oauth_only = same(
      Filter(
        function(e) {
          identical(e[["src"]], "CreateTokenEndpointResponse") &&
            identical(e[["result"]], "SUCCESS")
        },
        logs
      ),
      function(e) {
        body <- e[["Created token endpoint response"]]
        openid_string(body[["access_token"]]) &&
          !"id_token" %in% names(body) &&
          identical(tolower(body[["token_type"]]), "bearer")
      }
    ),
    resource_bearer_valid = same(resource, function(e) {
      identical(e[["incoming_method"]], "GET") &&
        openid_string(e[["incoming_headers"]][["authorization"]]) &&
        startsWith(e[["incoming_headers"]][["authorization"]], "Bearer ")
    }),
    suite_checks = setNames(
      lapply(checks, function(src) {
        any(vapply(
          logs,
          function(e) {
            info <- openid_mtls_info_checks()
            if (src %in% names(info)) {
              return(
                identical(e[["src"]], src) &&
                  is.null(e[["result"]]) &&
                  identical(e[["msg"]], unname(info[[src]]))
              )
            }
            identical(e[["src"]], src) &&
              (identical(e[["result"]], "SUCCESS") ||
                (discovery &&
                  is.null(e[["result"]]) &&
                  identical(
                    e[["issuer"]],
                    paste0(module[["issuer"]], "INVALID")
                  ) &&
                  identical(
                    e[["msg"]],
                    "Added invalid issuer to server configuration"
                  )))
          },
          logical(1)
        ))
      }),
      checks
    )
  )
  if (method == "mtls") {
    proof[["assertion_metadata_valid"]] <- NULL
    proof[["assertion_jtis_distinct"]] <- NULL
  }
  if (oidc) {
    proof[["oauth_scope_valid"]] <- NULL
    proof[["token_response_oauth_only"]] <- NULL
    proof[["oidc_scope_nonce_valid"]] <- same(par, function(e) {
      form <- e[["incoming_body_form_params"]]
      identical(form[["scope"]], plan[["registration"]][["scope"]]) &&
        "openid" %in% strsplit(form[["scope"]], " ", fixed = TRUE)[[1L]] &&
        openid_string(form[["nonce"]]) &&
        nchar(form[["nonce"]]) >= 16L
    })
    bodies <- lapply(
      Filter(
        function(e) {
          identical(e[["src"]], "CreateTokenEndpointResponse") &&
            identical(e[["result"]], "SUCCESS")
        },
        logs
      ),
      function(e) e[["Created token endpoint response"]]
    )
    body <- if (length(bodies) == 1L) bodies[[1L]] else list()
    id <- body[["id_token"]]
    # Inspect claims only; the installed client validates the actual signature.
    # An empty signature is needed for the suite's intentional alg=none case.
    parts <- if (openid_string(id)) {
      strsplit(id, ".", fixed = TRUE)[[1L]]
    } else {
      character()
    }
    decoded <- if (length(parts) %in% c(2L, 3L)) {
      openid_fapi_decode(paste(c(parts[1:2], "inspection"), collapse = "."))
    }
    proof[["oidc_token_response_observed"]] <- length(bodies) == 1L &&
      openid_string(body[["access_token"]]) &&
      is.list(decoded) &&
      identical(tolower(body[["token_type"]]), "bearer")
    proof[["id_token_variant_observed"]] <- openid_mtls_id_token_variant(
      decoded,
      module[["name"]],
      module[["issuer"]],
      client_id
    )
    nonce <- decoded[[2L]][["nonce"]]
    proof[["id_token_nonce_result"]] <- if (is.null(nonce)) {
      "missing"
    } else if (identical(nonce, par_form[["nonce"]])) {
      "matched"
    } else {
      "mismatched"
    }
    proof[["userinfo_peer_valid"]] <- peer_valid(userinfo)
    proof[["userinfo_endpoint_valid"]] <- same(userinfo, function(e) {
      identical(e[["incoming_path"]], paste0(mtls_path, "userinfo"))
    })
    proof[["issued_bearer_tokens_valid"]] <- same(
      c(userinfo, resource),
      function(e) {
        identical(e[["incoming_method"]], "GET") &&
          openid_string(body[["access_token"]]) &&
          identical(
            e[["incoming_headers"]][["authorization"]],
            paste("Bearer", body[["access_token"]])
          )
      }
    )
  }
  if (!discovery) {
    proof <- c(proof, openid_mtls_state_evidence(par))
  }
  proof
}

openid_mtls_state_evidence <- function(par) {
  states <- lapply(par, function(e) e[["incoming_body_form_params"]][["state"]])
  state <- if (length(states)) states[[1L]] else NULL
  list(
    state_characters = if (openid_string(state)) nchar(state) else 0L,
    state_reference_valid = openid_string(state) &&
      grepl("^[A-Za-z0-9_-]{22,128}$", state) &&
      all(vapply(states, identical, logical(1), state))
  )
}

openid_mtls_matches <- function(result, expectation) {
  p <- result[["fapi"]]
  discovery <- identical(expectation[["outcome"]], "discovery_rejected")
  callback <- identical(expectation[["outcome"]], "callback_rejected")
  method <- result[["variant"]][["client_auth_type"]]
  oidc <- identical(result[["variant"]][["fapi_client_type"]], "oidc")
  token_rejected <- oidc && identical(expectation[["outcome"]], "rejected")
  if (
    !method %in% c("private_key_jwt", "mtls") ||
      !identical(p[["suite_id"]], result[["suite_id"]]) ||
      !identical(
        p[["client_authentication"]],
        if (method == "mtls") "tls_client_auth" else method
      ) ||
      !identical(p[["sender_constraint"]], "mtls") ||
      !identical(
        p[["stage"]],
        if (discovery) {
          "discovery"
        } else if (callback) {
          "callback"
        } else if (token_rejected) {
          "id_token"
        } else {
          "resource"
        }
      )
  ) {
    return(FALSE)
  }
  counts <- c(
    par_request_count = if (discovery) 0L else 1L,
    authorization_request_count = if (discovery) 0L else 1L,
    token_request_count = if (discovery || callback) 0L else 1L,
    userinfo_request_count = if (
      oidc && !discovery && !callback && !token_rejected
    ) {
      1L
    } else {
      0L
    },
    discovery_request_count = 1L,
    resource_request_count = if (discovery || callback || token_rejected) {
      0L
    } else {
      1L
    }
  )
  if (
    !all(vapply(
      names(counts),
      function(name) identical(p[[name]], counts[[name]]),
      logical(1)
    ))
  ) {
    return(FALSE)
  }
  flags <- if (discovery) {
    character()
  } else {
    c(
      if (oidc) "oidc_scope_nonce_valid" else "oauth_scope_valid",
      "request_credentials_valid",
      if (method == "private_key_jwt") {
        c("assertion_metadata_valid", "assertion_jtis_distinct")
      },
      "authorization_par_only",
      "endpoint_selection_valid",
      "pkce_s256_verified",
      "par_peer_valid",
      "no_dpop",
      if (!callback) {
        c(
          "token_peer_valid",
          if (oidc) {
            c("oidc_token_response_observed", "id_token_variant_observed")
          } else {
            "token_response_oauth_only"
          },
          if (!token_rejected) {
            c("resource_peer_valid", "resource_bearer_valid")
          },
          if (oidc && !token_rejected) {
            c(
              "userinfo_peer_valid",
              "userinfo_endpoint_valid",
              "issued_bearer_tokens_valid"
            )
          }
        )
      }
    )
  }
  if (!all(vapply(flags, function(name) isTRUE(p[[name]]), logical(1)))) {
    return(FALSE)
  }
  checks <- openid_mtls_checks(
    discovery,
    callback,
    endsWith(result[["module"]], "happy-path-no-mtls-endpoint-aliases"),
    method,
    oidc,
    token_rejected
  )
  if (
    !setequal(names(p[["suite_checks"]]), checks) ||
      anyDuplicated(names(p[["suite_checks"]])) ||
      !all(vapply(p[["suite_checks"]], isTRUE, logical(1)))
  ) {
    return(FALSE)
  }
  if (callback && !openid_http_callback_matches(result, expectation)) {
    return(FALSE)
  }
  if (oidc && !discovery && !callback) {
    expected_nonce <- if (
      endsWith(result[["module"]], "invalid-missing-nonce")
    ) {
      "missing"
    } else if (endsWith(result[["module"]], "invalid-nonce")) {
      "mismatched"
    } else {
      "matched"
    }
    if (!identical(p[["id_token_nonce_result"]], expected_nonce)) return(FALSE)
  }
  resource <- result[["app"]][["resource"]]
  if (discovery || callback || token_rejected) {
    return(is.null(resource))
  }
  all(vapply(
    c("done", "succeeded", "response_marker_valid"),
    function(name) isTRUE(resource[[name]]),
    logical(1)
  )) &&
    identical(resource[["api"]], "connection") &&
    identical(resource[["transport"]], "main_process") &&
    identical(resource[["pid"]], result[["app"]][["transport"]][["app_pid"]]) &&
    identical(resource[["expiry_unknown"]], FALSE) &&
    identical(resource[["connection_unusable"]], FALSE)
}

openid_mtls_id_token_variant <- function(decoded, module, issuer, client_id) {
  if (!is.list(decoded) || length(decoded) != 2L) {
    return(FALSE)
  }
  header <- decoded[[1L]]
  claims <- decoded[[2L]]
  fault <- sub("^fapi2-security-profile-final-client-test-", "", module)
  alg <- switch(
    fault,
    `invalid-null-alg` = "none",
    `invalid-alternate-alg` = "RS256",
    "ES256"
  )
  audience <- unlist(claims[["aud"]], use.names = FALSE)
  issuer_valid <- if (fault == "invalid-missing-iss") {
    is.null(claims[["iss"]])
  } else if (fault == "invalid-iss") {
    openid_string(claims[["iss"]]) && !identical(claims[["iss"]], issuer)
  } else {
    identical(claims[["iss"]], issuer)
  }
  audience_valid <- if (fault == "invalid-missing-aud") {
    is.null(claims[["aud"]])
  } else if (fault == "invalid-aud") {
    length(audience) > 0L && !client_id %in% audience
  } else if (fault == "invalid-secondary-aud") {
    client_id %in%
      audience &&
      length(audience) > 1L &&
      any(audience != client_id)
  } else {
    identical(audience, client_id) &&
      (fault != "valid-aud-as-array" || is.list(claims[["aud"]]))
  }
  numeric_scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && is.finite(value)
  }
  expiry_valid <- if (fault == "invalid-missing-exp") {
    is.null(claims[["exp"]])
  } else {
    numeric_scalar(claims[["exp"]]) &&
      numeric_scalar(claims[["iat"]]) &&
      if (fault == "invalid-expired-exp") {
        claims[["exp"]] < claims[["iat"]]
      } else {
        claims[["exp"]] > claims[["iat"]]
      }
  }
  identical(header[["alg"]], alg) &&
    issuer_valid &&
    audience_valid &&
    expiry_valid
}
