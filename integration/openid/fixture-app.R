openid_fixture_digest <- function(value) {
  paste(openssl::sha256(charToRaw(value)), collapse = "")
}

openid_fixture_jarm_error <- function(content) {
  messages <- c(
    "without-iss" = "JARM payload missing required iss claim",
    "with-invalid-iss" = "JARM issuer does not match provider issuer",
    "without-aud" = "JARM aud claim is invalid",
    "with-invalid-aud" = "JARM aud claim does not include client_id",
    "without-exp" = "JARM payload missing required exp claim",
    "with-expired-exp" = "JARM payload expired",
    "with-invalid-sig" = "JARM signature is invalid",
    "signature-is-not-none" = "JARM alg=none is not allowed",
    "without-state" = "JARM payload missing required state",
    "with-invalid-state" = "State store entry is missing or malformed"
  )
  index <- which(vapply(
    messages,
    function(message) grepl(message, content, fixed = TRUE),
    logical(1)
  ))
  if (length(index) == 1L) names(messages)[[index]] else NULL
}

openid_fixture_app <- function(config) {
  advanced <- config[["advanced"]]
  use_jar <- isTRUE(config[["message_signing"]]) || !is.null(advanced)
  use_dpop <- identical(advanced[["sender"]], "dpop") ||
    (isTRUE(config[["fapi"]]) &&
      !identical(config[["sender_constraint"]], "mtls"))
  required <- c(
    "issuer",
    "origin",
    "client_id",
    "run_id",
    "response_mode"
  )
  if (
    !all(required %in% names(config)) ||
      !all(vapply(
        config[required],
        function(value) {
          is.character(value) && length(value) == 1L && !is.na(value)
        },
        logical(1)
      )) ||
      !startsWith(config[["issuer"]], "https://") ||
      !grepl("^https://localhost:[0-9]+$", config[["origin"]]) ||
      !config[["response_mode"]] %in% c("query", "form_post", "jwt")
  ) {
    stop("Invalid private OpenID fixture configuration")
  }
  method <- config[["client_auth_type"]]
  if (is.null(method)) {
    method <- "client_secret_basic"
  }
  style <- switch(
    method,
    none = "public",
    client_secret_basic = "header",
    client_secret_post = "body",
    client_secret_jwt = "client_secret_jwt",
    private_key_jwt = "private_key_jwt",
    mtls = "tls_client_auth"
  )
  if (is.null(style)) {
    stop("Unsupported fixture client authentication method")
  }
  audit <- new.env(parent = emptyenv())
  audit[["sessions"]] <- 0L
  audit[["form_post"]] <- NULL
  audit[["cache_updates"]] <- 0L
  audit[["cache_hits"]] <- 0L
  audit[["jwks_digest"]] <- NULL
  audit[["prefetch_completed"]] <- FALSE
  audit[["prefetched_key_ids"]] <- list()
  random <- function() paste(format(openssl::rand_bytes(16)), collapse = "")
  app_instance <- random()
  cache_instance <- random()
  cache <- cachem::cache_mem(max_age = 3600)
  cache_get <- cache[["get"]]
  cache_set <- cache[["set"]]
  cache[["get"]] <- function(key, missing = NULL) {
    value <- cache_get(key, missing = missing)
    if (is.list(value) && !is.null(value[["jwks"]])) {
      audit[["cache_hits"]] <- audit[["cache_hits"]] + 1L
    }
    value
  }
  cache[["set"]] <- function(key, value) {
    if (is.list(value) && !is.null(value[["jwks"]])) {
      audit[["cache_updates"]] <- audit[["cache_updates"]] + 1L
      audit[["jwks_digest"]] <- openid_fixture_digest(
        as.character(jsonlite::toJSON(value[["jwks"]], auto_unbox = TRUE))
      )
    }
    cache_set(key, value)
  }
  options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.audit_hook = openid_fixture_hook(
      config[["audit_directory"]],
      config[["run_id"]],
      config[["package_path"]],
      config[["ca"]],
      expected_timeout = config[["expected_timeout"]]
    )
  )
  discover <- if (isTRUE(config[["oauth_only"]])) {
    shinyOAuth::oauth_provider_oauth_discover
  } else {
    shinyOAuth::oauth_provider_oidc_discover
  }
  discovery_args <- list(
    issuer = config[["issuer"]],
    token_auth_style = style,
    allowed_token_types = if (use_dpop) {
      "DPoP"
    } else {
      "Bearer"
    },
    authorization_request_front_channel_mode = if (
      isTRUE(config[["fapi"]]) || isTRUE(advanced[["par"]])
    ) {
      "minimal"
    } else {
      "compat"
    },
    jwks_cache = cache
  )
  if (!isTRUE(config[["oauth_only"]])) {
    discovery_args[["id_token_profile"]] <- if (isTRUE(config[["fapi"]])) {
      "fapi2"
    } else {
      "oidc"
    }
  }
  if (!is.null(config[["extra_auth_params"]])) {
    discovery_args[["extra_auth_params"]] <- config[["extra_auth_params"]]
  }
  if (isTRUE(config[["message_signing"]])) {
    discovery_args[["userinfo_allowed_algs"]] <- c("ES256", "EdDSA", "Ed25519")
  }
  if (!is.null(advanced)) {
    discovery_args[["userinfo_signed_jwt_required"]] <- TRUE
    discovery_args[["userinfo_allowed_algs"]] <- "RS256"
  }
  if (!is.null(config[["resource_indicators"]])) {
    discovery_args[["userinfo_required"]] <- FALSE
    discovery_args[["userinfo_id_token_match"]] <- FALSE
  }
  provider <- tryCatch(
    do.call(discover, discovery_args),
    error = function(error) {
      if (!isTRUE(config[["report_setup_failure"]])) {
        stop(error)
      }
      NULL
    }
  )
  snapshot <- function(
    token = NULL,
    authenticated = FALSE,
    error = NULL,
    session_number = 0L,
    refresh = NULL
  ) {
    observed <- openid_fixture_audit(
      config[["audit_directory"]],
      config[["run_id"]],
      as.character(utils::packageVersion("shinyOAuth")),
      config[["worker_probes"]]
    )
    observed[["transport"]][["backend"]] <- config[["transport"]]
    observed[["transport"]][["backend_verified"]] <- config[[
      "backend_verified"
    ]]
    observed[["transport"]][["cache_scope"]] <- if (
      identical(config[["transport"]], "sync")
    ) {
      "main_process"
    } else {
      "serialized_per_dispatch"
    }
    for (name in c("counts", "errors", "claims", "reasons")) {
      audit[[name]] <- observed[[name]]
    }
    allowed_errors <- c(
      "token_exchange_error",
      "token_refresh_error",
      "invalid_state",
      "callback_iss_validation_error",
      "issuer_missing",
      "issuer_mismatch",
      "http_callback_rejected",
      "invalid_request",
      "invalid_target",
      "access_denied",
      "login_required",
      "interaction_required",
      "discovery_setup_error",
      "logged_out"
    )
    jsonlite::toJSON(
      list(
        run_id = config[["run_id"]],
        transport = observed[["transport"]],
        ready = !is.null(provider),
        mtls_configured = !is.null(provider) &&
          identical(config[["sender_constraint"]], "mtls") &&
          identical(provider@token_auth_style, style) &&
          (style %in%
            c("private_key_jwt", "tls_client_auth") ||
            (!is.null(advanced) && identical(style, "header"))) &&
          provider@mtls_client_certificate_bound_access_tokens &&
          client@mtls_certificate_bound_access_tokens &&
          !client@mtls_require_observed_cnf &&
          identical(
            client@mtls_client_cert_file,
            config[["mtls"]][["cert_file"]]
          ) &&
          identical(
            client@mtls_client_key_file,
            config[["mtls"]][["key_file"]]
          ) &&
          is.null(client@dpop_private_key),
        state_transport = if (is.null(provider)) {
          NULL
        } else {
          client@state_transport
        },
        oauth_only_configured = !is.null(provider) &&
          !provider@infer_oidc_from_issuer &&
          !provider@use_nonce &&
          !provider@id_token_required &&
          !provider@id_token_validation &&
          !provider@userinfo_required &&
          !provider@userinfo_id_token_match,
        app_instance = app_instance,
        cache_instance = cache_instance,
        cache_updates = audit[["cache_updates"]],
        cache_hits = audit[["cache_hits"]],
        jwks_digest = audit[["jwks_digest"]],
        prefetch_completed = audit[["prefetch_completed"]],
        prefetched_key_ids = audit[["prefetched_key_ids"]],
        token_key_id_digest = if (
          !is.null(token) && isTRUE(token@id_token_validated)
        ) {
          header <- getFromNamespace("parse_jwt_header", "shinyOAuth")(
            token@id_token
          )
          if (is.character(header[["kid"]]) && length(header[["kid"]]) == 1L) {
            openid_fixture_digest(header[["kid"]])
          } else {
            NULL
          }
        } else {
          NULL
        },
        discovery_issuer_exact = !is.null(provider) &&
          identical(provider@issuer, config[["issuer"]]),
        session_number = session_number,
        form_post = audit[["form_post"]],
        authenticated = authenticated,
        has_token = !is.null(token),
        id_token_present = !is.null(token) &&
          is.character(token@id_token) &&
          length(token@id_token) == 1L &&
          !is.na(token@id_token) &&
          nzchar(token@id_token),
        has_refresh_token = !is.null(token) &&
          is.character(token@refresh_token) &&
          length(token@refresh_token) == 1L &&
          !is.na(token@refresh_token) &&
          nzchar(token@refresh_token),
        refresh = refresh,
        resource = audit[["resource"]],
        advanced = audit[["advanced"]],
        resource_checks = audit[["resource_checks"]],
        callback_rejections = observed[["callbacks"]],
        id_token_validated = !is.null(token) &&
          isTRUE(token@id_token_validated),
        userinfo_present = !is.null(token) && length(token@userinfo) > 0L,
        userinfo_claims = if (is.null(token)) {
          list()
        } else {
          as.list(intersect(
            names(token@userinfo),
            c(
              "sub",
              "name",
              "given_name",
              "family_name",
              "email",
              "email_verified"
            )
          ))
        },
        error_code = if (is.null(error)) {
          NULL
        } else if (error %in% allowed_errors) {
          error
        } else {
          "other_error"
        },
        error_classes = as.list(audit[["errors"]]),
        claims = as.list(audit[["claims"]]),
        reasons = as.list(audit[["reasons"]]),
        operations = as.list(audit[["counts"]]),
        package_version = as.character(utils::packageVersion("shinyOAuth"))
      ),
      auto_unbox = TRUE,
      null = "null"
    )
  }
  if (is.null(provider)) {
    return(shiny::shinyApp(
      shiny::fluidPage(shiny::verbatimTextOutput("snapshot")),
      function(input, output, session) {
        output[["snapshot"]] <- shiny::renderText(snapshot(
          error = "discovery_setup_error"
        ))
      }
    ))
  }
  client <- shinyOAuth::oauth_client(
    provider,
    client_id = config[["client_id"]],
    client_secret = if (is.null(config[["client_secret"]])) {
      NA_character_
    } else {
      config[["client_secret"]]
    },
    client_assertion_private_key = config[["client_assertion_private_key"]],
    client_assertion_private_key_kid = config[[
      "client_assertion_private_key_kid"
    ]],
    client_assertion_alg = config[["client_assertion_alg"]],
    request_object_mode = if (use_jar) {
      "request"
    } else {
      "parameters"
    },
    request_object_signing_alg = if (!is.null(advanced)) {
      "RS256"
    } else if (isTRUE(config[["message_signing"]])) {
      "ES256"
    } else {
      NULL
    },
    jarm_signed_response_alg = if (isTRUE(advanced[["jarm"]])) {
      "RS256"
    } else if (isTRUE(config[["message_signing"]])) {
      "ES256"
    } else {
      NULL
    },
    request_object_nbf_skew = if (use_jar) {
      0
    } else {
      NULL
    },
    client_assertion_audience = if (isTRUE(config[["fapi"]])) {
      config[["issuer"]]
    } else {
      NULL
    },
    mtls_client_cert_file = config[["mtls"]][["cert_file"]],
    mtls_client_key_file = config[["mtls"]][["key_file"]],
    mtls_client_ca_file = if (
      identical(config[["sender_constraint"]], "mtls")
    ) {
      config[["ca"]]
    } else {
      NULL
    },
    mtls_certificate_bound_access_tokens = identical(
      config[["sender_constraint"]],
      "mtls"
    ),
    mtls_require_observed_cnf = !identical(
      config[["sender_constraint"]],
      "mtls"
    ),
    dpop_private_key = if (use_dpop) {
      openssl::write_pem(openssl::ec_keygen("P-256"))
    } else {
      NULL
    },
    dpop_signing_alg = if (use_dpop) {
      "ES256"
    } else {
      NULL
    },
    resource = config[["resource"]],
    resource_bases = if (!is.null(config[["resource_indicators"]])) {
      c(api = config[["resource"]])
    } else if (!is.null(advanced)) {
      c(
        profile = paste0(
          if (identical(advanced[["sender"]], "mtls")) {
            config[["mtls_origin"]]
          } else {
            config[["issuer"]]
          },
          "/"
        )
      )
    } else if (isTRUE(config[["fapi"]])) {
      c(suite = sub("accounts$", "", config[["resource_endpoint"]]))
    } else {
      character()
    },
    redirect_uri = paste0(config[["origin"]], "/"),
    scopes = if (is.null(config[["scopes"]])) {
      c("openid", "profile", "email")
    } else {
      config[["scopes"]]
    },
    response_mode = config[["response_mode"]],
    state_transport = if (is.null(config[["state_transport"]])) {
      "encrypted"
    } else {
      config[["state_transport"]]
    },
    state_key = openssl::rand_bytes(32)
  )
  if (isTRUE(config[["message_signing"]])) {
    openid_assert_message_signing_configuration(client)
  }
  if (isTRUE(config[["preload_jwks"]])) {
    # No public prefetch API exists. This calls the installed package's normal
    # fetch/cache/host-policy path, without injecting keys or validation results.
    fetch <- getFromNamespace("fetch_client_jwks", "shinyOAuth")
    keys <- fetch(
      client,
      provider@issuer,
      provider@jwks_cache,
      pins = provider@jwks_pins,
      pin_mode = provider@jwks_pin_mode,
      provider = provider
    )
    audit[["prefetch_completed"]] <- TRUE
    audit[["prefetched_key_ids"]] <- lapply(keys[["keys"]], function(key) {
      if (is.character(key[["kid"]]) && length(key[["kid"]]) == 1L) {
        openid_fixture_digest(key[["kid"]])
      } else {
        NULL
      }
    })
  }
  ui <- shiny::fluidPage(
    shiny::actionButton("login", "Log in"),
    shiny::actionButton("logout", "Log out"),
    shiny::actionButton("refresh", "Refresh"),
    if (
      isTRUE(config[["fapi"]]) ||
        !is.null(advanced) ||
        !is.null(config[["resource_indicators"]])
    ) {
      shiny::actionButton("resource", "Read resource")
    },
    if (!is.null(advanced)) {
      shiny::tagList(
        shiny::actionButton("probes", "Check token binding"),
        shiny::actionButton("lifecycle", "Check token lifecycle")
      )
    },
    if (!is.null(config[["resource_indicators"]])) {
      shiny::actionButton("resource_probes", "Check resource isolation")
    },
    shiny::verbatimTextOutput("snapshot")
  )
  resolver <- function(req) {
    if (
      !req[["REMOTE_ADDR"]] %in% c("127.0.0.1", "::1") ||
        !identical(req[["HTTP_HOST"]], sub("^https://", "", config[["origin"]]))
    ) {
      return(NULL)
    }
    if (
      identical(config[["response_mode"]], "form_post") &&
        identical(req[["REQUEST_METHOD"]], "POST") &&
        identical(req[["PATH_INFO"]], "/")
    ) {
      site <- req[["HTTP_SEC_FETCH_SITE"]]
      if (
        !is.character(site) ||
          length(site) != 1L ||
          !site %in% c("same-site", "same-origin", "cross-site", "none")
      ) {
        site <- "missing_or_unknown"
      }
      content_type <- req[["CONTENT_TYPE"]]
      audit[["form_post"]] <- list(
        method = "POST",
        origin_matched = identical(
          req[["HTTP_ORIGIN"]],
          config[["provider_origin"]]
        ),
        sec_fetch_site = site,
        form_urlencoded = is.character(content_type) &&
          length(content_type) == 1L &&
          !is.na(content_type) &&
          nzchar(content_type) &&
          identical(
            tolower(trimws(strsplit(content_type, ";", fixed = TRUE)[[1L]][[
              1L
            ]])),
            "application/x-www-form-urlencoded"
          )
      )
    }
    paste0(config[["origin"]], req[["PATH_INFO"]])
  }
  wrap <- if (identical(config[["response_mode"]], "form_post")) {
    shinyOAuth::oauth_form_post_ui
  } else {
    shinyOAuth::oauth_ui
  }
  ui <- wrap(ui, id = "auth", client = client, request_uri_resolver = resolver)
  if (isTRUE(config[["callback_rejection"]])) {
    wrapped_ui <- ui
    rejection_request <- NULL
    pending_snapshot <- function() {
      keys <- sort(client@state_store[["keys"]]())
      records <- lapply(keys, client@state_store[["get"]])
      list(
        count = length(keys),
        digest = paste(
          openssl::sha256(serialize(list(keys, records), NULL, version = 3)),
          collapse = ""
        )
      )
    }
    response_contains <- function(response, sensitive) {
      text <- c(
        response[["content"]],
        unlist(response[["headers"]], use.names = FALSE)
      )
      any(vapply(
        sensitive,
        function(secret) {
          any(grepl(secret, text, fixed = TRUE))
        },
        logical(1)
      ))
    }
    ui <- function(req) {
      before <- pending_snapshot()
      response <- wrapped_ui(req)
      location <- response[["headers"]][["Location"]]
      if (
        is.list(response) &&
          identical(response[["status"]], 303L) &&
          is.character(location) &&
          length(location) == 1L &&
          grepl(
            "^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$",
            location
          )
      ) {
        params <- shiny::parseQueryString(req[["QUERY_STRING"]])
        sensitive <- unlist(
          params[intersect(
            names(params),
            c(
              "code",
              "state",
              "iss",
              "response",
              "error",
              "error_description",
              "error_uri"
            )
          )],
          use.names = FALSE
        )
        if (isTRUE(config[["message_signing"]]) || isTRUE(advanced[["jarm"]])) {
          claims <- getFromNamespace(
            "parse_jwt_payload_or_null",
            "shinyOAuth"
          )(params[["response"]])
          sensitive <- c(
            sensitive,
            unlist(
              claims[intersect(names(claims), c("code", "state", "iss"))],
              use.names = FALSE
            )
          )
        }
        sensitive <- sensitive[nchar(sensitive) >= 16L]
        continuation <- shiny::parseQueryString(sub("#$", "", location))
        rejection_request <<- list(
          handle = continuation[["shinyOAuth_callback_error"]],
          sensitive = sensitive,
          state_present = !is.null(params[["state"]]),
          issuer_present = !is.null(params[["iss"]]),
          redirect_credentials_absent = !response_contains(response, sensitive),
          pending_state_preserved = before[["count"]] > 0L &&
            identical(before, pending_snapshot()),
          pending_before = before
        )
      }
      params <- shiny::parseQueryString(req[["QUERY_STRING"]])
      if (
        is.list(response) &&
          identical(response[["status"]], 400L) &&
          !is.null(rejection_request) &&
          identical(
            params[["shinyOAuth_callback_error"]],
            rejection_request[["handle"]]
          )
      ) {
        original <- rejection_request
        rejection_request <<- NULL
        headers <- response[["headers"]]
        names(headers) <- tolower(names(headers))
        content <- response[["content"]]
        value <- jsonlite::fromJSON(
          snapshot(
            error = "http_callback_rejected",
            session_number = audit[["sessions"]]
          ),
          simplifyVector = FALSE
        )
        if (isTRUE(config[["message_signing"]]) || isTRUE(advanced[["jarm"]])) {
          value[["jarm_error"]] <- openid_fixture_jarm_error(content)
        }
        value[["http_rejection"]] <- list(
          status = 400L,
          no_store = identical(headers[["cache-control"]], "no-store"),
          no_referrer = identical(headers[["referrer-policy"]], "no-referrer"),
          plain_text = startsWith(response[["content_type"]], "text/plain"),
          credentials_absent = !response_contains(
            response,
            original[["sensitive"]]
          ),
          final_request_no_referrer = is.null(req[["HTTP_REFERER"]]) ||
            identical(req[["HTTP_REFERER"]], ""),
          redirect_credentials_absent = original[[
            "redirect_credentials_absent"
          ]],
          pending_state_preserved = isTRUE(original[[
            "pending_state_preserved"
          ]]) &&
            identical(original[["pending_before"]], pending_snapshot()),
          state_present = original[["state_present"]],
          issuer_present = original[["issuer_present"]],
          content_digest = openid_fixture_digest(trimws(content))
        )
        if (isTRUE(config[["message_signing"]]) || isTRUE(advanced[["jarm"]])) {
          value[["http_rejection"]][["jarm_error"]] <- value[["jarm_error"]]
        }
        path <- file.path(config[["audit_directory"]], "callback-http.json")
        pending <- paste0(path, ".pending")
        jsonlite::write_json(value, pending, auto_unbox = TRUE, null = "null")
        if (!file.rename(pending, path)) {
          stop("Cannot publish private HTTP rejection evidence")
        }
      }
      response
    }
  }
  server <- function(input, output, session) {
    if (!is.null(config[["stop_file"]])) {
      stop_observer <- shiny::observe({
        shiny::invalidateLater(50, session)
        if (file.exists(config[["stop_file"]])) {
          stop_observer[["destroy"]]()
          session[["close"]]()
          shiny::stopApp()
        }
      })
    }
    audit[["sessions"]] <- audit[["sessions"]] + 1L
    session_number <- audit[["sessions"]]
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE,
      async = !identical(config[["transport"]], "sync")
    )
    extension <- if (!is.null(advanced)) {
      interop_advanced_server(auth, input, client, config)
    } else if (!is.null(config[["resource_indicators"]])) {
      interop_resource_server(auth, input, client, config)
    } else {
      NULL
    }
    refresh <- NULL
    shiny::observeEvent(
      input[["resource"]],
      {
        if (!isTRUE(config[["fapi"]]) || !is.null(audit[["resource"]])) {
          return(invisible(NULL))
        }
        audit[["resource"]] <- tryCatch(
          {
            token <- auth[["token"]]
            connection <- auth[["connection"]]()
            connection_unusable <- !isTRUE(connection[["is_usable"]]())
            expiry_unknown <- is.null(token) ||
              !is.finite(as.numeric(token@expires_at))
            control <- config[["resource_control"]]
            response <- if (is.null(control)) {
              connection[["request"]]("suite", "accounts")
            } else {
              request <- httr2::request(config[["resource_endpoint"]]) |>
                httr2::req_headers(
                  Authorization = paste("Bearer", token@access_token)
                ) |>
                httr2::req_options(
                  cainfo = config[["ca"]],
                  followlocation = FALSE
                ) |>
                httr2::req_error(is_error = function(...) FALSE) |>
                httr2::req_timeout(10)
              if (!identical(control[["kind"]], "missing")) {
                request <- request |>
                  httr2::req_options(
                    sslcert = control[["cert_file"]],
                    sslkey = control[["key_file"]]
                  )
              }
              if (identical(control[["kind"]], "forged_header")) {
                request <- request |>
                  httr2::req_headers(
                    `X-Ssl-Cert` = paste(
                      readLines(config[["mtls"]][["cert_file"]]),
                      collapse = "\t"
                    )
                  )
              }
              httr2::req_perform(request)
            }
            body <- tryCatch(
              httr2::resp_body_json(response),
              error = function(...) list()
            )
            list(
              done = TRUE,
              succeeded = identical(httr2::resp_status(response), 200L),
              response_marker_valid = identical(
                body[["conformance-test-finished"]],
                "true"
              ),
              http_status = httr2::resp_status(response),
              control_kind = control[["kind"]],
              pid = Sys.getpid(),
              transport = "main_process",
              api = if (is.null(control)) {
                "connection"
              } else {
                "raw_attacker_request"
              },
              expiry_unknown = expiry_unknown,
              connection_unusable = connection_unusable
            )
          },
          error = function(...) list(done = TRUE, succeeded = FALSE)
        )
      },
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["refresh"]],
      {
        attempts <- if (is.null(refresh)) 1L else refresh[["attempts"]] + 1L
        token <- auth[["token"]]
        connection <- auth[["connection"]]()
        if (
          is.null(token) ||
            is.null(connection) ||
            !isTRUE(token@id_token_validated)
        ) {
          refresh <<- list(
            attempts = attempts,
            done = TRUE,
            result = "invalid_initial_state"
          )
          return(invisible(NULL))
        }
        # Keep the original grant and identity private in this same Shiny session.
        # Evidence contains comparisons only, never token or identity values.
        access <- token@access_token
        original_id <- token@id_token
        issuer <- token@id_token_claims[["iss"]]
        subject <- token@id_token_claims[["sub"]]
        settle <- function(failure = NULL) {
          current <- auth[["token"]]
          current_connection <- auth[["connection"]]()
          exported <- tryCatch(
            connection[["access_token"]](min_valid_for_seconds = 0),
            error = identity
          )
          accepted <- is.null(failure) && !is.null(current)
          refresh <<- list(
            attempts = attempts,
            done = TRUE,
            result = if (is.null(failure)) "succeeded" else "rejected",
            connection_same = identical(connection, current_connection),
            connection_present = !is.null(current_connection),
            old_connection_usable = isTRUE(connection[["is_usable"]]()),
            access_changed = accepted &&
              !identical(access, current@access_token),
            original_id_token_retained = accepted &&
              identical(original_id, current@original_id_token),
            issuer_unchanged = accepted &&
              identical(issuer, current@id_token_claims[["iss"]]),
            subject_unchanged = accepted &&
              identical(subject, current@id_token_claims[["sub"]]),
            exported_current = accepted &&
              identical(exported, current@access_token),
            export_blocked = inherits(exported, "shinyOAuth_access_error"),
            refresh_error_is_access_error = inherits(
              failure,
              "shinyOAuth_access_error"
            )
          )
          invisible(NULL)
        }
        result <- tryCatch(connection[["refresh"]](), error = identity)
        if (inherits(result, "promise")) {
          promises::then(
            result,
            onFulfilled = function(...) settle(),
            onRejected = function(error) settle(error)
          )
        } else {
          settle(if (inherits(result, "error")) result else NULL)
        }
        invisible(NULL)
      },
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["login"]],
      auth[["request_login"]](),
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["logout"]],
      auth[["logout"]](),
      ignoreInit = TRUE
    )
    output[["snapshot"]] <- shiny::renderText({
      shiny::invalidateLater(100, session)
      if (!is.null(extension)) {
        if (!is.null(config[["resource_indicators"]])) {
          audit[["resource_checks"]] <- extension()
        } else {
          audit[["advanced"]] <- extension()
        }
      }
      snapshot(
        auth[["token"]],
        isTRUE(auth[["authenticated"]]),
        auth[["error"]],
        session_number,
        refresh
      )
    })
  }
  shiny::shinyApp(ui, server, uiPattern = ".*")
}
