openid_fixture_digest <- function(value) {
  paste(openssl::sha256(charToRaw(value)), collapse = "")
}

openid_fixture_app <- function(config) {
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
      !config[["response_mode"]] %in% c("query", "form_post")
  ) {
    stop("Invalid private OpenID fixture configuration")
  }
  method <- config[["client_auth_type"]]
  if (is.null(method)) {
    method <- "client_secret_basic"
  }
  style <- switch(
    method,
    client_secret_basic = "header",
    client_secret_post = "body",
    client_secret_jwt = "client_secret_jwt",
    private_key_jwt = "private_key_jwt"
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
  provider <- tryCatch(
    shinyOAuth::oauth_provider_oidc_discover(
      config[["issuer"]],
      token_auth_style = style,
      id_token_profile = if (isTRUE(config[["fapi"]])) "fapi2" else "oidc",
      allowed_token_types = if (isTRUE(config[["fapi"]])) "DPoP" else "Bearer",
      authorization_request_front_channel_mode = if (isTRUE(config[["fapi"]])) {
        "minimal"
      } else {
        "compat"
      },
      jwks_cache = cache
    ),
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
        has_refresh_token = !is.null(token) &&
          is.character(token@refresh_token) &&
          length(token@refresh_token) == 1L &&
          !is.na(token@refresh_token) &&
          nzchar(token@refresh_token),
        refresh = refresh,
        resource = audit[["resource"]],
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
    client_assertion_audience = if (isTRUE(config[["fapi"]])) {
      config[["issuer"]]
    } else {
      NULL
    },
    dpop_private_key = if (isTRUE(config[["fapi"]])) {
      openssl::write_pem(openssl::ec_keygen("P-256"))
    } else {
      NULL
    },
    dpop_signing_alg = if (isTRUE(config[["fapi"]])) "ES256" else NULL,
    resource_bases = if (isTRUE(config[["fapi"]])) {
      c(suite = sub("accounts$", "", config[["resource_endpoint"]]))
    } else {
      character()
    },
    redirect_uri = paste0(config[["origin"]], "/"),
    scopes = c("openid", "profile", "email"),
    response_mode = config[["response_mode"]],
    state_key = openssl::rand_bytes(32)
  )
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
    if (isTRUE(config[["fapi"]])) {
      shiny::actionButton("resource", "Read resource")
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
    ui <- function(req) {
      response <- wrapped_ui(req)
      if (is.list(response) && identical(response[["status"]], 400L)) {
        params <- shiny::parseQueryString(req[["QUERY_STRING"]])
        sensitive <- unlist(
          params[intersect(names(params), c("code", "state", "iss"))],
          use.names = FALSE
        )
        sensitive <- sensitive[nchar(sensitive) >= 16L]
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
        value[["http_rejection"]] <- list(
          status = 400L,
          no_store = identical(headers[["cache-control"]], "no-store"),
          no_referrer = identical(headers[["referrer-policy"]], "no-referrer"),
          plain_text = startsWith(response[["content_type"]], "text/plain"),
          credentials_absent = !any(vapply(
            sensitive,
            function(secret) grepl(secret, content, fixed = TRUE),
            logical(1)
          )),
          state_present = !is.null(params[["state"]]),
          issuer_present = !is.null(params[["iss"]]),
          content_digest = openid_fixture_digest(trimws(content))
        )
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
            response <- connection[["request"]]("suite", "accounts")
            body <- httr2::resp_body_json(response)
            list(
              done = TRUE,
              succeeded = identical(httr2::resp_status(response), 200L),
              response_marker_valid = identical(
                body[["conformance-test-finished"]],
                "true"
              ),
              pid = Sys.getpid(),
              transport = "main_process",
              api = "connection",
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
