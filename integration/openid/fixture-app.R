openid_fixture_digest <- function(value) {
  paste(openssl::sha256(charToRaw(value)), collapse = "")
}

openid_fixture_app <- function(config) {
  required <- c(
    "issuer",
    "origin",
    "client_id",
    "client_secret",
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
  audit <- new.env(parent = emptyenv())
  audit[["counts"]] <- setNames(
    integer(4),
    c(
      "audit_token_exchange",
      "audit_userinfo",
      "audit_login_success",
      "audit_login_failed"
    )
  )
  audit[["errors"]] <- character()
  audit[["claims"]] <- character()
  audit[["reasons"]] <- character()
  audit[["sessions"]] <- 0L
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
    shinyOAuth.audit_hook = function(event) {
      type <- event[["type"]]
      if (
        is.character(type) &&
          length(type) == 1L &&
          type %in% names(audit[["counts"]])
      ) {
        audit[["counts"]][[type]] <- audit[["counts"]][[type]] + 1L
      }
      classes <- intersect(
        event[["error_class"]],
        c(
          "shinyOAuth_id_token_error",
          "shinyOAuth_userinfo_error",
          "shinyOAuth_userinfo_mismatch",
          "shinyOAuth_state_error",
          "shinyOAuth_token_error",
          "shinyOAuth_callback_error",
          "shinyOAuth_config_error"
        )
      )
      audit[["errors"]] <- unique(c(audit[["errors"]], classes))
      audit[["claims"]] <- unique(c(
        audit[["claims"]],
        intersect(
          event[["claim"]],
          c(
            "iss",
            "aud",
            "sub",
            "nonce",
            "exp",
            "iat",
            "azp",
            "auth_time",
            "at_hash"
          )
        )
      ))
      audit[["reasons"]] <- unique(c(
        audit[["reasons"]],
        intersect(
          event[["reason"]],
          c(
            "disallowed_algorithm",
            "invalid_signature",
            "discovery_issuer_mismatch"
          )
        )
      ))
    }
  )
  provider <- tryCatch(
    shinyOAuth::oauth_provider_oidc_discover(
      config[["issuer"]],
      token_auth_style = "header",
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
    session_number = 0L
  ) {
    allowed_errors <- c(
      "token_exchange_error",
      "invalid_state",
      "callback_iss_validation_error",
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
        authenticated = authenticated,
        has_token = !is.null(token),
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
    client_secret = config[["client_secret"]],
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
    shiny::verbatimTextOutput("snapshot")
  )
  resolver <- function(req) {
    if (
      !req[["REMOTE_ADDR"]] %in% c("127.0.0.1", "::1") ||
        !identical(req[["HTTP_HOST"]], sub("^https://", "", config[["origin"]]))
    ) {
      return(NULL)
    }
    paste0(config[["origin"]], req[["PATH_INFO"]])
  }
  wrap <- if (identical(config[["response_mode"]], "form_post")) {
    shinyOAuth::oauth_form_post_ui
  } else {
    shinyOAuth::oauth_ui
  }
  ui <- wrap(ui, id = "auth", client = client, request_uri_resolver = resolver)
  server <- function(input, output, session) {
    audit[["sessions"]] <- audit[["sessions"]] + 1L
    session_number <- audit[["sessions"]]
    auth <- shinyOAuth::oauth_module_server(
      "auth",
      client,
      auto_redirect = FALSE
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
        session_number
      )
    })
  }
  shiny::shinyApp(ui, server, uiPattern = ".*")
}
