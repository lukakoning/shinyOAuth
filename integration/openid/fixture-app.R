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
  audit[["sessions"]] <- 0L
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
    }
  )
  provider <- shinyOAuth::oauth_provider_oidc_discover(
    config[["issuer"]],
    token_auth_style = "header"
  )
  client <- shinyOAuth::oauth_client(
    provider,
    client_id = config[["client_id"]],
    client_secret = config[["client_secret"]],
    redirect_uri = paste0(config[["origin"]], "/"),
    scopes = c("openid", "profile", "email"),
    response_mode = config[["response_mode"]],
    state_key = openssl::rand_bytes(32)
  )
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
      token <- auth[["token"]]
      error <- auth[["error"]]
      allowed_errors <- c(
        "token_exchange_error",
        "invalid_state",
        "callback_iss_validation_error",
        "invalid_request",
        "access_denied",
        "login_required",
        "interaction_required"
      )
      jsonlite::toJSON(
        list(
          run_id = config[["run_id"]],
          ready = TRUE,
          session_number = session_number,
          authenticated = isTRUE(auth[["authenticated"]]),
          has_token = !is.null(token),
          id_token_validated = !is.null(token) &&
            isTRUE(token@id_token_validated),
          userinfo_present = !is.null(token) && length(token@userinfo) > 0L,
          error_code = if (is.null(error)) {
            NULL
          } else if (error %in% allowed_errors) {
            error
          } else {
            "other_error"
          },
          error_classes = as.list(audit[["errors"]]),
          claims = as.list(audit[["claims"]]),
          operations = as.list(audit[["counts"]]),
          package_version = as.character(utils::packageVersion("shinyOAuth"))
        ),
        auto_unbox = TRUE,
        null = "null"
      )
    })
  }
  shiny::shinyApp(ui, server, uiPattern = ".*")
}
