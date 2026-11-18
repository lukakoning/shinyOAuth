interop_retention_app <- function(config) {
  options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.audit_hook = openid_fixture_hook(
      config[["audit_directory"]],
      config[["run_id"]],
      config[["package_path"]],
      config[["ca"]]
    )
  )
  provider <- shinyOAuth::oauth_provider_oidc_discover(
    config[["issuer"]],
    token_auth_style = "header",
    extra_auth_params = list(prompt = "consent")
  )
  client <- shinyOAuth::oauth_client(
    provider,
    client_id = config[["client_id"]],
    client_secret = config[["client_secret"]],
    redirect_uri = paste0(config[["origin"]], "/"),
    scopes = config[["scopes"]],
    response_mode = config[["response_mode"]],
    state_key = openssl::rand_bytes(32),
    authorization_server_mode = "multi_issuer",
    resource_bases = c(profile = paste0(config[["issuer"]], "/"))
  )
  manager <- shinyOAuth::oauth_connections(
    list(oidc = client),
    config[["origin"]],
    retention = "browser",
    owner_policy = shinyOAuth::oauth_browser_owner(
      idle_timeout = 600,
      absolute_timeout = 1200,
      same_site = "Lax"
    ),
    store = shinyOAuth::oauth_connection_store_memory(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  app_instance <- paste(format(openssl::rand_bytes(16)), collapse = "")
  sessions <- 0L
  digest <- function(value) {
    paste(
      openssl::sha256(charToRaw(paste0(app_instance, value))),
      collapse = ""
    )
  }
  ui <- shiny::fluidPage(
    shiny::actionButton("login", "Connect"),
    shiny::actionButton("read", "Read profile"),
    shiny::actionButton("refresh", "Refresh"),
    shiny::actionButton("logout", "End local session"),
    shiny::textInput("probe_id", "Connection ID"),
    shiny::actionButton("probe", "Check access"),
    shiny::verbatimTextOutput("snapshot")
  )
  wrapped <- shinyOAuth::oauth_connections_ui(
    ui,
    "retained",
    manager,
    request_uri_resolver = function(req) {
      paste0(
        config[["origin"]],
        req[["PATH_INFO"]],
        if (nzchar(req[["QUERY_STRING"]])) {
          paste0("?", req[["QUERY_STRING"]])
        } else {
          ""
        }
      )
    }
  )
  server <- function(input, output, session) {
    sessions <<- sessions + 1L
    number <- sessions
    auth <- shinyOAuth::oauth_connections_server(
      "retained",
      manager,
      async = !identical(config[["transport"]], "sync"),
      refresh_check_interval_ms = 500
    )
    result <- shiny::reactiveVal(NULL)
    revision <- shiny::reactiveVal(0L)
    complete <- function(value) {
      result(value)
      revision(shiny::isolate(revision()) + 1L)
    }
    connection <- function() {
      rows <- auth[["connections"]]()
      if (length(rows) != 1L) {
        stop("Expected one retained authorization")
      }
      auth[["connection"]](rows[[1L]][["connection_id"]])
    }
    shiny::observeEvent(
      input[["login"]],
      auth[["connect"]]("oidc"),
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["read"]],
      {
        complete(tryCatch(
          {
            reference <- connection()
            original_identity <- reference[["identity"]](userinfo = "sub")
            response <- reference[["request"]]("profile", "userinfo")
            body <- httr2::resp_body_json(response)
            list(
              action = "read",
              done = TRUE,
              status = httr2::resp_status(response),
              subject_matches = identical(
                body[["sub"]],
                original_identity[["id_token_claims"]][["sub"]]
              ),
              identity_usable = isTRUE(reference[["is_usable"]]()),
              api = "connection",
              pid = Sys.getpid(),
              transport = "main_process"
            )
          },
          error = function(...) {
            list(action = "read", done = TRUE, failed = TRUE)
          }
        ))
      },
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["refresh"]],
      {
        reference <- connection()
        access <- reference[["access_token"]](min_valid_for_seconds = 0)
        original_identity <- reference[["identity"]](userinfo = "sub")
        settle <- function(failure = NULL) {
          complete(tryCatch(
            list(
              action = "refresh",
              done = TRUE,
              succeeded = is.null(failure),
              connection_same = identical(reference, connection()),
              access_changed = !identical(
                access,
                reference[["access_token"]](min_valid_for_seconds = 0)
              ),
              identity_unchanged = identical(
                original_identity,
                reference[["identity"]](userinfo = "sub")
              ),
              connection_usable = isTRUE(reference[["is_usable"]]())
            ),
            error = function(...) {
              list(action = "refresh", done = TRUE, failed = TRUE)
            }
          ))
        }
        value <- tryCatch(reference[["refresh"]](), error = identity)
        if (inherits(value, "promise")) {
          promises::then(value, function(...) settle(), function(error) {
            settle(error)
          })
        } else {
          settle(if (inherits(value, "error")) value else NULL)
        }
      },
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["probe"]],
      {
        denied <- tryCatch(
          {
            auth[["connection"]](input[["probe_id"]])[["access_token"]](
              min_valid_for_seconds = 0
            )
            FALSE
          },
          error = function(error) {
            inherits(error, "shinyOAuth_token_error") &&
              grepl(
                "Connection is unavailable",
                conditionMessage(error),
                fixed = TRUE
              )
          }
        )
        complete(list(action = "probe", done = TRUE, denied = denied))
      },
      ignoreInit = TRUE
    )
    shiny::observeEvent(
      input[["logout"]],
      {
        reference <- connection()
        auth[["logout"]](revoke = FALSE, reload = FALSE)
        blocked <- tryCatch(
          {
            reference[["access_token"]](min_valid_for_seconds = 0)
            FALSE
          },
          error = function(error) inherits(error, "shinyOAuth_access_error")
        )
        complete(list(
          action = "logout",
          done = TRUE,
          stale_unusable = !isTRUE(reference[["is_usable"]]()),
          export_blocked = blocked,
          remote_revocation_requested = FALSE
        ))
      },
      ignoreInit = TRUE
    )
    output[["snapshot"]] <- shiny::renderText({
      shiny::invalidateLater(100, session)
      rows <- auth[["connections"]]()
      verified <- if (length(rows) == 1L) {
        tryCatch(
          connection()[["identity"]](userinfo = "sub"),
          error = function(...) NULL
        )
      } else {
        NULL
      }
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
        config[["transport"]] == "sync"
      ) {
        "main_process"
      } else {
        "serialized_per_dispatch"
      }
      jsonlite::toJSON(
        list(
          run_id = config[["run_id"]],
          ready = TRUE,
          package_version = as.character(utils::packageVersion("shinyOAuth")),
          app_instance = app_instance,
          session_number = number,
          app_pid = Sys.getpid(),
          connection_count = length(rows),
          connection_id = if (length(rows) == 1L) {
            rows[[1L]][["connection_id"]]
          } else {
            NULL
          },
          identity_verified = !is.null(verified),
          identity_digest = if (is.null(verified)) {
            NULL
          } else {
            digest(as.character(jsonlite::toJSON(verified, auto_unbox = TRUE)))
          },
          errors = auth[["errors"]](),
          result_revision = revision(),
          result = result(),
          operations = observed[["counts"]],
          transport = observed[["transport"]]
        ),
        auto_unbox = TRUE,
        null = "null"
      )
    })
  }
  shiny::shinyApp(wrapped, server, uiPattern = ".*")
}
